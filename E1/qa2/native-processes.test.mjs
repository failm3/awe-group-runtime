import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fork} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {digest,validateBoundValue} from '../contracts/index.mjs';
import {createAuthorityServer,createAuthorityClient} from '../coordinator/index.mjs';
import {makeFixture,connect,coordinator,pause,completion} from './native-fixture.mjs';

const evidence=[];
function record(item){evidence.push(item);fs.writeFileSync('E1/qa2/native-process-readbacks.json',JSON.stringify({schema:'awe.qa2.native-process-readbacks/1',environment:'ISOLATED_E1_POSTGRESQL_18_PORT_5433',live_model_calls:0,external_effects:0,evidence},null,2)+'\n');}
function leaf(server,credential,{task_id,mission_id,delay_ms=500,lease_ms=5000}={}){
 const child=fork(new URL('../coordinator/leaf-worker.mjs',import.meta.url),[],{stdio:['ignore','ignore','pipe','ipc'],windowsHide:true,env:Object.fromEntries(['SystemRoot','WINDIR','PATH','TEMP','TMP'].filter(k=>process.env[k]).map(k=>[k,process.env[k]]))});
 const messages=[];child.on('message',x=>messages.push(x));child.stderr.resume();
 const exit=new Promise(resolve=>child.once('exit',(code,signal)=>resolve({code,signal})));
 child.send({url:server.url,token:credential.token,capabilities:['e1.code.parse'],task_id,mission_id,delay_ms,lease_ms});
 return{child,messages,exit,async wait(type){const until=Date.now()+10000;while(Date.now()<until){const value=messages.find(x=>x.type===type);if(value)return value;const error=messages.find(x=>x.type==='ERROR');if(error)throw new Error(error.code);await pause(10);}throw new Error('QA2_OWNED_LEAF_TIMEOUT');}};
}
function ownCredential(server,f,id,role='WORKER'){return server.issueCredential({project_id:f.project,principal_id:id,role,capabilities:['e1.code.parse']});}
async function readAcceptance(q,f,task){
 let schema=true;try{validateBoundValue(task.output_schema,task.result.output);}catch{schema=false;}
 const trace=task.result.trace;
 const checks=[{check_id:'schema',passed:schema},{check_id:'source_exact',passed:task.result.output.text==='Computed: '+task.document.input.instruction},{check_id:'scope',passed:task.project_id===f.project&&task.mission_id===f.spec.mission_id},{check_id:'independent_qa',passed:task.producer_id!=='e1_qa'},{check_id:'trace_interval',passed:Number.isInteger(trace.pid)&&trace.pid!==process.pid&&Date.parse(trace.finished_at)>=Date.parse(trace.started_at)}];
 assert.ok(checks.every(x=>x.passed));assert.equal(digest(task.result),task.result_hash);assert.equal(digest(task.result.output),task.result.artifact_digest);
 return q.qaEvaluate({mission_id:task.mission_id,task_id:task.task_id,plan_digest:task.plan_digest,result_hash:task.result_hash,evaluator_id:'e1_qa',verdict:'PASS',checks});
}
test('QA2 native: independent real worker processes overlap and dependent dispatch waits for persisted QA',async()=>{
 const f=makeFixture({scenario:'reads',retryClaims:2}),db=await connect(),qa=await connect('qa'),c=coordinator(db,f),q=coordinator(qa,f);let server;const leaves=[];
 try{
  await c.admit({},f.contexts.e1_owner);server=await createAuthorityServer({coordinator:c,qaCoordinator:q});
  for(const [id,task_id] of [['e1_worker_a','read_a'],['e1_worker_b','read_b']])leaves.push(leaf(server,ownCredential(server,f,id),{task_id,mission_id:f.spec.mission_id,delay_ms:500}));
  const claims=await Promise.all(leaves.map(x=>x.wait('CLAIMED'))),exits=await Promise.all(leaves.map(x=>x.exit));assert.ok(exits.every(x=>x.code===0));assert.notEqual(claims[0].pid,claims[1].pid);
  assert.ok(claims.every(x=>!x.received_keys.some(k=>/database|pgdata|descriptor|password/.test(k))));
  let state=await q.snapshot();const upstream=state.tasks.filter(x=>['read_a','read_b'].includes(x.task_id));assert.ok(upstream.every(x=>x.state==='WAIT_QA'));
  const intervals=upstream.map(x=>x.result.trace);assert.ok(Math.max(...intervals.map(x=>Date.parse(x.started_at)))<Math.min(...intervals.map(x=>Date.parse(x.finished_at))));
  const client=createAuthorityClient({url:server.url,token:ownCredential(server,f,'e1_worker_a').token});assert.equal((await client.claim({mission_id:f.spec.mission_id,task_id:'join',capabilities:['e1.code.parse']})).status,'WAIT');
  for(const task of upstream)assert.equal((await readAcceptance(q,f,task)).status,'ACCEPTED');
  const join=leaf(server,ownCredential(server,f,'e1_worker_a'),{task_id:'join',mission_id:f.spec.mission_id,delay_ms:30});leaves.push(join);assert.equal((await join.exit).code,0);
  state=await q.snapshot();assert.equal((await readAcceptance(q,f,state.tasks.find(x=>x.task_id==='join'))).status,'ACCEPTED');state=await q.snapshot();assert.equal(state.missions[0].state,'COMPLETE');
  record({case:'REAL_PROCESS_OVERLAP_WITH_INDEPENDENT_UPSTREAM_QA',project_id:f.project,distinct_worker_pids:claims.map(x=>x.pid),intervals,persisted_state:state,acceptance_kind:'SYNTHETIC_TECHNICAL_DB_QA_NO_OWNER_OR_D08_SIGNATURE'});
 }finally{for(const x of leaves)if(x.child.exitCode===null&&x.child.signalCode===null)x.child.kill('SIGKILL');if(server)await server.close();await db.close();await qa.close();}
});
test('QA2 native: force-killed owned worker is fenced after lease takeover and late result is rejected',async()=>{
 const f=makeFixture({scenario:'reads',retryClaims:2}),db=await connect(),qa=await connect('qa'),c=coordinator(db,f),q=coordinator(qa,f);let server;const leaves=[];
 try{
  await c.admit({},f.contexts.e1_owner);server=await createAuthorityServer({coordinator:c,qaCoordinator:q});
  const first=leaf(server,ownCredential(server,f,'e1_worker_a'),{task_id:'read_a',mission_id:f.spec.mission_id,delay_ms:3000,lease_ms:300});leaves.push(first);const old=await first.wait('CLAIMED');assert.ok(old.pid>0&&old.pid!==process.pid);first.child.kill('SIGKILL');const killed=await first.exit;await pause(400);
  const second=leaf(server,ownCredential(server,f,'e1_worker_b'),{task_id:'read_a',mission_id:f.spec.mission_id,delay_ms:30,lease_ms:3000});leaves.push(second);const fresh=await second.wait('CLAIMED');assert.equal((await second.exit).code,0);assert.ok(fresh.scope.fence>old.scope.fence);
  const task=f.plan.tasks.find(x=>x.task_id==='read_a');await assert.rejects(()=>c.complete(completion({...old.scope,task})),e=>['A2_RESULT_SCOPE','A2_STALE_FENCE'].includes(e.code));
  const state=await q.snapshot(),row=state.tasks.find(x=>x.task_id==='read_a');assert.equal(row.state,'WAIT_QA');assert.equal(row.producer_id,'e1_worker_b');assert.equal(row.result.trace.pid,fresh.pid);
  record({case:'OWNED_PROCESS_FORCE_KILL_LEASE_TAKEOVER',platform:process.platform,kill:'child.kill(SIGKILL); native Windows termination, not a Linux kill-9 claim',project_id:f.project,old_pid:old.pid,new_pid:fresh.pid,old_fence:old.scope.fence,new_fence:fresh.scope.fence,killed,late_result_accepted:false,persisted_state:state});
 }finally{for(const x of leaves)if(x.child.exitCode===null&&x.child.signalCode===null)x.child.kill('SIGKILL');if(server)await server.close();await db.close();await qa.close();}
});
test('QA2 native: RPC credentials reject worker impersonation, project crossing, QA/owner misuse and revocation',async()=>{
 const f=makeFixture(),db=await connect(),qa=await connect('qa'),c=coordinator(db,f),q=coordinator(qa,f);let server;
 try{
  await c.admit({},f.contexts.e1_owner);server=await createAuthorityServer({coordinator:c,qaCoordinator:q});
  const credential=ownCredential(server,f,'e1_worker_a'),client=createAuthorityClient({url:server.url,token:credential.token});
  for(const [method,request,code]of [['claim',{worker_id:'e1_worker_b',capabilities:['e1.code.parse']},'A2_WORKER_IMPERSONATION'],['claim',{project_id:'prj_other',capabilities:['e1.code.parse']},'A2_PROJECT_SCOPE'],['claim',{capabilities:['shell.exec']},'A2_WORKER_CAPABILITY'],['qaEvaluate',{},'A2_INDEPENDENT_QA_REQUIRED'],['cancel',{},'A2_OWNER_REQUIRED']])await assert.rejects(()=>client.call(method,request),{code});
  const qaClient=createAuthorityClient({url:server.url,token:ownCredential(server,f,'e1_qa','QA').token});await assert.rejects(()=>qaClient.claim({capabilities:['e1.code.parse']}),{code:'A2_WORKER_REQUIRED'});
  server.revokeCredential(credential.token);await assert.rejects(()=>client.claim({capabilities:['e1.code.parse']}),{code:'A2_AUTH_REQUIRED'});
  const state=await q.snapshot();assert.equal(state.leases.length,0);record({case:'SCOPED_RPC_NEGATIVE_ACL',project_id:f.project,persisted_state:state,credential_values_recorded:false});
 }finally{if(server)await server.close();await db.close();await qa.close();}
});
test('QA2 native: canonical business key across two missions yields one intent and persisted fake-provider count',async()=>{
 for(const after of [false,true]){
  const key='qa2_canonical_'+randomUUID().replaceAll('-',''),f=makeFixture({scenario:'effect',businessKey:key}),g=makeFixture({scenario:'effect',businessKey:key,projectId:f.project,sharedRegistry:f.originalRegistry}),db=await connect(),other=await connect(),qa=await connect('qa'),c=coordinator(db,f),c2=coordinator(other,g),q=coordinator(qa,f);let server;
  const root=fs.realpathSync(process.cwd()),parent=path.resolve(root,'E1/.local');if(!fs.existsSync(parent))fs.mkdirSync(parent);assert.equal(fs.lstatSync(parent).isSymbolicLink(),false);assert.equal(fs.realpathSync(parent).toLowerCase(),parent.toLowerCase());
  const scratch=path.join(parent,'awe_e1_qa2_'+randomUUID().replaceAll('-',''));assert.ok(scratch.startsWith(parent+path.sep));assert.equal(fs.existsSync(scratch),false);fs.mkdirSync(scratch);assert.equal(fs.realpathSync(scratch).toLowerCase(),scratch.toLowerCase());const providerFile=path.join(scratch,'clearly-fake-provider.json');fs.writeFileSync(providerFile,JSON.stringify({kind:'CLEARLY_FAKE_LOCAL_TEST_PROVIDER_NO_EXTERNAL_ACTION',submits:0,effects:[]}));
  try{
   await c.admit({},f.contexts.e1_owner);await c2.admit({},g.contexts.e1_owner);
   server=await createAuthorityServer({coordinator:c,dispatchEffect:async permit=>{if(after){const provider=JSON.parse(fs.readFileSync(providerFile));provider.submits++;provider.effects.push({business_key:permit.business_key,provider_ref:'qa2_fake:'+permit.business_key,payload_digest:permit.payload_digest});fs.writeFileSync(providerFile,JSON.stringify(provider));}throw new Error('Explicit synthetic lost ACK or before-effect fault');}});
   const credential=ownCredential(server,f,'e1_worker_a'),client=createAuthorityClient({url:server.url,token:credential.token});
   const claims=await Promise.all([client.claim({mission_id:f.spec.mission_id,task_id:'canonical_effect',capabilities:['e1.code.parse']}),c2.claim({mission_id:g.spec.mission_id,task_id:'canonical_effect',worker_id:'e1_worker_b',capabilities:['e1.code.parse'],lease_ms:1000})]);assert.equal(claims.filter(x=>x.status==='CLAIMED').length,1);
   let work=claims.find(x=>x.status==='CLAIMED');let actorClient=client;
   if(work.worker_id==='e1_worker_b')actorClient=createAuthorityClient({url:server.url,token:ownCredential(server,f,'e1_worker_b').token});
   const scope={mission_id:work.mission_id,task_id:work.task_id,worker_id:work.worker_id,fence:work.fence};
   await assert.rejects(()=>actorClient.dispatchEffect(scope),{code:'A2_EFFECT_OUTCOME_UNKNOWN'});
   const state=await q.snapshot();assert.equal(state.intents.length,1);assert.equal(state.intents[0].state,'OUTCOME_UNKNOWN');
   await assert.rejects(()=>actorClient.dispatchEffect(scope));assert.equal((await c2.claim({mission_id:work.mission_id===f.spec.mission_id?g.spec.mission_id:f.spec.mission_id,task_id:'canonical_effect',worker_id:'e1_worker_b',capabilities:['e1.code.parse'],lease_ms:1000})).status,'WAIT');
   const provider=JSON.parse(fs.readFileSync(providerFile));assert.equal(provider.submits,after?1:0);assert.equal(provider.effects.length,after?1:0);
   if(after){const receipt=provider.effects[0];await c.confirmEffect({...scope,provider_ref:receipt.provider_ref,receipt});assert.equal((await q.snapshot()).intents[0].state,'CONFIRMED');}
   record({case:'CROSS_MISSION_CANONICAL_BUSINESS_KEY_'+(after?'AFTER_FAKE_EFFECT':'BEFORE_FAKE_EFFECT'),project_id:f.project,intents:1,provider_readback:provider,provider_readback_sha256:digest(provider),no_second_submit:true,persisted_state:await q.snapshot()});
  }finally{if(server)await server.close();await db.close();await other.close();await qa.close();}
 }
});
