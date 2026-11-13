import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {digest} from '../contracts/index.mjs';import {createAuthorityServer,createAuthorityClient} from '../coordinator/index.mjs';import {LOCAL_MODEL_QUIESCENCE} from '../coordinator/quiescence.mjs';
import {makeFixture,connect,coordinator,modelAttempt,pause} from './native-fixture.mjs';
const readbacks=[];function record(value){readbacks.push(value);fs.writeFileSync('E1/qa2/quiescence-independent-readbacks.json',JSON.stringify({schema:'awe.qa2.quiescence-readback/1',proof_kind:'SYNTHETIC_OPERATOR_ATTESTATION_TEST_FIXTURE_NO_PROVIDER_CALL',actual_model_calls:0,readbacks},null,2)+'\n');}
async function held(options={}){
 const f=makeFixture(options),db=await connect(),qa=await connect('qa'),c=coordinator(db,f),q=coordinator(qa,f);
 await c.admit({},f.contexts.e1_owner);const task=options.scenario==='effect'?'canonical_effect':'model_a';
 const work=await c.claim({mission_id:f.spec.mission_id,task_id:task,worker_id:'e1_worker_a',capabilities:['e1.head.plan','e1.code.parse'],lease_ms:30000});assert.equal(work.status,'CLAIMED');
 const a={...modelAttempt(f,work,'quiescence_'+f.project),reserve_micros:options.reserve??0};await c.reserve(a);
 if(options.checkSecondAttempt)await assert.rejects(()=>c.reserve({...a,attempt_id:a.attempt_id+'_other',logical_request_id:a.logical_request_id+'_other'}),{code:'A2_NO_BLIND_RETRY'});
 await c.markSending(a);await c.unknown({...a,reason:'QA2_SYNTHETIC_NO_PROVIDER_CALL'});
 const t0=new Date().toISOString();await pause(1100);const t1=new Date().toISOString();
 const ref=(kind,status,at)=>({schema:'awe.e1.local-'+kind+'-proof-ref/1',ref:'artifact:qa2/'+kind+'/'+f.project,digest:digest({kind,project:f.project,synthetic:true}),observed_at:at,status});
 const idle=(index,at)=>({schema:'awe.e1.local-idle-proof-ref/1',ref:'artifact:qa2/idle-'+index+'/'+f.project,digest:digest({index,kind:'idle',project:f.project,synthetic:true}),observed_at:at,status:'IDLE'});
 const proof={...LOCAL_MODEL_QUIESCENCE,project_id:f.project,mission_id:a.mission_id,task_id:a.task_id,logical_request_id:a.logical_request_id,attempt_id:a.attempt_id,worker_id:a.worker_id,fence:String(a.fence),effect_class:'NONE',observed_at:t1,proof_ref:'artifact:qa2/quiescence/'+f.project,cancellation:ref('cancel','COMPLETED',t0),idle_observations:[idle(1,t0),idle(2,t1)],runner_absence:ref('runner-absence','ABSENT',t1)};
 const request={mission_id:a.mission_id,task_id:a.task_id,logical_request_id:a.logical_request_id,attempt_id:a.attempt_id,worker_id:a.worker_id,fence:a.fence,proof,proof_digest:digest(proof)};
 return{f,db,qa,c,q,a,request,close:async()=>{await db.close();await qa.close();}};
}
function accounting(state){return{project:{spent:state.project.spent,reserved:state.project.reserved,quota_used:state.project.quota_used},mission:{state:state.missions[0].state,spent:state.missions[0].spent,reserved:state.missions[0].reserved},attempts:state.attempts,task:state.tasks.map(x=>({task_id:x.task_id,state:x.state,claims:x.claims,result_hash:x.result_hash,document:x.document}))};}
test('QA2 native quiescence releases only one held execution lease and preserves UNKNOWN plus charged quota',async()=>{
 const p=await held({scenario:'models'});
 try{
  const before=await p.q.snapshot();const result=await p.c.quiesceLocalModel(p.request);assert.equal(result.status,'QUIESCED_EXECUTION_ONLY');assert.equal(result.quota_released,false);assert.equal(result.accounting_unchanged,true);
  const after=await p.q.snapshot();assert.deepEqual(accounting(after),accounting(before));assert.equal(after.project.quota_used,1);assert.equal(after.leases.length,0);const target=after.tasks.find(x=>x.task_id==='model_a');assert.ok(target.fence>p.a.fence);assert.equal(target.state,'HOLD');assert.equal(after.attempts[0].fence,p.a.fence);
  const repeat=await p.c.quiesceLocalModel(p.request);assert.equal(repeat.repeated,true);assert.equal(repeat.new_fence,result.new_fence);assert.equal((await p.q.snapshot()).project.quota_used,1);
  const proof={...p.request.proof,proof_ref:p.request.proof.proof_ref+'-changed'};await assert.rejects(async()=>p.c.quiesceLocalModel({...p.request,proof,proof_digest:digest(proof)}),{code:'A2_QUIESCENCE_PROOF_CONFLICT'});
  const events=await p.q.events();assert.equal(events.filter(x=>x.kind==='LOCAL_MODEL_EXECUTION_QUIESCED').length,1);
  assert.equal((await p.c.claim({mission_id:p.a.mission_id,task_id:'model_b',worker_id:'e1_worker_b',capabilities:['e1.head.plan']})).status,'WAIT');await assert.rejects(()=>p.c.heartbeat(p.a));
  record({case:'EXECUTION_ONLY_RELEASE_NO_OUTCOME_OR_QUOTA_REWRITE',project_id:p.f.project,before:accounting(before),after:accounting(after),old_fence:p.a.fence,new_fence:target.fence,event_count:1,repeated_fence_stable:true});
 }finally{await p.close();}
});
test('QA2 native quiescence cannot be called by QA or any worker/broker/QA RPC credential',async()=>{
 const p=await held({scenario:'models'});let server;
 try{
  assert.throws(()=>p.q.quiesceLocalModel(p.request),{code:'A2_QUIESCENCE_ROLE_DENIED'});
  server=await createAuthorityServer({coordinator:p.c,qaCoordinator:p.q});
  for(const role of ['WORKER','BROKER','QA']){const credential=server.issueCredential({project_id:p.f.project,principal_id:role==='QA'?'e1_qa':'e1_worker_a',role,capabilities:['e1.head.plan']});const client=createAuthorityClient({url:server.url,token:credential.token});await assert.rejects(()=>client.call('quiesceLocalModel',p.request),{code:'A2_RPC_METHOD_DENIED'});}
  const after=await p.q.snapshot();assert.equal(after.leases.length,1);assert.equal(after.project.quota_used,1);record({case:'QUIESCENCE_ROLE_AND_RPC_DENIAL',project_id:p.f.project,ledger:accounting(after),held_leases:after.leases.length,credential_values_recorded:false});
 }finally{if(server)await server.close();await p.close();}
});
test('QA2 native quiescence rejects stale/future/pin/scope/cancellation/idle/hash proof defects atomically',async()=>{
 const p=await held({scenario:'models'});
 try{
  const before=await p.q.snapshot();
  const bad=[r=>r.proof.route_id='cloud.synthetic',r=>r.proof.model_digest='0'.repeat(64),r=>r.proof.cancellation.status='PENDING',r=>r.proof.idle_observations[1].observed_at=r.proof.idle_observations[0].observed_at,r=>r.proof.observed_at=new Date(Date.now()+30000).toISOString(),r=>{r.proof.observed_at=new Date(Date.now()-360000).toISOString();r.proof.cancellation.observed_at=new Date(Date.now()-362000).toISOString();r.proof.idle_observations[0].observed_at=new Date(Date.now()-362000).toISOString();r.proof.idle_observations[1].observed_at=new Date(Date.now()-360500).toISOString();r.proof.runner_absence.observed_at=new Date(Date.now()-360500).toISOString();},r=>{r.fence=Number(r.fence)+1;r.proof.fence=String(r.fence);}];
  for(const mutate of bad){const request=structuredClone(p.request);mutate(request);request.proof_digest=digest(request.proof);await assert.rejects(async()=>p.c.quiesceLocalModel(request));}
  await assert.rejects(async()=>p.c.quiesceLocalModel({...p.request,proof_digest:'sha256:'+'0'.repeat(64)}));
  const after=await p.q.snapshot();assert.deepEqual(after,before);record({case:'QUIESCENCE_MALFORMED_PROOFS_ROLL_BACK',project_id:p.f.project,negative_cases:bad.length+1,unchanged_snapshot_digest:digest(accounting(after)),held_leases:after.leases.length});
 }finally{await p.close();}
});
test('QA2 native quiescence rejects positive money and effect intent without changing a held target',async()=>{
 const options=[{scenario:'models',budget:18,taskReserve:9,projectBudget:18,reserve:1},{scenario:'effect',effectLlm:true}];
 for(const config of options){const p=await held(config);try{const before=await p.q.snapshot();await assert.rejects(async()=>p.c.quiesceLocalModel(p.request));const after=await p.q.snapshot();assert.deepEqual(after,before);record({case:'QUIESCENCE_INELIGIBLE_TARGET_DENIED',project_id:p.f.project,config,unchanged_snapshot_digest:digest(accounting(after)),held_leases:after.leases.length});}finally{await p.close();}}
});
test('QA2 native one-active-attempt guard blocks a second pending model request on the same lease',async()=>{
 const p=await held({scenario:'models',checkSecondAttempt:true});try{const state=await p.q.snapshot();assert.equal(state.attempts.length,1);assert.equal(state.project.quota_used,1);assert.equal(state.leases.length,1);record({case:'SECOND_PENDING_ATTEMPT_PREVENTED_BY_PUBLIC_BOUNDARY',project_id:p.f.project,attempts:1,quota_used:1,provider_calls:0});}finally{await p.close();}
});
