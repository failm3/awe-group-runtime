import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {digest} from '../contracts/index.mjs';
import {createPsqlSession} from '../coordinator/index.mjs';
import {createOfflineModelBrokerForTests} from '../broker/model.mjs';
import {MODEL_POLICY} from '../broker/schemas.mjs';
import {makeFixture,resource,connect,coordinator,completion,modelAttempt} from './native-fixture.mjs';

const readbacks=[];
function record(label,f,state,extra={}){readbacks.push({label,project_id:f.project,mission_id:f.spec.mission_id,persisted_state:state,...extra});fs.writeFileSync('E1/qa2/native-seams-readbacks.json',JSON.stringify({schema:'awe.qa2.native-readbacks/1',environment:'ISOLATED_E1_POSTGRESQL_18_PORT_5433',model_calls:0,external_provider_calls:0,readbacks},null,2)+'\n');}
async function ports(f){const db=await connect(),qa=await connect('qa');return{db,qa,c:coordinator(db,f),q:coordinator(qa,f),close:async()=>{await db.close();await qa.close();}};}
const denied=(fn,code)=>assert.rejects(async()=>fn(),error=>code?error.code===code:typeof error.code==='string');
const claim=(c,f,task_id,worker_id='e1_worker_a',lease_ms=30000)=>c.claim({mission_id:f.spec.mission_id,task_id,worker_id,capabilities:['e1.code.parse','e1.head.plan'],lease_ms});

test('QA2 native: malformed output is rejected before persistence; independent seeded-error QA is persisted',async()=>{
 const f=makeFixture(),p=await ports(f);
 try{
  assert.equal((await p.c.admit({},f.contexts.e1_owner)).status,'ADMITTED');
  const work=await claim(p.c,f,'parse_source');assert.equal(work.status,'CLAIMED');
  await assert.rejects(()=>p.c.complete(completion(work,{text:123})),e=>e.code?.startsWith('E1_'));
  let state=await p.q.snapshot();let row=state.tasks.find(t=>t.task_id==='parse_source');assert.equal(row.state,'RUNNING');assert.equal(row.result_hash,null);
  const output={text:JSON.stringify({input:[10,2,-1],actual:[10,2,-1],input_after:[10,2,-1]})};
  const submitted=completion(work,output);assert.equal((await p.c.complete(submitted)).status,'WAIT_QA');
  state=await p.q.snapshot();row=state.tasks.find(t=>t.task_id==='parse_source');assert.equal(row.result_hash,submitted.result_hash);assert.equal(digest(row.result),row.result_hash);
  const bytes=JSON.parse(row.result.output.text),expected=[...bytes.input].sort((a,b)=>a-b);
  const checks=[{check_id:'schema',passed:true},{check_id:'numeric_order',passed:JSON.stringify(bytes.actual)===JSON.stringify(expected)},{check_id:'input_preserved',passed:JSON.stringify(bytes.input_after)===JSON.stringify(bytes.input)},{check_id:'independent_qa',passed:row.producer_id!=='e1_qa'},{check_id:'scope',passed:row.project_id===f.project}];
  assert.equal(checks.find(x=>x.check_id==='numeric_order').passed,false);
  const request={mission_id:f.spec.mission_id,task_id:row.task_id,plan_digest:row.plan_digest,result_hash:row.result_hash,evaluator_id:'e1_qa',verdict:'FAIL',checks};
  await denied(()=>p.c.qaEvaluate(request),'A2_INDEPENDENT_QA_REQUIRED');
  await denied(()=>p.q.qaEvaluate({...request,result_hash:'sha256:'+'0'.repeat(64)}),'A2_QA_BINDING');
  await denied(()=>p.q.qaEvaluate({...request,evaluator_id:row.producer_id}),'A2_QA_BINDING');
  assert.equal((await p.q.qaEvaluate(request)).status,'FAILED');
  state=await p.q.snapshot();assert.equal(state.tasks.find(t=>t.task_id===row.task_id).state,'FAILED');
  const events=await p.q.events();assert.ok(events.some(e=>e.kind==='QA_FAIL'&&e.body.result_hash===row.result_hash));
  record('SEEDED_NUMERIC_ERROR_REJECTED_ON_FROZEN_PERSISTED_RESULT',f,state,{checks,qa_events:events.filter(e=>e.kind==='QA_FAIL'),cryptographic_acceptance:'NOT_ISSUED'});
 }finally{await p.close();}
});

test('QA2 native: project wrapper, leaf SQL ACL and QA write role are denied',async()=>{
 const f=makeFixture(),p=await ports(f);let worker;
 try{
  await p.c.admit({},f.contexts.e1_owner);
  await denied(()=>p.c.claim({project_id:'prj_unrelated',worker_id:'e1_worker_a',capabilities:['e1.code.parse']}),'A2_PROJECT_SCOPE');
  await denied(()=>p.q.cancel({mission_id:f.spec.mission_id,owner_id:'e1_owner',reason:'synthetic denied test'}),'A2_QA_WRITE_DENIED');
  worker=await createPsqlSession(resource,{role:'worker',verify_marker:false});
  await assert.rejects(()=>worker.query('SELECT count(*) FROM awe_e1_runtime.project;'));
  record('PROJECT_WRAPPER_WORKER_DB_AND_QA_WRITE_DENIAL',f,await p.q.snapshot());
 }finally{if(worker)await worker.close();await p.close();}
});

test('QA2 native: shared project budget race admits one reservation and cancellation releases it',async()=>{
 const f=makeFixture({scenario:'reads',budget:21,taskReserve:7,projectBudget:10}),p=await ports(f);const other=await connect();
 try{
  await p.c.admit({},f.contexts.e1_owner);const c2=coordinator(other,f);
  const contenders=await Promise.all([claim(p.c,f,'read_a'),claim(c2,f,'read_b','e1_worker_b')]);
  assert.equal(contenders.filter(x=>x.status==='CLAIMED').length,1);assert.equal(contenders.filter(x=>x.status==='WAIT').length,1);
  const state=await p.q.snapshot();assert.equal(state.project.reserved,7);assert.equal(state.project.spent,0);assert.ok(state.project.reserved+state.project.spent<=state.project.budget_cap);
  await p.c.cancel({mission_id:f.spec.mission_id,owner_id:'e1_owner',reason:'QA2 bounded budget race complete'});
  const after=await p.q.snapshot();assert.equal(after.project.reserved,0);record('CONCURRENT_BUDGET_RESERVATION_ONE_WINNER',f,after,{before_cancel:state,claim_results:contenders.map(x=>({status:x.status,task_id:x.task_id??null}))});
 }finally{await other.close();await p.close();}
});

test('QA2 native: concurrent model quota reservation has one winner in the same database',async()=>{
 const f=makeFixture({scenario:'models',quota:1}),p=await ports(f);const other=await connect();
 try{
  await p.c.admit({},f.contexts.e1_owner);const c2=coordinator(other,f);
  const a=await claim(p.c,f,'model_a'),b=await claim(c2,f,'model_b','e1_worker_b');assert.equal(a.status,'CLAIMED');assert.equal(b.status,'CLAIMED');
  const attempts=[modelAttempt(f,a,'quota_a_'+f.project),modelAttempt(f,b,'quota_b_'+f.project)];
  const results=await Promise.allSettled([p.c.reserve(attempts[0]),c2.reserve(attempts[1])]);
  assert.equal(results.filter(x=>x.status==='fulfilled').length,1);assert.equal(results.filter(x=>x.status==='rejected'&&x.reason.code==='A2_QUOTA_EXHAUSTED').length,1);
  const state=await p.q.snapshot();assert.equal(state.project.quota_used,1);assert.equal(state.attempts.length,1);assert.equal(state.attempts[0].state,'RESERVED');
  record('CONCURRENT_MODEL_QUOTA_ONE_WINNER_NO_MODEL_WIRE',f,state,{provider_kind:'NO_PROVIDER_CALLED',provider_effect_count:0});
  await p.c.cancel({mission_id:f.spec.mission_id,owner_id:'e1_owner',reason:'QA2 quota race complete'});
 }finally{await other.close();await p.close();}
});

test('QA2 native: unknown before provider call and after a fake lost ACK remains HOLD without resubmit',async()=>{
 for(const fakeEffects of [0,1]){
  const f=makeFixture({scenario:'models'}),p=await ports(f);let reopened;
  try{
   await p.c.admit({},f.contexts.e1_owner);const work=await claim(p.c,f,'model_a'),a=modelAttempt(f,work,'unknown_'+f.project);
   await p.c.reserve(a);if(fakeEffects)await p.c.markSending(a);
   const fakeProvider={kind:'IN_PROCESS_TEST_DOUBLE_NO_EXTERNAL_ACTION',effect_count:fakeEffects,submits:fakeEffects};
   await p.c.unknown({...a,reason:fakeEffects?'QA2_FAKE_EFFECT_LOST_ACK':'QA2_FAILURE_BEFORE_ANY_PROVIDER_CALL'});
   await denied(()=>p.c.reserve({...a,attempt_id:a.attempt_id+'_retry'}));
   assert.equal((await claim(p.c,f,'model_b','e1_worker_b')).status,'WAIT');
   await p.db.close();reopened=await connect();const c=coordinator(reopened,f);await c.recover();
   const state=await p.q.snapshot();assert.equal(state.missions[0].state,'HOLD');assert.equal(state.attempts.length,1);assert.equal(state.attempts[0].state,'OUTCOME_UNKNOWN');assert.equal(fakeProvider.submits,fakeEffects);
   record('UNKNOWN_'+fakeEffects+'_FAKE_PROVIDER_EFFECTS_NO_BLIND_RETRY',f,state,{fake_provider:fakeProvider});
  }finally{if(reopened)await reopened.close();await p.close();}
 }
});

test('QA2 native: cancellation and grant revocation reject late results and new dispatch',async()=>{
 for(const method of ['cancel','revoke']){
  const f=makeFixture(),p=await ports(f);
  try{
   await p.c.admit({},f.contexts.e1_owner);const work=await claim(p.c,f,'parse_source');
   await denied(()=>p.c[method]({mission_id:f.spec.mission_id,owner_id:'not_owner',reason:'synthetic denial'}),'A2_OWNER_REQUIRED');
   await p.c[method]({mission_id:f.spec.mission_id,owner_id:'e1_owner',reason:'QA2 bounded stop'});
   await denied(()=>p.c.complete(completion(work)));assert.equal((await claim(p.c,f,'head_control')).status,'WAIT');
   const state=await p.q.snapshot();assert.equal(state.missions[0].state,method==='cancel'?'CANCELLED':'REVOKED');assert.equal(state.project.reserved,0);record('STOP_'+method.toUpperCase()+'_PERSISTED',f,state);
  }finally{await p.close();}
 }
});

test('QA2 native: inbox dedupe, cursor CAS and fresh-session resume persist',async()=>{
 const f=makeFixture(),p=await ports(f);let reopened;
 try{
  await p.c.admit({},f.contexts.e1_owner);const consumer='qa2_consumer',body={kind:'synthetic-code-maintenance',number:1};
  assert.equal((await p.c.getCursor(consumer)).sequence,0);
  const item={source_id:'qa2_fixture',event_id:'qa2_event',body,payload_hash:digest(body)};
  const first=await p.c.inbox(item),second=await p.c.inbox(item);assert.equal(first.sequence,second.sequence);assert.equal(second.repeated,true);
  const changed={...body,number:2};await denied(()=>p.c.inbox({...item,body:changed,payload_hash:digest(changed)}),'A2_INBOX_CONFLICT');
  await p.c.ackCursor({consumer_id:consumer,sequence:first.sequence,expected_sequence:0});
  await denied(()=>p.c.ackCursor({consumer_id:consumer,sequence:first.sequence,expected_sequence:0}),'A2_CURSOR_CAS');
  await p.db.close();reopened=await connect();const c=coordinator(reopened,f);const cursor=await c.getCursor(consumer);assert.equal(cursor.sequence,first.sequence);
  assert.equal((await p.q.getCursor(consumer)).sequence,first.sequence);record('CURSOR_FRESH_SESSION_RESUME_AND_INBOX_DEDUPE',f,await p.q.snapshot(),{cursor,events:await p.q.events({after:first.sequence})});
 }finally{if(reopened)await reopened.close();await p.close();}
});
test('QA2 native: post-reserve expiry and route revocation release quota with zero generation wire',async()=>{
 for(const mutation of ['clock','route']){
  const f=makeFixture({scenario:'models'}),p=await ports(f);
  try{
   await p.c.admit({},f.contexts.e1_owner);const work=await claim(p.c,f,'model_a');const registry=structuredClone(f.registry);let clock=new Date().toISOString(),generation=0,released=0;
   const port={reserve:async request=>{const value=await p.c.reserve(request);if(mutation==='clock')clock=f.grant.expires_at;else registry.entries.find(x=>x.descriptor.ref.capability_id==='e1.head.plan').installed=false;return value;},markSending:request=>p.c.markSending(request),settle:request=>p.c.settle(request),unknown:request=>p.c.unknown(request),failBeforeSend:async request=>{released++;return p.c.failBeforeSend(request);}};
   const transport=async url=>{if(url.endsWith('/api/tags'))return new Response(JSON.stringify({models:[{name:MODEL_POLICY.model,digest:MODEL_POLICY.digest}]}));generation++;throw new Error('QA2 synthetic model generation must never run');};
   const broker=createOfflineModelBrokerForTests({accounting:port,registry,clock:()=>clock},{transport,label:'OFFLINE_TEST_DOUBLE'});
   const scope={mission_id:f.spec.mission_id,task_id:work.task_id,worker_id:work.worker_id,fence:work.fence,logical_request_id:'prewire_'+f.project,attempt_id:'prewire_attempt_'+f.project};
   const response=await broker.invoke({scope,spec:f.spec,grant:f.grant,capability_id:'e1.head.plan',input:{instruction:'Propose a bounded synthetic maintenance plan.'},data_label:'SYNTHETIC'});
   assert.equal(response.wire_attempts,0);assert.equal(generation,0);assert.equal(released,1);
   const state=await p.q.snapshot();assert.equal(state.attempts.length,1);assert.equal(state.attempts[0].state,'FAILED');assert.equal(state.project.quota_used,0);assert.equal(state.project.reserved,0);assert.equal(state.leases.length,0);
   assert.equal((await p.c.failBeforeSend(scope)).status,'FAILED');assert.equal((await p.q.snapshot()).project.quota_used,0);
   record('PROVEN_PREWIRE_'+mutation.toUpperCase()+'_RELEASES_PERSISTED_QUOTA_EXACTLY_ONCE',f,state,{broker_response:response,provider_kind:'OFFLINE_TEST_DOUBLE',generation_attempts:0});
  }finally{await p.close();}
 }
});
test('QA2 native: database function bodies match the exact frozen migration source',async()=>{
 const db=await connect();
 try{
  const names=['command','assert_active','assert_fence','release_task','quiesce_local_model','quiescence_canonical','quiescence_ref'];const matches=[];
  const {createHash}=await import('node:crypto');
  for(const name of names){
   const migration=fs.readFileSync('E1/coordinator/migrations/'+(name.startsWith('quiesc')?'0002-local-model-quiescence.sql':'0001-durable-runtime.sql'),'utf8');
   const local=new RegExp('CREATE OR REPLACE FUNCTION awe_e1_runtime\\.'+name+'\\([\\s\\S]*?AS \\$\\$([\\s\\S]*?)\\$\\$;').exec(migration);assert.ok(local,'Function source missing: '+name);
   const raw=await db.query("SELECT jsonb_build_object('md5',md5(p.prosrc)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='awe_e1_runtime' AND p.proname='"+name+"';");
   const actual=JSON.parse(raw);const expected=createHash('md5').update(local[1]).digest('hex');assert.equal(actual.md5,expected);matches.push({function:name,body_md5:expected});
  }
  readbacks.push({label:'FROZEN_DATABASE_FUNCTION_SOURCE_MATCH',resource_id:resource.resource_id,port:5433,matches});fs.writeFileSync('E1/qa2/native-seams-readbacks.json',JSON.stringify({schema:'awe.qa2.native-readbacks/1',environment:'ISOLATED_E1_POSTGRESQL_18_PORT_5433',model_calls:0,external_provider_calls:0,readbacks},null,2)+'\n');
 }finally{await db.close();}
});
test('QA2 native: length-limited final backend ACK is CONFIRMED accounting with REPAIR and retained usage',async()=>{
 const f=makeFixture({scenario:'models'}),p=await ports(f);
 try{
  await p.c.admit({},f.contexts.e1_owner);const work=await claim(p.c,f,'model_a');let generated=0;
  const transport=async url=>{if(url.endsWith('/api/tags'))return new Response(JSON.stringify({models:[{name:MODEL_POLICY.model,digest:MODEL_POLICY.digest}]}));generated++;return new Response(JSON.stringify({model:MODEL_POLICY.model,created_at:new Date().toISOString(),done:true,done_reason:'length',response:JSON.stringify({text:'A complete-looking but truncated-by-limit answer.'}),prompt_eval_count:17,eval_count:9,total_duration:101,eval_duration:55,load_duration:1,prompt_eval_duration:45}));};
  const port=Object.fromEntries(['reserve','markSending','settle','unknown','failBeforeSend'].map(name=>[name,request=>p.c[name](request)]));
  const broker=createOfflineModelBrokerForTests({accounting:port,registry:f.registry},{transport,label:'OFFLINE_TEST_DOUBLE'});
  const scope={mission_id:f.spec.mission_id,task_id:work.task_id,worker_id:work.worker_id,fence:work.fence,logical_request_id:'length_'+f.project,attempt_id:'length_attempt_'+f.project};
  const r=await broker.invoke({scope,spec:f.spec,grant:f.grant,capability_id:'e1.head.plan',input:{instruction:'Synthetic structured-output cap accounting check.'},data_label:'SYNTHETIC'});
  assert.equal(r.decision,'REPAIR');assert.equal(r.reason,'A3_OUTPUT_TRUNCATED');assert.equal(r.output,undefined);assert.equal(r.wire_attempts,1);assert.equal(generated,1);
  const state=await p.q.snapshot();assert.equal(state.attempts.length,1);assert.equal(state.attempts[0].state,'CONFIRMED');assert.equal(digest(state.attempts[0].usage),digest(r.usage));assert.equal(state.project.quota_used,1);assert.equal(state.project.spent,0);record('FINAL_LENGTH_ACK_KNOWN_USAGE_CONFIRMED_NOT_UNKNOWN',f,state,{provider_kind:'OFFLINE_TEST_DOUBLE',broker_decision:r.decision,generated_test_double_calls:1});
  await p.c.cancel({mission_id:f.spec.mission_id,owner_id:'e1_owner',reason:'QA2 length ACK test completed'});
 }finally{await p.close();}
});
