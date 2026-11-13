import test from 'node:test';
import assert from 'node:assert/strict';
import {digest, immutable} from '../contracts/index.mjs';
import {createMaintenanceMission, selectExecutor, materializeHeadDraft, MODEL_POLICY, createLocalModelBroker, freezeBrokerArtifact} from '../broker/index.mjs';
import {createOfflineModelBrokerForTests} from '../broker/model.mjs';
import {validateResourceDescriptor} from '../coordinator/resource.mjs';

const now='2026-11-08T01:00:00.000Z';
const clone=x=>structuredClone(x);
function fixture(){
 const f=createMaintenanceMission({now,suffix:'qa2'});
 return {...f,scope:{mission_id:f.spec.mission_id,task_id:'head_control',logical_request_id:'qa2.model',attempt_id:'qa2.attempt',worker_id:'e1_worker',fence:1}};
}
function accountingDouble(options={}){
 const events=[];
 return {events,port:Object.fromEntries(['reserve','markSending','settle','unknown','failBeforeSend'].map(method=>[method,async request=>{events.push({method,request:clone(request)});if(options[method])return options[method](request);return {status:{reserve:'RESERVED',markSending:'SENDING',settle:'CONFIRMED',unknown:'OUTCOME_UNKNOWN',failBeforeSend:'FAILED'}[method]};}]))};
}
function transportDouble({response=JSON.stringify({text:'Bounded synthetic review.'}),usage=true,tagsError=false,generateError=false,pin=MODEL_POLICY.digest,done_reason='stop'}={}){
 const calls=[];
 return {calls,transport:async(url,options)=>{
  calls.push({url,method:options.method,body:options.body?JSON.parse(options.body):null});
  if(url.endsWith('/api/tags')){if(tagsError)throw new TypeError('Synthetic model unavailable');return new Response(JSON.stringify({models:[{name:MODEL_POLICY.model,digest:pin,details:{family:'synthetic-test-double'}}]}));}
  assert.equal(url,MODEL_POLICY.endpoint+'/api/generate');if(generateError)throw new TypeError('Synthetic lost acknowledgement');
  const ack={model:MODEL_POLICY.model,created_at:now,done:true,done_reason,response};
  if(usage)Object.assign(ack,{prompt_eval_count:17,eval_count:9,total_duration:101,eval_duration:55,load_duration:1,prompt_eval_duration:45});
  return new Response(JSON.stringify(ack));
 }};
}
function fakeBroker(f,a,t){return createOfflineModelBrokerForTests({accounting:a.port,registry:f.registry,clock:()=>now},{transport:t.transport,label:'OFFLINE_TEST_DOUBLE'});}
const request=f=>({scope:f.scope,spec:f.spec,grant:f.grant,capability_id:'e1.code.review',input:{instruction:'Review the supplied synthetic numerical-sort requirement.'},data_label:'SYNTHETIC'});
function validDraft(){return {reason:'Inspect then independently review the supplied code.',tasks:[{task_id:'inspect',title:'Deterministic inspection',capability_id:'e1.code.parse',instruction:'Parse the supplied clean code fixture.',depends_on:[],criterion_ids:['correctness']},{task_id:'review',title:'Bounded semantic review',capability_id:'e1.code.review',instruction:'Review numeric ordering and preservation; request independent QA.',depends_on:['inspect'],criterion_ids:['review']}]};}
function bridge(f){return {spec:f.spec,grant:f.grant,capabilities:f.registry.descriptors,domainManifest:f.domainManifest,authority:f.authority,headContext:f.contexts.head,source:f.source,now,plan_id:'plan_qa2',revision:2,previous_digest:digest(f.bootstrapPlan)};}

test('QA2 resource descriptor denies retarget, hidden fields and unexpected roles before spawning',()=>{
 // Pure validation fixture, not a host resource handoff or execution authority.
 const descriptor=immutable({
  schema:'awe.e1.pg-resource/1',composition:'AWE_E1',resource_id:'awe_e1_a2a3_20261108',
  distro:'Ubuntu',port:5433,database:'awe_e1_test',
  socket_directory:'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/socket',
  pgdata:'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/pgdata',psql:'/usr/lib/postgresql/18/bin/psql',
  roles:{
   admin:{linux_user:'awe_e1_test',database_role:'awe_e1_test'},
   coordinator:{linux_user:'awe_e1_coord',database_role:'awe_e1_coord'},
   worker:{linux_user:'awe_e1_worker',database_role:'awe_e1_worker'},
   qa:{linux_user:'awe_e1_qa',database_role:'awe_e1_qa'}
  }
 });
 assert.equal(validateResourceDescriptor(descriptor).port,5433);
 for(const mutate of [x=>x.port=5432,x=>x.port=55582,x=>x.database='awe_e0_master01',x=>x.pgdata+='/../pgdata',x=>x.roles.qa.database_role='postgres',x=>x.roles.extra=x.roles.qa,x=>Object.defineProperty(x,'hidden',{enumerable:false,value:'synthetic'})]){
  const bad=clone(descriptor);mutate(bad);assert.throws(()=>validateResourceDescriptor(bad));
 }
});
test('QA2 public live broker denies injected wire and nonlocal endpoint',()=>{
 const f=fixture(),a=accountingDouble();
 assert.throws(()=>createLocalModelBroker({accounting:a.port,registry:f.registry,transport:()=>{}}));
 assert.throws(()=>createLocalModelBroker({accounting:a.port,registry:f.registry,endpoint:'https://example.invalid'}));
 assert.throws(()=>createLocalModelBroker({registry:f.registry}));
});
test('QA2 selector distinguishes deterministic script and bounded semantic model with rejected alternatives',()=>{
 const f=fixture();const options={registry:f.registry,spec:f.spec,grant:f.grant,now,remaining_micros:0};
 const script=selectExecutor({...options,task:{kind:'deterministic',data_label:'SYNTHETIC'}}),model=selectExecutor({...options,task:{kind:'semantic',data_label:'SYNTHETIC'}});
 assert.equal(script.selected.descriptor.executor_kind,'script');assert.equal(model.selected.descriptor.executor_kind,'llm');assert.ok(script.rejected.length>=2);assert.ok(model.rejected.length>=2);
 const denied=selectExecutor({...options,task:{kind:'semantic',data_label:'PERSONAL'}});assert.equal(denied.decision,'WAIT');assert.equal(denied.selected,null);assert.equal(denied.automatic_retry,false);
});
test('QA2 Head raw draft cannot inject budget, owner, recipient or executable tool',()=>{
 const f=fixture();for(const extra of [{budget:{amount_micros:'999'}},{owner_id:'e1_worker'},{recipient:'synthetic@example.invalid'},{tools:[{name:'shell',command:'whoami'}]}])assert.throws(()=>materializeHeadDraft({...validDraft(),...extra},bridge(f)));
 const tool=validDraft();tool.tasks[1].capability_id='shell.exec';assert.throws(()=>materializeHeadDraft(tool,bridge(f)));
 const cyclic=validDraft();cyclic.tasks[0].depends_on=['review'];assert.throws(()=>materializeHeadDraft(cyclic,bridge(f)));
});
test('QA2 forged Head context cannot materialize an otherwise valid plan',()=>{
 const f=fixture();assert.throws(()=>materializeHeadDraft(validDraft(),{...bridge(f),headContext:clone(f.contexts.head)}));
 assert.throws(()=>materializeHeadDraft(validDraft(),{...bridge(f),headContext:f.contexts.executor}));
});
test('QA2 one generation is bracketed by mandatory accounting and carries backend counts',async()=>{
 const f=fixture(),a=accountingDouble(),t=transportDouble();const r=await fakeBroker(f,a,t).invoke(request(f));
 assert.equal(r.decision,'PROPOSED');assert.equal(r.evidence_level,'OFFLINE_TEST_DOUBLE');assert.equal(r.accepted,false);assert.equal(r.effects,0);
 assert.equal(t.calls.filter(x=>x.method==='POST').length,1);assert.deepEqual(a.events.map(x=>x.method),['reserve','markSending','settle']);
 assert.equal(r.usage.input_tokens,17);assert.equal(r.usage.output_tokens,9);assert.equal(a.events[2].request.usage.output_tokens,9);assert.equal(a.events[0].request.quota_units,1);
 assert.equal(t.calls[1].body.model,MODEL_POLICY.model);assert.equal(t.calls[1].body.stream,false);
});
test('QA2 malformed model JSON settles consumed usage and asks for bounded repair without retry',async()=>{
 const f=fixture(),a=accountingDouble(),t=transportDouble({response:'{invalid synthetic JSON'});const r=await fakeBroker(f,a,t).invoke(request(f));
 assert.equal(r.decision,'REPAIR');assert.equal(r.accounting_status,'CONFIRMED');assert.equal(t.calls.filter(x=>x.method==='POST').length,1);assert.deepEqual(a.events.map(x=>x.method),['reserve','markSending','settle']);
});
test('QA2 personal label or email content blocks before tags, model generation and accounting',async()=>{
 for(const patch of [{data_label:'PERSONAL'},{input:{instruction:'Synthetic personal contact synthetic@example.invalid'}}]){
  const f=fixture(),a=accountingDouble(),t=transportDouble();const r=await fakeBroker(f,a,t).invoke({...request(f),...patch});
  assert.equal(r.decision,'BLOCK');assert.equal(t.calls.length,0);assert.equal(a.events.length,0);
 }
});
test('QA2 unavailable model or pin mismatch has controlled no-fallback decision and zero generation',async()=>{
 for(const options of [{tagsError:true},{pin:'0'.repeat(64)}]){const f=fixture(),a=accountingDouble(),t=transportDouble(options);const r=await fakeBroker(f,a,t).invoke(request(f));assert.ok(['WAIT','BLOCK'].includes(r.decision));assert.equal(r.accepted,false);assert.equal(t.calls.filter(x=>x.method==='POST').length,0);assert.equal(a.events.length,0);}
});
test('QA2 generation acknowledgement loss or missing usage enters UNKNOWN with one generation',async()=>{
 for(const options of [{generateError:true},{usage:false}]){const f=fixture(),a=accountingDouble(),t=transportDouble(options);const r=await fakeBroker(f,a,t).invoke(request(f));assert.equal(r.decision,'WAIT');assert.equal(r.accounting_status,'UNKNOWN');assert.equal(r.wire_attempts,1);assert.equal(t.calls.filter(x=>x.method==='POST').length,1);assert.deepEqual(a.events.map(x=>x.method),['reserve','markSending','unknown']);}
});
test('QA2 grant expiry or route revocation after reserve releases a proven no-wire reservation',async()=>{
 for(const mutation of ['clock','route']){
  const f=fixture(),registry=clone(f.registry);let current=now;
  const a=accountingDouble({reserve:()=>{if(mutation==='clock')current=f.grant.expires_at;else registry.entries.find(x=>x.descriptor.ref.capability_id==='e1.code.review').installed=false;return{status:'RESERVED'};}}),t=transportDouble();
  const broker=createOfflineModelBrokerForTests({accounting:a.port,registry,clock:()=>current},{transport:t.transport,label:'OFFLINE_TEST_DOUBLE'});
  const r=await broker.invoke(request(f));assert.ok(['BLOCK','WAIT'].includes(r.decision));assert.equal(r.wire_attempts,0);assert.equal(t.calls.filter(x=>x.method==='POST').length,0);assert.deepEqual(a.events.map(x=>x.method),['reserve','failBeforeSend']);
 }
});
test('QA2 lost SENDING marker response is UNKNOWN with zero model wire and no blind generation',async()=>{
 const f=fixture(),a=accountingDouble({markSending:()=>{throw Object.assign(new Error('Synthetic durable marker ACK lost'),{code:'A2_DB_TRANSPORT_UNKNOWN'});}}),t=transportDouble();
 const r=await fakeBroker(f,a,t).invoke(request(f));assert.equal(r.decision,'WAIT');assert.equal(r.wire_attempts,0);assert.equal(t.calls.filter(x=>x.method==='POST').length,0);assert.deepEqual(a.events.map(x=>x.method),['reserve','markSending','unknown']);
});
test('QA2 ambiguous reservation ACK is held UNKNOWN rather than released as a proven no-send',async()=>{
 const f=fixture(),a=accountingDouble({reserve:()=>{throw Object.assign(new Error('Synthetic reservation commit ACK lost'),{code:'A2_DB_TRANSPORT_UNKNOWN'});}}),t=transportDouble();
 const r=await fakeBroker(f,a,t).invoke(request(f));assert.equal(r.decision,'WAIT');assert.equal(r.wire_attempts,0);assert.equal(t.calls.filter(x=>x.method==='POST').length,0);assert.deepEqual(a.events.map(x=>x.method),['reserve','unknown']);
});
test('QA2 genuine length ACK settles once and requests REPAIR even when output happens to be valid JSON',async()=>{
 for(const response of [JSON.stringify({text:'Complete-looking but length-limited output.'}),'{truncated']){const f=fixture(),a=accountingDouble(),t=transportDouble({response,done_reason:'length'});const r=await fakeBroker(f,a,t).invoke(request(f));assert.equal(r.decision,'REPAIR');assert.equal(r.reason,'A3_OUTPUT_TRUNCATED');assert.equal(r.accounting_status,'CONFIRMED');assert.equal(r.wire_attempts,1);assert.equal(r.usage.output_tokens,9);assert.equal(r.output,undefined);assert.equal(r.plan,undefined);assert.equal(r.accepted,false);assert.deepEqual(a.events.map(x=>x.method),['reserve','markSending','settle']);assert.equal(t.calls.filter(x=>x.method==='POST').length,1);}
});
test('QA2 unrecognized backend completion reason remains UNKNOWN with no invented settlement',async()=>{const f=fixture(),a=accountingDouble(),t=transportDouble({done_reason:'synthetic_unrecognized'});const r=await fakeBroker(f,a,t).invoke(request(f));assert.equal(r.decision,'WAIT');assert.equal(r.accounting_status,'UNKNOWN');assert.deepEqual(a.events.map(x=>x.method),['reserve','markSending','unknown']);});
test('QA2 independent frozen proposal checker rejects seeded missing dependency and digest substitution',()=>{
 const f=fixture();
 const evaluate=artifact=>{
  if(digest(artifact.output)!==artifact.artifact_digest)return 'REJECT_DIGEST';
  const plan=artifact.output;
  const deterministic=new Set(plan.tasks.filter(x=>x.capability.capability_id==='e1.code.parse').map(x=>x.task_id));
  if(!plan.tasks.some(x=>x.capability.capability_id==='e1.code.review'&&x.depends_on.some(id=>deterministic.has(id))))return 'REJECT_SEMANTIC_DEPENDENCY';
  if(artifact.producer_id==='e1_qa')return 'REJECT_SELF_REVIEW';
  return 'TECHNICAL_CHECK_PASS_NO_ACCEPTANCE';
 };
 const result=materializeHeadDraft(validDraft(),bridge(f));const frozen=freezeBrokerArtifact({output:result.plan,producer_id:'e1_head',task_id:'head_control',plan_digest:digest(f.bootstrapPlan),rubric_digest:digest(f.rubric)});
 assert.equal(evaluate(frozen),'TECHNICAL_CHECK_PASS_NO_ACCEPTANCE');
 const corrupted=clone(result.plan);corrupted.tasks.find(x=>x.capability.capability_id==='e1.code.review').depends_on=[];
 const seeded=freezeBrokerArtifact({...frozen,output:corrupted});assert.equal(evaluate(seeded),'REJECT_SEMANTIC_DEPENDENCY');
 assert.equal(evaluate({...frozen,output:corrupted}),'REJECT_DIGEST');assert.equal(frozen.accepted,false);assert.ok(Object.isFrozen(frozen.output.tasks));
});
