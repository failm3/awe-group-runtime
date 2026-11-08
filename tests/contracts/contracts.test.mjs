import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {validate,createValidationContext,evaluateOfflinePolicy,qaBindingMatches} from '../../contracts/validate.mjs';
import {supportedSchemas,inspectSchemas,validateShape} from '../../contracts/schema-validator.mjs';
import {canonicalize,digest} from '../../contracts/canonical.mjs';
import {validateSpecSuccessor,approvalBindingMatches} from '../../contracts/revisions.mjs';
const read=name=>JSON.parse(readFileSync(new URL('./fixtures/'+name+'.json',import.meta.url)));
const positive=read('positive'),negative=read('negative'),catalog=read('catalog');
const fixture=name=>structuredClone(positive.find(f=>f.contract===name));
test('all schema keywords and references are supported locally',()=>assert.deepEqual(inspectSchemas(),[]));
test('all registered schemas have a positive fixture',()=>assert.deepEqual(positive.map(f=>f.contract).sort(),[...supportedSchemas].sort()));
for(const f of positive) test('valid: '+f.id,()=>assert.deepEqual(validate(f.contract,f.value,createValidationContext(f.context)),{ok:true,errors:[]}));
for(const f of negative) test('reject: '+f.id,()=>{
 const actual=validate(f.contract,f.value,createValidationContext(f.context));
 assert.equal(actual.ok,false);
 assert(actual.errors.some(e=>e.includes(f.expected_error)),JSON.stringify(actual));
});
test('fixture catalogue binds every input including invalid money floats',()=>{
 for(const group of ['positive','negative']) for(const f of group==='positive'?positive:negative)
  assert.equal(catalog[group].find(c=>c.id===f.id).sha256,'sha256:'+createHash('sha256').update(JSON.stringify(f)).digest('hex'));
});
test('unknown contract rejected',()=>assert.deepEqual(validateShape('root-admin',{}),['UNKNOWN_CONTRACT']));
test('JSON object cannot impersonate trusted validation context',()=>{
 const f=fixture('actor-ref');assert(validate(f.contract,f.value,f.context).errors.includes('TRUSTED_CONTEXT_REQUIRED'));
});
test('validation context snapshots caller state',()=>{
 const f=fixture('actor-ref');const ctx=createValidationContext(f.context);f.context.principals.act_supervisor.role='OWNER';
 assert.equal(validate(f.contract,f.value,ctx).ok,true);assert(Object.isFrozen(ctx.principals));
});
test('canonical JSON fixed vector and insertion-order independence',()=>{
 assert.equal(canonicalize({z:1,a:[true,null,'Ж']}),'{"a":[true,null,"Ж"],"z":1}');
 assert.equal(digest({z:1,a:2}),digest({a:2,z:1}));
 assert.equal(digest({}),'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a');
});
for(const [name,value] of [['float',1.1],['unsafe integer',Number.MAX_SAFE_INTEGER+1],['NaN',NaN],['negative zero',-0],['undefined',undefined],['unicode','\ud800'],['sparse',new Array(1)],['date',new Date(0)],['prototype',Object.create({admin:true})],['unsafe-key',JSON.parse('{"__proto__":{}}')],['oversize','x'.repeat(66000)]])
 test('canonical rejects '+name,()=>assert.throws(()=>canonicalize(value)));
test('valid terminal transition requires exact read-back/checkpoint/outbox guard refs',()=>{
 const f=fixture('state-transition');f.context.state=f.value.from_state='PERSISTING';f.value.to_state='COMPLETE';
 f.value.guard_refs=['persisted','independent_readback','checkpoint','outbox'].map(k=>f.context.guards[k]);
 assert.equal(validate(f.contract,f.value,createValidationContext(f.context)).ok,true);
});
test('wait and verified resume contract are distinct from executing a transition',()=>{
 const f=fixture('state-transition');f.value.to_state='WAITING_FOR_OWNER';f.value.owner_action_id='oa_inventory';
 assert.equal(validate(f.contract,f.value,createValidationContext(f.context)).ok,true);
 f.context.state=f.value.from_state='WAITING_FOR_OWNER';f.context.resume_state=f.value.resume_state=f.value.to_state='RUNNING';
 f.value.guard_refs=['resume_verified','deps_complete','project_ready','quota'].map(k=>f.context.guards[k]);
 assert.equal(validate(f.contract,f.value,createValidationContext(f.context)).ok,true);
});
test('uncertain known-price attempt retains reservation and cannot settle',()=>{
 const f=fixture('attempt-receipt');const p=f.value.price;
 Object.assign(p,{status:'QUOTED',currency:'USD',input_micros_per_million:'1000000',output_micros_per_million:'2000000',quote_ref:digest({quote:1}),checked_at:f.context.now,expires_at:'2026-11-06T12:00:00.000Z',reason:null});
 Object.assign(f.value,{status:'OUTCOME_UNKNOWN',uncertain:true,reservation_micros:'10'});
 assert.equal(validate(f.contract,f.value,createValidationContext(f.context)).ok,true);
 f.value.reservation_micros='0';assert.equal(validate(f.contract,f.value,createValidationContext(f.context)).ok,false);
 f.value.reservation_micros='10';f.value.settled_micros='0';assert.equal(validate(f.contract,f.value,createValidationContext(f.context)).ok,false);
});
test('child grant narrows capabilities deadline and inherited budget',()=>{
 const f=fixture('run-grant');f.context.parent_grant=structuredClone(f.value);
 Object.assign(f.value,{run_id:'run_child',parent_run_id:'run_parent',depth:1,max_children:0,max_physical_attempts:1});
 assert.equal(validate(f.contract,f.value,createValidationContext(f.context)).ok,true);
 f.value.capabilities.push('tool_foreign');assert.equal(validate(f.contract,f.value,createValidationContext(f.context)).ok,false);
});
test('immutable spec revision cannot be rewritten; successor invalidates old QA',()=>{
 const old=fixture('spec-revision').value,next=structuredClone(old);next.spec.content_hash=digest({new:true});
 assert.equal(validateSpecSuccessor(old,next).reason,'IMMUTABLE_REVISION');
 next.spec.revision=2;next.supersedes=structuredClone(old.spec);
 assert.equal(validateSpecSuccessor(old,next).ok,true);
 const qa=fixture('qa-evidence');assert.equal(qaBindingMatches(qa.value,{spec:next.spec,aggregate_hash:qa.context.aggregate_hash,artifact_hash:qa.context.artifact_hash}),false);
});
test('approval cannot bind different action resource payload spec task or operation',()=>{
 const a=fixture('approval').value;assert.equal(approvalBindingMatches(a,a),true);
 for(const mutate of [x=>x.action='publish',x=>x.resource='other',x=>x.payload_hash=digest({changed:true}),x=>x.scope.task_id='task_foreign',x=>x.scope.operation_id='op_foreign',x=>x.spec.revision++,x=>x.policy_revision++]) {
  const b=structuredClone(a);mutate(b);assert.equal(approvalBindingMatches(a,b),false);
 }
});
test('draft policy never grants risky actions even with valid approval DTO',()=>{
 for(const action of ['read','publish','delete','charge','send_sensitive','inference','install','training']) assert.equal(evaluateOfflinePolicy(action,fixture('approval').value).decision,'DENY');
});
test('every declared terminal state denies every state destination',()=>{
 const base=fixture('state-transition');
 const states=JSON.parse(readFileSync(new URL('../../contracts/v1/catalog.json',import.meta.url))).task_states;
 for(const from of ['COMPLETE','CANCELLED','FAILED']) for(const to of states) {
  const f=structuredClone(base);f.value.from_state=f.context.state=from;f.value.to_state=to;
  assert(validate(f.contract,f.value,createValidationContext(f.context)).errors.includes('TERMINAL_IMMUTABLE'),from+' -> '+to);
 }
});
test('cancel remains sticky during reconciliation contract checks',()=>{
 const f=fixture('state-transition');f.context.state=f.value.from_state='RECONCILING';f.context.resume_state=f.value.resume_state=f.value.to_state='RUNNING';f.context.cancel_requested=true;
 f.value.guard_refs=['resume_verified','deps_complete','project_ready','quota'].map(k=>f.context.guards[k]);
 assert(validate(f.contract,f.value,createValidationContext(f.context)).errors.includes('CANCEL_PENDING'));
});
test('repeat validation is deterministic for every fixture',()=>{
 for(const f of [...positive,...negative]) {
  const ctx=createValidationContext(f.context);
  assert.deepEqual(validate(f.contract,f.value,ctx),validate(f.contract,f.value,ctx));
 }
});
