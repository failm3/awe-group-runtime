import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture} from './fixtures.mjs';
import {digest} from '../../awe/hermes_runtime/protocol.mjs';
import {planHash,createHermesRuntime} from '../../awe/hermes_runtime/adapter.mjs';
import {createNativeHermesTransport} from '../../awe/hermes_runtime/native-binding.mjs';
const denied=r=>assert.equal(r.decision,'DENY',JSON.stringify(r));
const status=(r,s)=>assert.equal(r.status,s,JSON.stringify(r));
test('real D03 projection + synthetic parent/child lifecycle, checkpoint, join, no QA/task completion',async t=>{
 const f=await fixture(t);status(await f.launch(),'RUNNING');const child=f.child();status(await f.launch(child),'RUNNING');
 const cp=await f.host.checkpoint('run_child');assert.equal(cp.resumable,false);
 f.emit('RESULT',undefined,'run_child');status(await f.host.join('run_child'),'WORK_COMPLETED');
 f.emit();const r=await f.host.join('run_parent');status(r,'WORK_COMPLETED');assert.equal(r.qa,'QA_NOT_RUN');assert.equal(r.authoritative_complete,false);
 assert.equal(f.task().state,'RUNNING');assert.equal(f.counts.begin,2);assert.equal(f.counts.result,2);assert.equal(f.synthetic.control.inspect().physical_dispatches,0);
});
test('concurrent duplicate launch is a readback, exactly one synthetic child',async t=>{
 const f=await fixture(t);const rs=await Promise.all(Array.from({length:20},()=>f.launch()));rs.forEach(r=>status(r,'RUNNING'));
 assert.equal(f.counts.begin,1);assert.equal(f.synthetic.control.inspect().launches,1);
});
test('same run id with modified request fails idempotency',async t=>{
 const f=await fixture(t);await f.launch();const r=f.request();r.actor_id='act_other';denied(await f.launch(r));assert.equal(f.counts.begin,1);
});
const mutations={
 version:r=>r.version='rt01/2',unknown_field:r=>r.shell='cmd',actor:r=>r.actor_id='act_other',grant_actor:r=>r.grant.actor.identity_id='act_other',
 project:r=>r.grant.scope.project_id='prj_beta',task:r=>r.grant.scope.task_id='task_other',epoch:r=>r.grant.epochs.auth++,spec:r=>r.grant.spec.revision++,revision:r=>r.grant.expected_revision++,
 config:r=>r.grant.config_hash=digest({bad:1}),manifest:r=>r.grant.manifest_hash=digest({bad:1}),fence:r=>r.runtime_pin.fence++,lease:r=>r.grant.deadline='2027-01-01T00:00:00.000Z',
 memory_project:r=>r.context.project_id='prj_beta',memory_task:r=>r.context.task_id='task_other',writable_context:r=>r.context.readonly=false,
 context_hash:r=>r.context.hash=digest({bad:1}),model_pin:r=>r.model.revision=34,tool_capability:r=>r.grant.capabilities=[],
 admission_project:r=>r.admission.project_id='prj_beta',admission_task:r=>r.admission.task_id='task_other',admission_payload:r=>r.admission.payload_hash=digest({bad:1}),
 money_number:r=>r.admission.reserve_micros=1,excess_depth:r=>r.grant.depth=2
};
for(const [name,mutate]of Object.entries(mutations))test('launch denies '+name+' before any attempt',async t=>{
 const f=await fixture(t),r=f.request();mutate(r);r.admission.plan_hash=planHash(r);denied(await f.launch(r));assert.equal(f.counts.begin,0);assert.equal(f.synthetic.control.inspect().launches,0);
});
test('admission plan tampering denied',async t=>{const f=await fixture(t),r=f.request();r.admission.plan_hash=digest({bad:1});denied(await f.launch(r));});
for(const [name,change]of Object.entries({capability:{capabilities:['tool_other']},budget:{budget_ref:digest({other:1})},depth:{depth:0},deadline:{deadline:'2027-01-01T00:00:00.000Z'},attempts:{max_physical_attempts:6},grandchildren:{max_children:1}}))
 test('child grant narrowing denies '+name,async t=>{const f=await fixture(t);await f.launch();denied(await f.launch(f.child('run_child',change)));assert.equal(f.counts.begin,1);});
test('child model swap denied against parent pin',async t=>{const f=await fixture(t);await f.launch();const r=f.child();r.model.revision='rev_two';r.admission.plan_hash=planHash(r);denied(await f.launch(r));});
test('child tool digest swap denied against parent',async t=>{const f=await fixture(t);await f.launch();const r=f.child();r.tools[0].digest=digest({bad:1});r.admission.plan_hash=planHash(r);denied(await f.launch(r));});
test('child limit and attempt allocation retained after cancellation',async t=>{
 const f=await fixture(t);await f.launch();await f.launch(f.child('run_one'));await f.host.cancel('run_one');await f.launch(f.child('run_two'));
 denied(await f.launch(f.child('run_three')));assert.equal(f.counts.begin,3);
});
test('sibling allocation cannot exceed parent',async t=>{const f=await fixture(t);await f.launch();await f.launch(f.child('run_one',{max_physical_attempts:3}));denied(await f.launch(f.child('run_two')));});
test('attempt and effect operation cannot be reused by another child',async t=>{
 const f=await fixture(t);await f.launch();const r=f.child();r.admission.attempt_id=f.request().admission.attempt_id;r.admission.plan_hash=planHash(r);denied(await f.launch(r));
 r.admission.attempt_id='attempt_unique';r.admission.operation_id=f.request().admission.operation_id;denied(await f.launch(r));
});
test('cancellation cascades with terminal proof; late result cannot resurrect',async t=>{
 const f=await fixture(t);await f.launch();await f.launch(f.child());status(await f.host.cancel('run_parent'),'CANCELLED');status(f.host.inspect('run_child'),'CANCELLED');
 f.emit();status(await f.host.streamEvents('run_parent'),'CANCELLED');assert.equal(f.counts.result,2);
});
for(const fault of ['launch','hang_launch','stream','hang_stream','cancel','hang_cancel','reconcile','hang_reconcile'])test('lost or hung '+fault+' -> sticky uncertainty; never retry',async t=>{
 const f=await fixture(t,{transport:{fault}});let r=await f.launch();
 if(fault.includes('stream'))r=await f.host.streamEvents('run_parent');if(fault.includes('cancel'))r=await f.host.cancel('run_parent');if(fault.includes('reconcile'))r=await f.host.reconcile('run_parent');
 status(r,'OUTCOME_UNKNOWN');for(let i=0;i<5;i++)status(await f.launch(),'OUTCOME_UNKNOWN');assert.equal(f.counts.begin,1);assert.equal(f.synthetic.control.inspect().launches,1);
});
test('bounded join detects no terminal result',async t=>{const f=await fixture(t);await f.launch();status(await f.host.join('run_parent'),'OUTCOME_UNKNOWN');});
test('restart quarantines orphan and preserves unknown on a second restart',async t=>{
 const f=await fixture(t);await f.launch();f.restart();status(f.host.inspect('run_parent'),'OUTCOME_UNKNOWN');status(await f.launch(),'OUTCOME_UNKNOWN');f.restart();status(f.host.inspect('run_parent'),'OUTCOME_UNKNOWN');assert.equal(f.counts.begin,1);
});
test('completed work survives adapter recreation without execution',async t=>{const f=await fixture(t);await f.launch();f.emit();await f.host.join('run_parent');f.restart();status(await f.launch(),'WORK_COMPLETED');assert.equal(f.counts.begin,1);});
test('D09 admission acknowledgement loss never launches or retries',async t=>{const f=await fixture(t);f.control.admissionLost=true;status(await f.launch(),'OUTCOME_UNKNOWN');status(await f.launch(),'OUTCOME_UNKNOWN');assert.equal(f.synthetic.control.inspect().launches,0);});
test('D09 result acknowledgement loss cannot leave successful work status',async t=>{const f=await fixture(t);await f.launch();f.control.resultLost=true;f.emit();status(await f.host.join('run_parent'),'OUTCOME_UNKNOWN');});
test('crash between terminal intent and D09 result cannot recover as success',async t=>{
 const f=await fixture(t);let snapshot;f.args.attempts.result=()=>{snapshot=f.journal.read();return new Promise(()=>{});};await f.launch();f.emit();status(await f.host.join('run_parent'),'OUTCOME_UNKNOWN');
 assert.equal(snapshot.at(-1).entry.run.status,'TERMINAL_INTENT');const recovered=createHermesRuntime({...f.args,journal:{read:()=>snapshot,append:()=>digest({saved:true})}});status(recovered.inspect('run_parent'),'OUTCOME_UNKNOWN');
});
test('authority lost after D09 begin is checked again before launch',async t=>{
 const f=await fixture(t),begin=f.args.attempts.begin;f.args.attempts.begin=async c=>{const r=await begin(c);f.control.revoked=true;return r;};status(await f.launch(),'OUTCOME_UNKNOWN');assert.equal(f.synthetic.control.inspect().launches,0);
});
test('parent failure cancels active child rather than leaving unowned work',async t=>{const f=await fixture(t);await f.launch();await f.launch(f.child());f.emit('ERROR',{code:'parent_failure'});status(await f.host.join('run_parent'),'FAILED');status(f.host.inspect('run_child'),'CANCELLED');});
test('parent uncertainty quarantines active descendants',async t=>{const f=await fixture(t);await f.launch();await f.launch(f.child());f.emit();status(await f.host.join('run_parent'),'OUTCOME_UNKNOWN');status(f.host.inspect('run_child'),'OUTCOME_UNKNOWN');});
test('zero attempt grant cannot launch even a synthetic child',async t=>{const f=await fixture(t),r=f.request();r.grant.max_physical_attempts=0;r.admission.plan_hash=planHash(r);denied(await f.launch(r));assert.equal(f.counts.begin,0);});
for(const field of ['revoked','modelLive','toolLive'])test('dynamic '+field+' change fences callbacks',async t=>{
 const f=await fixture(t);await f.launch();f.control[field]=field==='revoked';f.emit();status(await f.host.join('run_parent'),'OUTCOME_UNKNOWN');assert.equal(f.counts.result,0);
});
for(const [name,transform]of Object.entries({owner:s=>({...s,epochs:{...s.epochs,owner:99}}),fence:s=>({...s,runtime_pin:{...s.runtime_pin,fence:99}}),cancel:s=>({...s,cancelled:true}),restore:s=>({...s,restore_pending:true}),lease:s=>({...s,lease_expires_at:'2020-01-01T00:00:00.000Z'})}))
 test('D03 '+name+' invalidation fences callbacks',async t=>{const f=await fixture(t);await f.launch();f.transform(transform);f.emit();status(await f.host.join('run_parent'),'OUTCOME_UNKNOWN');});
test('checkpoint is immutable scoped digest, never re-execution permission',async t=>{const f=await fixture(t);await f.launch();const c=await f.host.checkpoint('run_parent');assert(Object.isFrozen(c));assert.equal(c.resumable,false);f.restart();status(f.host.inspect('run_parent'),'OUTCOME_UNKNOWN');});
test('worker facade has no privileged APIs, self QA, memory mutation or physical effects',async t=>{
 const f=await fixture(t);await f.launch();const w=f.host.bindWorker('run_parent',f.session);assert.equal(w.launchChild,undefined);assert.equal(w.checkpoint,undefined);
 for(const method of ['readMemory','writeMemory','submitQa','accept','executeTool','requestPhysicalEffect']){const r=w[method]();denied(r);assert.equal(r.physical_decision,'DENY');}
 denied(w.proposeChild('{}'));const fake=f.host.bindWorker('run_parent',{});assert.throws(()=>fake.status());denied(await fake.cancel());
});
test('native transport cannot enter the E0 host',async t=>{const f=await fixture(t);assert.throws(()=>createHermesRuntime({...f.args,transport:createNativeHermesTransport()}),/REAL_HERMES_NOT_RUN/);});
