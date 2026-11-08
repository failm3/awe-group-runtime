import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fixture} from './fixtures.mjs';
import {restoreCheckpoint} from '../../awe/integration_v4/checkpoint.mjs';
import {digest,canonicalize} from '../../contracts/canonical.mjs';
import {evaluateExact} from '../../awe/qa/evaluator.mjs';
import {assertCaps} from '../budget/fixtures.mjs';

async function completed(t,options){const f=await fixture(t,options);assert.equal((await f.host.start()).status,'RUNNING');assert.equal((await f.host.finish()).status,'WORK_COMPLETED');return f;}
test('INT04 actual TR -> SEC -> LLM/D06 -> RT parent/child -> pure tool -> D03/D07 -> fixed D08 -> distinct owner',async t=>{
 const f=await completed(t),{host}=f;assert.equal(host.bundle.evidence.execution.output.input_hash,digest({text:f.task.text}));
 assert.equal(host.read().qa,null);assert.equal(host.bundle.evidence.physical_dispatches,0);
 const before=globalThis.__sec01EvaluatorCalls;const qa=await host.verify();assert.equal(qa.qa,'QA_PASS',JSON.stringify(qa));assert.equal(globalThis.__sec01EvaluatorCalls-before,1);assert.equal(qa.evaluator_calls,1);
 assert.equal(host.read().qa.accepted,false);const accepted=await host.accept(qa.proof);assert.equal(accepted.acceptance,'OWNER_ACCEPTED');assert.equal(accepted.authoritative_complete,false);assert.equal(accepted.published,false);
 assert.equal(f.b.controls.r1.calls().length,1);assert.equal(f.b.ledger.operation('op-one').attempts.length,1);assertCaps(f.b);
 const restored=restoreCheckpoint(f.directory);assert.equal(restored.checkpoint.bundle.reference.file_hash,host.bundle.reference.file_hash);assert.equal(restored.checkpoint.d03.includes('OWNER_ACCEPTED'),false);
 fs.mkdirSync('INT-04/evidence/scenarios',{recursive:true});fs.writeFileSync('INT-04/evidence/scenarios/full-cycle.json',JSON.stringify({status:'PASS',task:f.task,plan:host.plan,result:host.bundle.evidence.execution.output,model:host.model,work:'WORK_COMPLETED',qa:{qa:qa.qa,evaluator_calls:qa.evaluator_calls},owner:accepted,physical_dispatches:0,baseline_task:f.h.service.getTask(f.h.state,{project_id:'prj_alpha',task_id:'task_one',operation_id:'op_control_one'}).state,bundle:host.bundle},null,2)+'\n');
});
test('changed user text changes real computed local result',async t=>{const a=await completed(t,{text:'first input'}),b=await completed(t,{text:'second input'});assert.notEqual(a.host.bundle.evidence.execution.output.input_hash,b.host.bundle.evidence.execution.output.input_hash);assert.equal((await a.host.verify()).qa,'QA_PASS');assert.equal((await b.host.verify()).qa,'QA_PASS');});
test('forbidden tool stops the integrated path before model and child',async t=>{const f=await fixture(t,{toolDenied:true});assert.equal((await f.host.start()).reason,'TOOL_NOT_FOUND');assert.equal(f.b.controls.r1.calls().length,0);assert.equal(Object.keys(f.host.read().runtime).length,0);});
test('over-budget model has no invocation, tool result or QA',async t=>{const f=await fixture(t,{cap:'1'});const r=await f.host.start();assert.notEqual(r.status,'RUNNING');assert.equal(f.b.controls.r1.calls().length,0);assert.equal(f.host.bundle,null);assertCaps(f.b);});
test('provider timeout quarantines original liability without fallback/retry',async t=>{const f=await fixture(t,{providerFailure:true});assert.equal((await f.host.start()).status,'OUTCOME_UNKNOWN');assert.equal((await f.host.start()).reason,'INT04_START_REPLAY');assert.equal(f.b.controls.r1.calls().length,1);assert.equal(f.host.bundle,null);assertCaps(f.b);});
test('subagent failure never becomes work complete or QA',async t=>{const f=await fixture(t,{childFailure:true});await f.host.start();assert.equal((await f.host.finish()).status,'FAILED');assert.equal(f.host.bundle,null);assert.equal(f.host.read().qa,null);});
test('cancel cascades to RT child and D03; late work and QA denied',async t=>{const f=await fixture(t);await f.host.start();assert.equal((await f.host.cancel()).status,'CANCELLED');assert.equal(f.host.runtime.inspect('run_int04_child').status,'CANCELLED');assert.notEqual((await f.host.finish()).status,'WORK_COMPLETED');assert.equal((await f.host.verify()).decision,'DENY');});
test('authority mismatch is denied by actual SEC and RT',async t=>{const f=await fixture(t);f.host.testControl.revokeChild();const r=await f.host.start();assert.notEqual(r.status,'RUNNING');assert.equal(f.b.controls.r1.calls().length,0);});
test('revocation after launch blocks child work',async t=>{const f=await fixture(t);await f.host.start();f.host.testControl.revokeChild();assert.equal((await f.host.finish()).status,'OUTCOME_UNKNOWN');assert.equal(f.host.bundle,null);});
test('SEC revocation during model await hides output and retains D06 settlement',async t=>{
 const f=await fixture(t,{deferred:true}),pending=f.host.start();
 for(let i=0;i<100&&f.b.controls.r1.calls().length===0;i++)await new Promise(resolve=>setImmediate(resolve));
 assert.equal(f.b.controls.r1.calls().length,1);f.host.testControl.revokeChild();f.b.controls.r1.completeNext();
 const result=await pending;assert.equal(result.status,'DENY');assert.equal(result.output,null);assert.equal(result.costMicros,'8');
 assert.equal(Object.keys(f.host.read().runtime).length,0);assertCaps(f.b);
});
test('duplicate RT event is consumed once; durable inbox replay is stable and conflicting event denied',async t=>{const f=await completed(t,{duplicateEvent:true});assert.equal(Object.keys(f.host.read().attempts).length,1);assert.equal((await f.host.deliverEvent('evt_user',{task:'one'})).status,'RECORDED');assert.equal((await f.host.deliverEvent('evt_user',{task:'one'})).status,'REPLAY');await assert.rejects(()=>f.host.deliverEvent('evt_user',{task:'two'}));assert.equal((await f.host.verify()).qa,'QA_PASS');});
test('lost child handle remains unknown and cannot be accepted',async t=>{const f=await fixture(t);await f.host.start();f.host.testControl.loseChild();assert.equal((await f.host.finish()).status,'OUTCOME_UNKNOWN');assert.equal((await f.host.verify()).decision,'DENY');});
test('RT restart restores journal and quarantines unfinished runs',async t=>{const f=await fixture(t);await f.host.start();assert.equal((await f.host.restartRuntime()).status,'OUTCOME_UNKNOWN');assert.equal(f.host.runtime.inspect('run_int04_child').status,'OUTCOME_UNKNOWN');assert.equal((await f.host.finish()).status,'OUTCOME_UNKNOWN');assert.equal(f.b.controls.r1.calls().length,1);});
test('checkpoint restart restores existing D03 and D06 with recovery gates closed',async t=>{const f=await completed(t);const r=restoreCheckpoint(f.directory);assert.equal(r.resumable,false);assert.equal(r.ledger.inspect().recoveryRequired,true);assert.equal(r.storage.read(db=>db.projects.prj_alpha.tasks.task_one.restore_pending),true);assert.equal(r.checkpoint.bundle.reference.file_hash,f.host.bundle.reference.file_hash);assert.equal(r.ledger.operation('op-one').attempts.length,1);});
test('lost/corrupt checkpoint fails closed instead of making fresh state',async t=>{const f=await fixture(t);fs.renameSync(path.join(f.directory,'checkpoint.json'),path.join(f.directory,'checkpoint.saved'));assert.throws(()=>restoreCheckpoint(f.directory));fs.writeFileSync(path.join(f.directory,'checkpoint.json'),'{}');assert.throws(()=>restoreCheckpoint(f.directory));});
test('worker cannot self-QA, accept, dispatch or issue child',async t=>{const f=await completed(t),w=f.host.worker();assert.equal(w.submitQa().decision,'DENY');assert.equal(w.accept().decision,'DENY');assert.equal(w.executeTool().decision,'DENY');const qa=await f.host.verify();assert.equal((await f.host.accept(qa.proof,'child')).decision,'DENY');assert.equal(f.host.gate.requestPhysicalEffect().decision,'DENY');assert.equal(f.host.gateway.physicalDispatch().decision,'DENY');});
test('owner can reject a computed QA pass separately',async t=>{const f=await completed(t);const qa=await f.host.verify();assert.equal(qa.qa,'QA_PASS');assert.equal((await f.host.reject()).acceptance,'OWNER_REJECTED');assert.equal(f.host.read().qa.accepted,false);assert.equal((await f.host.accept(qa.proof)).decision,'DENY');});
test('tool without exact SEC registry authority denied before model',async t=>{const f=await fixture(t);f.host.request.tool_id='tool_forbidden';assert.equal((await f.host.start()).status,'DENIED');assert.equal(f.b.controls.r1.calls().length,0);});
test('changed persisted artifact bundle cannot be substituted into QA',async t=>{const f=await completed(t);await f.host.testControl.corruptBundle();assert.equal((await f.host.verify()).decision,'DENY');});
for(const [name,mutate] of [
 ['local result',o=>o.execution.output.text_bytes++],['model cost',o=>o.model.costMicros='0'],['tool binding',o=>o.discovery.proposal.plan_digest=digest({forged:true})],['child result',o=>o.runtime.child.status='FAILED'],['task',o=>o.task.text='replacement']
])test('D08 rejects correctly rehashed forged '+name,async t=>{const f=await completed(t),b=f.host.bundle,o=JSON.parse(Buffer.from(b.bytes_base64,'base64'));mutate(o);const bytes=Buffer.from(canonicalize(o));const result=evaluateExact({bytes,reference:{...b.reference,file_hash:digest(o),bytes:bytes.length},requirements:b.requirements,evidence:b.evidence,operations:b.operations,pin:b.pin});assert.equal(result.verdict,'QA_FAIL');});
