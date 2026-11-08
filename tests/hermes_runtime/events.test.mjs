import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture} from './fixtures.mjs';
import {digest} from '../../awe/hermes_runtime/protocol.mjs';
const unknown=r=>assert.equal(r.status,'OUTCOME_UNKNOWN',JSON.stringify(r));
for(const field of ['project_id','task_id','actor_id','run_id','child_id'])test('callback '+field+' spoof quarantined',async t=>{
 const f=await fixture(t);await f.launch();f.emit('HEARTBEAT',{},'run_parent',{[field]:'foreign_id'});unknown(await f.host.streamEvents('run_parent'));assert.equal(f.counts.result,0);
});
test('model swap vs pinned revision quarantined',async t=>{const f=await fixture(t);await f.launch();f.emit('HEARTBEAT',{},'run_parent',{model:{...f.request().model,revision:'rev_two'}});unknown(await f.host.streamEvents('run_parent'));});
test('exact duplicate event ignored without second result or effect',async t=>{
 const f=await fixture(t);await f.launch();const e=f.emit('HEARTBEAT',{});f.synthetic.control.append(f.synthetic.control.handle('run_parent'),JSON.stringify(e));
 const r=await f.host.streamEvents('run_parent');assert.equal(r.cursor,1);assert.equal(r.status,'RUNNING');assert.equal(f.counts.result,0);
});
test('conflicting repeated sequence quarantines',async t=>{
 const f=await fixture(t);await f.launch();const e=f.emit('HEARTBEAT',{});f.synthetic.control.append(f.synthetic.control.handle('run_parent'),JSON.stringify({...e,kind:'ERROR',payload:{code:'bad'}}));unknown(await f.host.streamEvents('run_parent'));
});
test('event gap quarantines',async t=>{const f=await fixture(t);await f.launch();f.emit('HEARTBEAT',{},'run_parent',{seq:2});unknown(await f.host.streamEvents('run_parent'));});
test('duplicate event ID at new sequence quarantines',async t=>{const f=await fixture(t);await f.launch();const e=f.emit('HEARTBEAT',{});f.emit('HEARTBEAT',{},'run_parent',{event_id:e.event_id});unknown(await f.host.streamEvents('run_parent'));});
test('tool proposal is recorded only; retry of the operation is denied',async t=>{
 const f=await fixture(t);await f.launch();const payload={operation_id:'op_tool',tool_id:f.tool.id,tool_digest:f.tool.digest,input_hash:digest({input:1})};
 f.emit('TOOL_PROPOSAL',payload);assert.equal((await f.host.streamEvents('run_parent')).cursor,1);
 f.emit('TOOL_PROPOSAL',payload);unknown(await f.host.streamEvents('run_parent'));assert.equal(f.synthetic.control.inspect().physical_dispatches,0);
});
test('ungranted tool proposal denied',async t=>{const f=await fixture(t);await f.launch();f.emit('TOOL_PROPOSAL',{operation_id:'op_tool',tool_id:'tool_other',tool_digest:f.tool.digest,input_hash:digest({})});unknown(await f.host.streamEvents('run_parent'));});
test('result before child join is quarantined',async t=>{const f=await fixture(t);await f.launch();await f.launch(f.child());f.emit();unknown(await f.host.join('run_parent'));});
test('producer cannot forge QA or acceptance through result payload',async t=>{const f=await fixture(t);await f.launch();f.emit('RESULT',{artifact_ref:digest({}),artifact_hash:digest({}),qa:'QA_PASS'});unknown(await f.host.join('run_parent'));});
test('failed D07 readback blocks work completion',async t=>{const f=await fixture(t);f.args.artifacts.verify=()=>false;await f.launch();f.emit();unknown(await f.host.join('run_parent'));assert.equal(f.counts.result,0);});
test('producer error becomes FAILED, never QA PASS',async t=>{const f=await fixture(t);await f.launch();f.emit('ERROR',{code:'synthetic_failure'});const r=await f.host.join('run_parent');assert.equal(r.status,'FAILED');assert.equal(r.qa,'QA_NOT_RUN');});
test('unrequested terminal cancellation cannot assert termination',async t=>{const f=await fixture(t);await f.launch();f.emit('CANCELLED',{});unknown(await f.host.streamEvents('run_parent'));});
test('late successful result in cancellation queue cannot turn cancel into success',async t=>{const f=await fixture(t);await f.launch();f.emit();unknown(await f.host.cancel('run_parent'));});
test('orphaned transport handle detected without relaunch',async t=>{const f=await fixture(t);await f.launch();f.synthetic.control.lose(f.synthetic.control.handle('run_parent'));unknown(await f.host.reconcile('run_parent'));assert.equal(f.counts.begin,1);});
test('unknown remains sticky even after late result is available',async t=>{const f=await fixture(t);await f.launch();await f.host.join('run_parent');f.emit();unknown(await f.host.streamEvents('run_parent'));unknown(await f.host.reconcile('run_parent'));});
for(const [name,text]of Object.entries({oversized:' '.repeat(65537),duplicate:'{"version":"rt01/1","version":"rt01/1"}',prototype:'{"__proto__":{}}',malformed:'{',unknown_kind:'{"kind":"QA_PASS"}'}))test('restricted event JSON '+name+' denied',async t=>{
 const f=await fixture(t);await f.launch();f.synthetic.control.append(f.synthetic.control.handle('run_parent'),text);unknown(await f.host.streamEvents('run_parent'));
});
test('oversized event batch rejected before consumption',async t=>{const f=await fixture(t);await f.launch();for(let i=0;i<65;i++)f.emit('HEARTBEAT',{});unknown(await f.host.streamEvents('run_parent'));});
