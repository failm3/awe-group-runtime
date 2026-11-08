import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture} from './fixtures.mjs';
import {createSyntheticProcessTransport} from '../../awe/hermes_runtime/process-transport.mjs';
test('isolated fixed Node fixture produces synthetic artifact; Hermes is not launched',async t=>{
 const transport=createSyntheticProcessTransport();t.after(()=>transport.close());const f=await fixture(t,{process:transport,timeoutMs:1000});
 assert.equal((await f.launch()).status,'RUNNING');const r=await f.host.join('run_parent');assert.equal(r.status,'WORK_COMPLETED');assert.equal(r.mode,'RT01_SYNTHETIC_ONLY');assert.equal(r.physical_decision,'DENY');assert.equal(r.qa,'QA_NOT_RUN');
});
test('terminated synthetic Node process becomes unknown and cannot be relaunched',async t=>{
 const transport=createSyntheticProcessTransport();t.after(()=>transport.close());const f=await fixture(t,{process:transport,timeoutMs:1000});await f.launch();await transport.close();
 assert.equal((await f.host.reconcile('run_parent')).status,'OUTCOME_UNKNOWN');assert.equal((await f.launch()).status,'OUTCOME_UNKNOWN');assert.equal(f.counts.begin,1);
});
