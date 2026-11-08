import test from 'node:test';
import assert from 'node:assert/strict';
import {localFixture,digest} from './fixtures.mjs';
import {executeReviewedStats} from '../../awe/execution_security/local-adapter.mjs';
test('fixed adapter component executes reviewed TOOLS02 source under RT02 Job limits (NOT SEC/D09 E2E)',async()=>{const f=localFixture();const out=await executeReviewedStats({request:f.r,current:()=>{}});assert.equal(out.output.utf8_bytes,Buffer.byteLength(f.r.payload.text));assert.equal(out.output_hash,digest(out.output));assert.ok(out.evidence.created_processes+1<=out.evidence.total_process_limit);assert.equal(out.evidence.job_active_process_limit,1);assert.equal(out.evidence.active_processes,0);assert.equal(out.physical_decision,'DENY');assert.equal(f.world.sent,0);});
test('fixed adapter cancellation after process creation never exposes a completed artifact',async()=>{const f=localFixture();let cancel=false;const pending=executeReviewedStats({request:f.r,current:()=>{if(cancel)throw Error('CANCELLED');}});setTimeout(()=>{cancel=true;},0);await assert.rejects(pending);assert.equal(f.world.sent,0);});
test('fixed adapter denies concurrent process creation',async()=>{const f=localFixture(),a=executeReviewedStats({request:f.r,current:()=>{}});await assert.rejects(()=>executeReviewedStats({request:f.r,current:()=>{}}),/LOCAL_PROCESS_LIMIT/);await a;});
