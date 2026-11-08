import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {digest} from '../../contracts/index.mjs';
import {createRecoverableModelPort, createRecoverableTestRunner, createStableInvocationIdFactory, createRecoverableCoordinatorBinding} from '../../host/coding/recovery.mjs';
import {scope, now, snapshot, modelArgs, confirmed, modelPort, testArgs, programRequest, programResult, completionArgs} from './fixtures.mjs';

function setup(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'awe-recovery-fixture-')), state = snapshot();
  // Cleanup uses only known individual flat files created inside this directory.
  t.after(() => { for (const name of fs.readdirSync(directory)) { const file = path.join(directory, name); assert.equal(fs.lstatSync(file).isFile(), true); fs.unlinkSync(file); } fs.rmdirSync(directory); });
  return {directory, state, project_id: 'fixture_project', readNativeState: async () => state, clock: () => now};
}
test('OFFLINE: actual child exit after fsync model cache; new process view reuses exact response with zero second wire', t => {
  const f = setup(t), stateFile = path.join(f.directory, 'state.json'), configFile = path.join(f.directory, 'child.json');
  fs.writeFileSync(stateFile, JSON.stringify(f.state)); fs.writeFileSync(configFile, JSON.stringify({directory: f.directory, state: stateFile}));
  const child = spawnSync(process.execPath, [fileURLToPath(new URL('./fixture-child.mjs', import.meta.url)), configFile], {encoding: 'utf8', windowsHide: true, timeout: 10000});
  assert.equal(child.status, 90, child.stderr);
  let wires = 0; f.readNativeState = async () => JSON.parse(fs.readFileSync(stateFile, 'utf8'));
  const wrapped = createRecoverableModelPort({...f, modelPort: modelPort(async () => { wires++; throw Error('SECOND_WIRE_FORBIDDEN'); })});
  return wrapped.proposePatch(modelArgs()).then(value => { assert.equal(wires, 0); assert.equal(value.native_receipt.response.evidence_level, 'LIVE_LOCAL_MODEL'); assert.equal(value.native_receipt.response.fixture, 'OFFLINE_TEST_DOUBLE'); });
});
test('OFFLINE: cache is invalid under changed issue/context or expired/native changed lease', async t => {
  const f = setup(t), wrapped = createRecoverableModelPort({...f, modelPort: modelPort(async () => confirmed(f.state))});
  await wrapped.proposePatch(modelArgs());
  await assert.rejects(wrapped.proposePatch({...modelArgs(), issue: {title: 'changed', body: 'changed'}}), /RECOVERY_MODEL_CONTEXT_CHANGED/);
  f.state.leases[0].expires_at = '2026-11-08T11:59:00.000Z';
  await assert.rejects(wrapped.proposePatch(modelArgs()), /RECOVERY_LEASE_EXPIRED_OR_CHANGED/);
});
test('OFFLINE: existing confirmed native row without private cache cannot send again', async t => {
  const f = setup(t); confirmed(f.state); let wires = 0;
  const wrapped = createRecoverableModelPort({...f, modelPort: modelPort(async () => { wires++; })});
  await assert.rejects(wrapped.proposePatch(modelArgs()), /RECOVERY_BLOCK_LOST_CONFIRMED_RESPONSE/); assert.equal(wires, 0);
});
test('OFFLINE: intent written before uncertain throw blocks subsequent broker call', async t => {
  const f = setup(t); let wires = 0;
  const wrapped = createRecoverableModelPort({...f, modelPort: modelPort(async () => { wires++; throw Error('LOST_ACK_FIXTURE'); })});
  await assert.rejects(wrapped.proposePatch(modelArgs()), /LOST_ACK_FIXTURE/);
  await assert.rejects(wrapped.proposePatch(modelArgs()), /RECOVERY_HOLD_MODEL_INTENT_UNCERTAIN_NO_RETRY/); assert.equal(wires, 1);
});
test('OFFLINE: UNKNOWN cached outcome remains held, never a successful proposal or resend', async t => {
  const f = setup(t); let wires = 0;
  const wrapped = createRecoverableModelPort({...f, modelPort: modelPort(async () => { wires++; const value = confirmed(f.state); f.state.attempts[0].state = 'OUTCOME_UNKNOWN'; return {...value, accounting_status: 'UNKNOWN', native_receipt: {...value.native_receipt, response: {...value.native_receipt.response, accounting_status: 'UNKNOWN'}}}; })});
  const first = await wrapped.proposePatch(modelArgs()); assert.equal(first.accounting_status, 'UNKNOWN');
  await assert.rejects(wrapped.proposePatch(modelArgs()), /RECOVERY_HOLD_MODEL_OUTCOME_UNKNOWN/); assert.equal(wires, 1);
});
test('OFFLINE: stable nonce survives new helper instance, changes only for new exact tree/cap binding', t => {
  const f = setup(t), binding = {grant: {grant_id: 'fixture'}, capability: testArgs().capability, readback: {head_sha: 'd'.repeat(40), tree_sha: 'e'.repeat(40)}};
  const one = createStableInvocationIdFactory({directory: f.directory, scope})(binding), two = createStableInvocationIdFactory({directory: f.directory, scope})(binding);
  assert.equal(one, two); assert.match(one, /^[a-f0-9]{32}$/);
  assert.notEqual(two, createStableInvocationIdFactory({directory: f.directory, scope})({...binding, readback: {...binding.readback, tree_sha: 'f'.repeat(40)}}));
});
test('OFFLINE: failed product test receipt cached exactly and no test rerun; changed input rejected', async t => {
  const f = setup(t); let runs = 0;
  const source = {kind: 'FIXED_SANDBOX_TEST_RUNNER', mode: 'LIVE_SCOPED_HOST', isolation: 'ALLOWLISTED_OS_SANDBOX', network: 'DENY', run: async () => { runs++; return programResult(programRequest()); }};
  const make = request => createRecoverableTestRunner({...f, scope, testRunner: source, resolveTestRequest: async () => request});
  const first = await make(programRequest()).run(testArgs()), second = await make(programRequest()).run(testArgs());
  assert.deepEqual(first, second); assert.equal(second.exit_code, 1); assert.equal(runs, 1);
  const changed = {...programRequest(), stdin: 'different'};
  // The same invocation cannot silently become a different input stream.
  await assert.rejects(make(changed).run(testArgs()), /RECOVERY_TEST_REQUEST_CHANGED/); assert.equal(runs, 1);
});
test('OFFLINE: test nonce/source and trusted boundary must match, even with recomputed self-hash', async t => {
  const f = setup(t), bad = programResult(programRequest()); bad.program_receipt.boundary.fork_denied = false;
  const {receipt_digest, ...rest} = bad.program_receipt; bad.program_receipt.receipt_digest = digest(rest);
  const wrapper = createRecoverableTestRunner({...f, scope, resolveTestRequest: async () => programRequest(), testRunner: {run: async () => bad}});
  await assert.rejects(wrapper.run(testArgs()), /PROGRAM_RECEIPT_BOUNDARY/);
});
test('OFFLINE: complete once, restore WAIT_QA/ACCEPTED/FAILED without stale-fence SQL and require real file readback', async t => {
  const f = setup(t), sourceFile = path.join(f.directory, 'source.py'), args = completionArgs(); fs.writeFileSync(sourceFile, args.artifact.patch.changes[0].after_text);
  let completes = 0;
  const client = {async complete(request) { completes++; f.state.tasks[0] = {...f.state.tasks[0], state: 'WAIT_QA', result: request.result, result_hash: request.result_hash}; f.state.leases = []; return {status: 'WAIT_QA'}; }};
  const config = {...f, client, scope, verifyArtifactReadback: async artifact => fs.readFileSync(sourceFile, 'utf8') === artifact.patch.changes[0].after_text};
  const binding = createRecoverableCoordinatorBinding(config); assert.equal(await binding.restore(), null);
  const value = await binding.complete(args); assert.equal(value.result.evidence.product_status, 'PRODUCER_TEST_FAILED'); assert.equal(completes, 1);
  const restored = await createRecoverableCoordinatorBinding(config).restore(); assert.equal(restored.value.status, 'WAIT_QA'); assert.equal(restored.result_hash, value.result_hash);
  f.state.tasks[0].state = 'ACCEPTED'; f.state.missions[0].state = 'COMPLETE';
  assert.equal((await createRecoverableCoordinatorBinding(config).complete(args)).value.status, 'ACCEPTED'); assert.equal(completes, 1);
  f.state.tasks[0].state = 'FAILED'; assert.equal((await createRecoverableCoordinatorBinding(config).restore()).value.status, 'FAILED');
  fs.writeFileSync(sourceFile, 'mutated'); await assert.rejects(createRecoverableCoordinatorBinding(config).restore(), /RECOVERY_ARTIFACT_READBACK/);
});
test('OFFLINE: SQL committed then lost ACK restores exact native result from durable pre-complete intent', async t => {
  const f = setup(t), args = completionArgs(); let completes = 0;
  const client = {async complete(request) { completes++; f.state.tasks[0] = {...f.state.tasks[0], state: 'WAIT_QA', result: request.result, result_hash: request.result_hash}; f.state.leases = []; throw Error('ACK_LOST_FIXTURE'); }};
  const config = {...f, client, scope, verifyArtifactReadback: async () => true};
  await assert.rejects(createRecoverableCoordinatorBinding(config).complete(args), /ACK_LOST_FIXTURE/);
  assert.equal((await createRecoverableCoordinatorBinding(config).restore()).value.status, 'WAIT_QA'); assert.equal(completes, 1);
  f.state.tasks[0].result_hash = 'sha256:' + '0'.repeat(64);
  await assert.rejects(createRecoverableCoordinatorBinding(config).restore(), /RECOVERY_NATIVE_RESULT_CONFLICT/);
});
test('OFFLINE: once native completion was observed, regressed DB state cannot cause a second complete', async t => {
  const f = setup(t), args = completionArgs(); let completes = 0;
  const running = structuredClone(f.state);
  const client = {async complete(request) { completes++; f.state.tasks[0] = {...f.state.tasks[0], state: 'WAIT_QA', result: request.result, result_hash: request.result_hash}; f.state.leases = []; return {status: 'WAIT_QA'}; }};
  const config = {...f, client, scope, verifyArtifactReadback: async () => true};
  await createRecoverableCoordinatorBinding(config).complete(args);
  f.state.tasks = running.tasks; f.state.leases = running.leases;
  await assert.rejects(createRecoverableCoordinatorBinding(config).restore(), /RECOVERY_NATIVE_COMPLETION_REGRESSED/);
  await assert.rejects(createRecoverableCoordinatorBinding(config).complete(args), /RECOVERY_NATIVE_COMPLETION_REGRESSED/); assert.equal(completes, 1);
});
