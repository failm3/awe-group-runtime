import test from 'node:test';
import assert from 'node:assert/strict';
import {createPhaseAccounting} from '../../host/coding/repair-driver.mjs';
import {validateRepairConfig} from '../../host/mission-runner.mjs';

// Explicit offline authority fixtures. No native DB, LLM or generation transport.
function fixture() {
  const calls = [], scope = {mission_id: 'mission_fixture', task_id: 'code_r02', worker_id: 'e1_worker', fence: 4, attempt_id: 'attempt_fixture', logical_request_id: 'logical_fixture'};
  let phase = 'CODE_PENDING', hold = false;
  const client = Object.fromEntries(['reserve', 'markSending', 'settle', 'unknown', 'failBeforeSend'].map(k => [k, async r => { calls.push({method: k, request: r}); return {status: k}; }]));
  const nativeScope = {...scope};
  const store = {read: async () => ({phase, counters: {hold, total: 2}, state: {refs: {...nativeScope, fence: '4'}}})};
  const port = createPhaseAccounting(client, {store, run_id: 'fixture', scope, kind: 'CODE'});
  return {port, scope, calls, setPhase: x => { phase = x; }, hold: () => { hold = true; }};
}
const reserve = scope => ({...scope, capability_id: 'e1.coding.patch', route_id: 'ollama.local.qwen3-4b-instruct', reserve_micros: 0, quota_units: 1});
test('real accounting port cannot be reached before native coding phase, with UNKNOWN or alternate request', async () => {
  for (const state of ['NEW', 'HEAD_PENDING', 'PLAN_READY', 'QA_PENDING', 'HOLD']) {
    const f = fixture(); f.setPhase(state); await assert.rejects(f.port.reserve(reserve(f.scope))); assert.equal(f.calls.length, 0);
  }
  const f = fixture(); f.hold(); await assert.rejects(f.port.markSending(f.scope)); assert.equal(f.calls.length, 0);
  const g = fixture(); await assert.rejects(g.port.reserve({...reserve(g.scope), attempt_id: 'wrong_attempt'})); assert.equal(g.calls.length, 0);
});
test('phase envelope snapshots scope and forbids cloud or extra quota without starting native attempt', async () => {
  const f = fixture(), original = {...f.scope}; f.scope.attempt_id = 'mutated_after_factory';
  await assert.rejects(f.port.reserve(reserve(f.scope))); assert.equal(f.calls.length, 0);
  await assert.rejects(f.port.reserve({...reserve(original), route_id: 'cloud.unproven'}));
  await assert.rejects(f.port.reserve({...reserve(original), quota_units: 2}));
  await f.port.reserve(reserve(original)); assert.equal(f.calls.length, 1);
});
test('uncertain sends can still settle or hold their original liability after phase stops', async () => {
  const f = fixture(); f.setPhase('HOLD');
  await f.port.unknown({...f.scope, reason: 'POSSIBLE_SEND'});
  await f.port.settle({...f.scope, actual_cost_micros: 0});
  await assert.rejects(async () => f.port.settle({...f.scope, mission_id: 'another_mission'}));
  assert.deepEqual(f.calls.map(c => c.method), ['unknown', 'settle']);
});
test('mutation while native phase read is pending cannot change the reserved request', async () => {
  const scope = {mission_id: 'mission_fixture', task_id: 'code_r02', worker_id: 'e1_worker', fence: 4, attempt_id: 'attempt_fixture', logical_request_id: 'logical_fixture'};
  let release, seen;
  const port = createPhaseAccounting({reserve: async r => { seen = r; }}, {run_id: 'fixture', scope, kind: 'CODE', store: {read: () => new Promise(resolve => { release = resolve; })}});
  const request = reserve(scope), pending = port.reserve(request); request.quota_units = 99; request.attempt_id = 'mutated';
  release({phase: 'CODE_PENDING', counters: {hold: false, total: 2}, state: {refs: {...scope}}}); await pending;
  assert.equal(seen.quota_units, 1); assert.equal(seen.attempt_id, scope.attempt_id);
});
test('authorized controller profile is explicitly two faults and two restarts, not open-ended', () => {
  const config = {schema: 'awe.e1.two-file-repair-config/1', run_id: 'fixture', resourcePath: 'C:/fixture/resource.json', issueSnapshotPath: 'C:/fixture/issue.json', priorReportPath: 'C:/fixture/prior.json', priorWitnessPath: 'C:/fixture/qa.json', max_restarts: 2, faults: ['AFTER_MODEL_PERSISTED', 'AFTER_NATIVE_COMPLETED']};
  assert.equal(validateRepairConfig(config), config);
  assert.throws(() => validateRepairConfig({...config, max_restarts: 3}));
  assert.throws(() => validateRepairConfig({...config, faults: ['BEFORE_SEND', 'ARBITRARY_SHELL']}));
});
