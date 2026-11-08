import test from 'node:test';
import assert from 'node:assert/strict';
import {world, request, approve, assertCaps, success, notSent, route} from './fixtures.mjs';

test('C01 32 simultaneous logical requests cannot overbook a cap of 40', async () => {
  const w = world({cap: '40', deferred: true, scripts: [Array.from({length: 32}, () => success())]});
  const requests = Array.from({length: 32}, (_, i) => request(String(i)));
  const grants = requests.map(r => approve(w, r));
  const pending = requests.map((r, i) => w.broker.execute(r, grants[i].approval.id));
  assert.equal(w.controls.r1.calls().length, 1); assert.equal(w.ledger.inspect().totals.global.reservedMicros, '40'); assertCaps(w);
  w.controls.r1.completeNext();
  const results = await Promise.all(pending);
  assert.equal(results.filter(r => r.status === 'SUCCEEDED').length, 1);
  assert.equal(results.filter(r => r.code === 'CAP_EXCEEDED').length, 31);
  assert.equal(w.ledger.inspect().totals.global.spentMicros, '8'); assertCaps(w);
});
test('C02 32 concurrent duplicates consume one approval and invoke one mock', async () => {
  const w = world({deferred: true}), r = request(), a = approve(w, r);
  const pending = Array.from({length: 32}, () => w.broker.execute(structuredClone(r), a.approval.id));
  assert.equal(w.controls.r1.calls().length, 1); assert.equal(w.ledger.inspect().approvals[a.approval.id].uses, 1);
  w.controls.r1.completeNext();
  const results = await Promise.all(pending); assert.equal(results.filter(r => r.status === 'IN_PROGRESS').length, 31);
  assert.equal(results.filter(r => r.status === 'SUCCEEDED').length, 1); assertCaps(w);
});
test('C03 deterministic completion permutations retain all in-flight liabilities', async () => {
  // Four independent mock tokens permit explicit completion order without clocks or network.
  for (const order of [[0, 1], [1, 0]]) {
    const w = world({cap: '80', routes: [route(), route('r2', 'direct')], deferred: true});
    const requests = [request('one'), request('two', {allowedRoutes: ['r2']})], grants = requests.map(r => approve(w, r));
    const pending = requests.map((r, i) => w.broker.execute(r, grants[i].approval.id));
    assert.equal(w.ledger.inspect().totals.global.reservedMicros, '80');
    for (const i of order) { w.controls[i === 0 ? 'r1' : 'r2'].completeNext(); await pending[i]; assertCaps(w); }
    assert.equal(w.ledger.inspect().totals.global.spentMicros, '16');
    assert.equal(w.ledger.inspect().totals.global.reservedMicros, '0');
  }
});
test('C04 deterministic mixed success/uncertainty/cancel schedules never overrun', async () => {
  let seed = 20261105;
  for (let i = 0; i < 24; i++) {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    const outcome = seed % 4;
    const w = world({cap: '40', deferred: true, scripts: [[outcome === 0 ? {status: 'TIMEOUT'} : outcome === 1 ? notSent('AUTH_ERROR') : success()]]});
    const r = request(), a = approve(w, r), pending = w.broker.execute(r, a.approval.id);
    assertCaps(w); if (outcome === 3) w.ledger.cancel(r.operationId); assertCaps(w);
    w.controls.r1.completeNext(); await pending; assertCaps(w);
    const calls = w.controls.r1.calls().length;
    await w.broker.execute(r, a.approval.id); assert.equal(w.controls.r1.calls().length, calls); assertCaps(w);
  }
});
test('C05 child scope cannot escape shared parent/global reservations', async () => {
  const base = world().baseScope;
  const w = world({cap: '40', deferred: true, scopes: [base, {...base, id: 'child-scope', taskId: 'child-task'}]});
  const r1 = request(), r2 = request('two', {scopeId: 'child-scope', taskId: 'child-task', kind: 'CHILD'});
  const a = approve(w, r1), b = approve(w, r2), pending = w.broker.execute(r1, a.approval.id);
  assert.equal((await w.broker.execute(r2, b.approval.id)).code, 'CAP_EXCEEDED');
  w.controls.r1.completeNext(); await pending; assertCaps(w);
});
test('C06 circuit breaker survives new logical IDs; reopening respects cooldown', async () => {
  const w = world({scripts: [[notSent(), success()]], retry: {owner: 'RouteBroker', baseDelay: 10, jitter: 3, breakerThreshold: 1, cooldown: 100}});
  const r = request(), a = approve(w, r), first = await w.broker.execute(r, a.approval.id);
  w.ledger.advanceClock(first.retryAt);
  assert.equal((await w.broker.execute(r, a.approval.id)).code, 'CIRCUIT_OPEN');
  w.ledger.advanceClock(1100); assert.equal((await w.broker.execute(r, a.approval.id)).status, 'SUCCEEDED');
  assert.equal(w.controls.r1.calls().length, 2); assertCaps(w);
});
test('C07 unsafe runtime/SDK retries and third attempt are rejected', () => {
  const w = world();
  for (const patch of [{sdkRetries: 1}, {runtimeRetries: 1}, {maxAttempts: 3}]) assert.equal(w.broker.prepare(request('one', patch)).decision, 'DENY');
  assert.equal(w.controls.r1.calls().length, 0);
});
test('C08 new child scope/operation cannot bypass quarantined origin', async () => {
  const base = world().baseScope;
  const w = world({scopes: [base, {...base, id: 'child-scope', taskId: 'child-task'}], scripts: [[{status: 'SPLIT_COMMIT'}]]});
  const r = request(), a = approve(w, r); await w.broker.execute(r, a.approval.id);
  const child = request('two', {scopeId: 'child-scope', taskId: 'child-task', kind: 'CHILD'}), b = approve(w, child);
  assert.equal((await w.broker.execute(child, b.approval.id)).code, 'SCOPE_QUARANTINED'); assert.equal(w.controls.r1.calls().length, 1); assertCaps(w);
});
