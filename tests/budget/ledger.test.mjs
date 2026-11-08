import test from 'node:test';
import assert from 'node:assert/strict';
import {world, request, approve, assertCaps, success, notSent, route, price} from './fixtures.mjs';

test('L01 reserve all attempts once; settle releases unused envelopes', async () => {
  const w = world({deferred: true}), r = request(), a = approve(w, r);
  const pending = w.broker.execute(r, a.approval.id);
  assert.equal(w.ledger.inspect().totals.global.reservedMicros, '40');
  assert.equal(w.ledger.inspect().approvals[a.approval.id].uses, 1);
  assert.equal((await w.broker.execute(r, a.approval.id)).status, 'IN_PROGRESS');
  assert.equal(w.controls.r1.calls().length, 1); assertCaps(w);
  w.controls.r1.completeNext(); assert.equal((await pending).status, 'SUCCEEDED');
  const totals = w.ledger.inspect().totals;
  for (const id of ['global', 'project', 'parent', 'task', 'day', 'month', 'agent', 'model', 'account1']) {
    assert.equal(totals[id].spentMicros, '8'); assert.equal(totals[id].reservedMicros, '0'); assert.equal(totals[id].uncertainMicros, '0');
  }
  assert.equal(totals.account2.spentMicros, '0'); assertCaps(w);
});
test('L02 duplicate settlement is idempotent, conflicting receipt rejected', async () => {
  const w = world(), r = request(), a = approve(w, r); await w.broker.execute(r, a.approval.id);
  const attempt = w.ledger.operation(r.operationId).attempts[0];
  assert.deepEqual(attempt.usage, success().usage); assert.equal(attempt.costSource, 'PINNED_SYNTHETIC_USAGE');
  assert(w.ledger.settle(r.operationId, attempt.id, '8', attempt.providerRequestId).replay);
  assert.throws(() => w.ledger.settle(r.operationId, attempt.id, '9', attempt.providerRequestId), /RECEIPT_CONFLICT/);
  assert.equal(w.ledger.inspect().totals.global.spentMicros, '8'); assertCaps(w);
});
test('L03 duplicate completed request never re-invokes provider', async () => {
  const w = world(), r = request(), a = approve(w, r);
  assert.equal((await w.broker.execute(r, a.approval.id)).status, 'SUCCEEDED');
  const replay = await w.broker.execute(r, a.approval.id); assert(replay.replay); assert.equal(replay.status, 'SUCCEEDED');
  assert.equal(w.controls.r1.calls().length, 1); assert.equal(w.ledger.inspect().approvals[a.approval.id].uses, 1);
});
for (const dimension of ['global', 'project', 'parent', 'task', 'day', 'month', 'agent', 'model', 'account1']) test('L04 atomic cap dimension ' + dimension, async () => {
  const w = world({budgetPatches: {[dimension]: {capMicros: '39'}}}), r = request(), a = approve(w, r);
  const result = await w.broker.execute(r, a.approval.id); assert.equal(result.code, 'CAP_EXCEEDED');
  assert.equal(w.controls.r1.calls().length, 0); assert.equal(w.ledger.inspect().approvals[a.approval.id].uses, 0);
  assert.equal(Object.keys(w.ledger.inspect().operations).length, 0); assertCaps(w);
});
test('L05 existing committed infra/fees share global cap', async () => {
  const w = world({cap: '50', budgetPatches: {global: {committedMicros: '11'}}}), r = request(), a = approve(w, r);
  assert.equal((await w.broker.execute(r, a.approval.id)).code, 'CAP_EXCEEDED'); assert.equal(w.ledger.inspect().totals.global.exposureMicros, '11');
});
for (const balance of ['-1', '0', '39']) test('L06 non-positive/insufficient balance ' + balance, async () => {
  const w = world({budgetPatches: {account1: {balanceMicros: balance}}}), r = request(), a = approve(w, r);
  assert.equal((await w.broker.execute(r, a.approval.id)).code, 'INSUFFICIENT_BALANCE'); assert.equal(w.controls.r1.calls().length, 0); assertCaps(w);
});
test('L07 changed balance is rechecked at final dispatch barrier', async () => {
  const w = world(), r = request(), a = approve(w, r);
  w.ledger.admit(a.prepared.plan, a.approval.id); w.ledger.updateBalance('account1', '-5');
  assert.equal((await w.broker.execute(r, a.approval.id)).code, 'BALANCE_CHANGED');
  assert.equal(w.ledger.inspect().totals.account1.reservedMicros, '40'); assert(w.ledger.inspect().totals.account1.balanceAtRisk);
  assert.equal(w.controls.r1.calls().length, 0); w.ledger.cancel(r.operationId); assertCaps(w);
});
test('L08 stale policy denies before admission without consumption', async () => {
  const w = world(), r = request(), a = approve(w, r); w.ledger.changeAuthority({policyVersion: 'synthetic-v2', epoch: 2});
  assert.equal((await w.broker.execute(r, a.approval.id)).code, 'POLICY_STALE');
  assert.equal(w.ledger.inspect().approvals[a.approval.id].uses, 0); assert.equal(w.controls.r1.calls().length, 0);
});
test('L09 stale approval and expired deadline deny', async () => {
  const w = world(), r = request(), a = approve(w, r, {expiresAt: 1001}); w.ledger.advanceClock(1001);
  assert.equal((await w.broker.execute(r, a.approval.id)).code, 'APPROVAL_STALE');
  const w2 = world(), r2 = request('one', {deadline: 1000}), a2 = approve(w2, r2);
  assert.equal((await w2.broker.execute(r2, a2.approval.id)).code, 'DEADLINE_EXPIRED');
});
test('L10 approval payload/route binding and finite cost ceiling', async () => {
  const w = world(), r = request(), a = approve(w, r);
  assert.equal((await w.broker.execute({...r, payload: {prompt: 'changed fixture'}}, a.approval.id)).code, 'APPROVAL_BINDING');
  const w2 = world(), b = approve(w2, r, {maxMicros: '39'});
  assert.equal((await w2.broker.execute(r, b.approval.id)).code, 'APPROVAL_COST_BOUND');
  assert.equal(w.controls.r1.calls().length + w2.controls.r1.calls().length, 0);
});
test('L11 immutable approval and monotonic policy epoch', () => {
  const w = world(), a = approve(w); assert.throws(() => w.ledger.approve(a.approval), /APPROVAL_IMMUTABLE/);
  assert.throws(() => w.ledger.changeAuthority({policyVersion: 'other', epoch: 1}), /EPOCH_NOT_MONOTONIC/);
});
test('L12 revoked pending approval cannot dispatch', async () => {
  const w = world(), r = request(), a = approve(w, r); w.ledger.revoke(a.approval.id);
  assert.equal((await w.broker.execute(r, a.approval.id)).code, 'APPROVAL_STALE'); assert.equal(w.controls.r1.calls().length, 0);
});
test('L13 cancel before dispatch releases reserve but never rearms same intent', async () => {
  const w = world(), r = request(), a = approve(w, r); w.ledger.admit(a.prepared.plan, a.approval.id); w.ledger.cancel(r.operationId);
  assert.equal(w.ledger.inspect().totals.global.exposureMicros, '0');
  assert.equal((await w.broker.execute(r, a.approval.id)).status, 'CANCELLED');
  const changed = {...r, operationId: 'op-other', logicalRequestId: 'logical-other', correlationId: 'corr-other'}, b = approve(w, changed);
  assert.equal((await w.broker.execute(changed, b.approval.id)).code, 'INTENT_ID_REUSE_BLOCKED'); assert.equal(w.controls.r1.calls().length, 0);
});
test('L14 logical and correlation IDs cannot be rebound to another intent', async () => {
  const w = world(), r = request(), a = approve(w, r); await w.broker.execute(r, a.approval.id);
  for (const field of ['logicalRequestId', 'correlationId']) {
    const other = request('two', {[field]: r[field]}), b = approve(w, other, {id: 'approval-two-' + field});
    assert.equal((await w.broker.execute(other, b.approval.id)).code, 'ID_ALREADY_BOUND');
  }
  assert.equal(w.controls.r1.calls().length, 1);
});
test('L15 retry exhaustion cannot multiply logical calls', async () => {
  const w = world({scripts: [[notSent(), notSent(), success()]]}), r = request(), a = approve(w, r);
  const first = await w.broker.execute(r, a.approval.id); w.ledger.advanceClock(first.retryAt);
  assert.equal((await w.broker.execute(r, a.approval.id)).status, 'FAILED');
  assert.equal((await w.broker.execute(r, a.approval.id)).status, 'FAILED'); assert.equal(w.controls.r1.calls().length, 2); assertCaps(w);
});
test('L16 ancestor physical attempt slots are reserved across parallel logical requests', async () => {
  const w = world({deferred: true, budgetPatches: {parent: {attemptLimit: 3}}}), r = request(), r2 = request('two');
  const a = approve(w, r), b = approve(w, r2), first = w.broker.execute(r, a.approval.id);
  assert.equal((await w.broker.execute(r2, b.approval.id)).code, 'ANCESTOR_ATTEMPT_LIMIT');
  w.controls.r1.completeNext(); await first; assert.equal(w.ledger.inspect().totals.parent.attempts, 1); assertCaps(w);
});
for (const kind of ['CHILD', 'QA', 'COMPACTION', 'REPAIR', 'FALLBACK']) test('L17 shared origin ledger counts ' + kind, async () => {
  const w = world({cap: '40', deferred: true}), r = request('one', {kind}), a = approve(w, r), r2 = request('two'), b = approve(w, r2);
  const pending = w.broker.execute(r, a.approval.id);
  assert.equal((await w.broker.execute(r2, b.approval.id)).code, 'CAP_EXCEEDED');
  w.controls.r1.completeNext(); await pending; assert.equal(w.ledger.inspect().totals.parent.spentMicros, '8'); assertCaps(w);
});
test('L18 final quote expiry prevents dispatch; new tariff changes approval hash', async () => {
  const w = world(), r = request('one', {deadline: 8500}), a = approve(w, r, {expiresAt: 8500});
  w.ledger.admit(a.prepared.plan, a.approval.id); w.ledger.advanceClock(8000);
  assert.throws(() => w.ledger.begin(r.operationId, 'r1'), /QUOTE_STALE/); assert.equal(w.controls.r1.calls().length, 0);
  const newer = world({routes: [route('r1', 'router.cheap', {price: price({rates: {...price().rates, output: '3000000'}})})]});
  newer.ledger.approve(a.approval);
  assert.equal((await newer.broker.execute(r, a.approval.id)).code, 'APPROVAL_BINDING');
});
