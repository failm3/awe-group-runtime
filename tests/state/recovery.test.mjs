import test from 'node:test';
import assert from 'node:assert/strict';
import {MemoryStorage} from '../../awe/state/memory-storage.mjs';
import {digest} from '../../contracts/canonical.mjs';
import {harness, scope, dto} from './harness.mjs';

const rejects = (operation, code) => assert.rejects(operation, error => error.code === code || error.details?.includes(code));

test('M15 crash before INTENT commit leaves no operation/dispatch', async () => {
  let crash = false;
  const storage = new MemoryStorage({fault: phase => {if (crash && phase === 'before_commit') {crash = false; throw new Error('CRASH');}}});
  const h = harness({storage}); await h.running();
  crash = true; await assert.rejects(h.intent(), /CRASH/);
  assert.deepEqual(JSON.parse(storage.snapshot()).data.projects.prj_alpha.operations, {});
});

test('M15 crash after INTENT ACK loss recovers unknown, same ID/payload retained without retry', async () => {
  let crash = false;
  const storage = new MemoryStorage({fault: phase => {if (crash && phase === 'after_commit') {crash = false; throw new Error('ACK_LOST');}}});
  const h = harness({storage}); await h.running(); crash = true;
  await assert.rejects(h.intent(), /ACK_LOST/);
  const before = Object.values(JSON.parse(storage.snapshot()).data.projects.prj_alpha.operations)[0];
  h.tick(10001); await h.service.recover(h.state, 'prj_alpha');
  const recovered = h.service.getOperation(h.owner, before.scope);
  assert.equal(recovered.status, 'OUTCOME_UNKNOWN'); assert.equal(recovered.attempts, 0);
  assert.equal(recovered.retained_reservation, true);
  assert.equal(recovered.binding.payload_hash, before.binding.payload_hash);
  await h.lease(); await rejects(h.dispatch(before.scope), 'EFFECT_STATE_DENIED');
});

for (const crashPoint of ['after_dispatch_before_effect', 'after_effect_before_ack'])
  test(`M15 ${crashPoint} restart snapshot fences stale worker and reconciles canary without duplicate`, async () => {
    const h = harness(); await h.running(); const intent = await h.intent(); const stale = h.transitionDto('QA_PENDING');
    const dispatch = await h.dispatch(intent.scope);
    const world = new Map();
    if (crashPoint === 'after_effect_before_ack') world.set(dispatch.operation_id, dispatch.payload_hash);
    const saved = h.storage.snapshot();
    const restarted = harness({storage: new MemoryStorage({snapshot: saved})}); restarted.tick(10001);
    await restarted.service.recover(restarted.state, 'prj_alpha');
    const recovered = restarted.service.getTask(restarted.owner, scope());
    assert.equal(recovered.state, 'RECONCILING'); assert(recovered.fence > stale.fence);
    await rejects(restarted.service.transition(restarted.supervisor, stale), 'USE_RESUME_COMMAND');
    await restarted.lease();
    const op = await restarted.reconcile(intent.scope, world.has(dispatch.operation_id) ? 'APPLIED' : 'NOT_APPLIED');
    assert.equal(op.retry_authorized, false); // NON_IDEMPOTENT remains blocked even NOT_APPLIED
    let task = restarted.service.getTask(restarted.supervisor, scope());
    await restarted.service.resume(restarted.supervisor, scope(), task.revision, task.lease);
    await rejects(restarted.dispatch(intent.scope), 'RECONCILIATION_REQUIRED');
    assert.equal(world.size, crashPoint === 'after_effect_before_ack' ? 1 : 0);
  });

test('M15 confirmed receipt ACK loss dedups on retry and cannot dispatch again', async () => {
  let crash = false;
  const storage = new MemoryStorage({fault: phase => {if (crash && phase === 'after_commit') {crash = false; throw new Error('ACK_LOST');}}});
  const h = harness({storage}); await h.running(); const intent = await h.intent(); await h.dispatch(intent.scope);
  const receipt = h.receipt(intent.scope); crash = true;
  await assert.rejects(h.service.recordToolReceipt(h.state, receipt), /ACK_LOST/);
  const result = await h.service.recordToolReceipt(h.state, receipt);
  assert.equal(result.status, 'CONFIRMED'); assert.equal(result.attempts, 1);
  await rejects(h.dispatch(intent.scope), 'RECONCILIATION_REQUIRED');
});

for (const outcome of ['OUTCOME_UNKNOWN', 'ABORTED']) test(`M15 tool ${outcome} retains reservation and requires verified reconciliation`, async () => {
  const h = harness(); await h.running(); const intent = await h.intent(); await h.dispatch(intent.scope);
  const op = await h.service.recordToolReceipt(h.state, h.receipt(intent.scope, outcome));
  assert.equal(op.status, 'OUTCOME_UNKNOWN'); assert.equal(op.retained_reservation, true);
  const task = h.service.getTask(h.state, scope());
  await rejects(h.service.reconcile(h.state, intent.scope, task.revision, {outcome: 'APPLIED', receipt: digest({forged: true})}), 'RECONCILIATION_UNVERIFIED');
  await rejects(h.dispatch(intent.scope), 'EFFECT_STATE_DENIED');
  await rejects(h.service.resume(h.supervisor, scope(), task.revision, task.lease), 'RECONCILIATION_REQUIRED');
});

test('M15 bounded idempotent canary retry requires NOT_APPLIED, same operation ID/payload and no cap reset', async () => {
  const h = harness(); await h.running(); const intent = await h.intent(scope(), 'IDEMPOTENT_WRITE');
  for (let attempt = 1; attempt <= 2; attempt++) {
    const dispatch = await h.dispatch(intent.scope);
    assert.equal(dispatch.operation_id, intent.scope.operation_id); assert.equal(dispatch.payload_hash, intent.op.binding.payload_hash);
    await h.service.recordToolReceipt(h.state, h.receipt(intent.scope, 'OUTCOME_UNKNOWN'));
    const result = await h.reconcile(intent.scope, 'NOT_APPLIED'); assert.equal(result.retry_authorized, attempt < 2);
    const task = h.service.getTask(h.supervisor, scope());
    await h.service.resume(h.supervisor, scope(), task.revision, task.lease);
  }
  await rejects(h.dispatch(intent.scope), 'RECONCILIATION_REQUIRED');
  assert.equal(h.service.getOperation(h.owner, intent.scope).attempts, 2);
});

test('M15 retry/rework counters survive explicit snapshot restore', async () => {
  const h = harness(); await h.running(); await h.go('QA_PENDING'); await h.go('REWORK'); await h.go('READY'); await h.go('RUNNING');
  const intent = await h.intent(scope(), 'IDEMPOTENT_WRITE'); await h.dispatch(intent.scope);
  await h.service.recordToolReceipt(h.state, h.receipt(intent.scope, 'OUTCOME_UNKNOWN'));
  const restored = harness({storage: new MemoryStorage({snapshot: h.storage.snapshot()})});
  assert.equal(restored.service.getTask(restored.owner, scope()).rework_count, 1);
  assert.equal(restored.service.getOperation(restored.owner, intent.scope).attempts, 1);
  await restored.service.recover(restored.state, 'prj_alpha'); await restored.lease();
  await restored.reconcile(intent.scope, 'NOT_APPLIED');
  let task = restored.service.getTask(restored.supervisor, scope());
  await restored.service.resume(restored.supervisor, scope(), task.revision, task.lease);
  assert.equal((await restored.dispatch(intent.scope)).attempts, 2);
  await restored.service.recordToolReceipt(restored.state, restored.receipt(intent.scope, 'OUTCOME_UNKNOWN'));
  assert.equal((await restored.reconcile(intent.scope, 'NOT_APPLIED')).retry_authorized, false);
});

test('M15 restored unexpired lease cannot dispatch or be reacquired before explicit recovery', async () => {
  const h = harness(); await h.running(); const intent = await h.intent();
  const restored = harness({storage: new MemoryStorage({snapshot: h.storage.snapshot()})});
  await rejects(restored.dispatch(intent.scope), 'RESTORE_RECOVERY_REQUIRED');
  await rejects(restored.lease(), 'RESTORE_RECOVERY_REQUIRED');
  await restored.service.recover(restored.state, 'prj_alpha');
  const task = await restored.lease();
  assert(task.fence > h.service.getTask(h.owner, scope()).fence);
  assert.equal(restored.service.getOperation(restored.owner, intent.scope).status, 'OUTCOME_UNKNOWN');
});

test('M15 changed operation ID cannot bypass logical operation dedup or unresolved status', async () => {
  const h = harness(); await h.running(); const intent = await h.intent();
  const changed = {...intent.input, scope: {...intent.scope, operation_id: 'op_new_bypass'}};
  let task = h.service.getTask(h.supervisor, scope());
  await rejects(h.service.intent(h.supervisor, changed, task.revision, task.lease, 'new-key'), 'LOGICAL_OPERATION_EXISTS');
  await h.dispatch(intent.scope); await h.service.recordToolReceipt(h.state, h.receipt(intent.scope));
  task = h.service.getTask(h.supervisor, scope());
  await rejects(h.service.intent(h.supervisor, changed, task.revision, task.lease, 'new-key'), 'LOGICAL_OPERATION_EXISTS');
});

test('M15 cancel during dispatched effect waits for reconciliation; late receipt never resumes', async () => {
  const h = harness(); await h.running(); const intent = await h.intent(); await h.dispatch(intent.scope);
  let task = h.service.getTask(h.owner, scope()); await h.service.cancel(h.owner, scope(), task.revision, 'cancel');
  task = await h.lease();
  await rejects(h.service.finishCancel(h.supervisor, scope(), task.revision, task.lease), 'GUARD_EVIDENCE_MISSING');
  await h.service.recordToolReceipt(h.state, h.receipt(intent.scope, 'OUTCOME_UNKNOWN'));
  assert.equal(h.service.getTask(h.owner, scope()).state, 'CANCELLING');
  const op = await h.reconcile(intent.scope, 'APPLIED'); assert.equal(op.retry_authorized, false);
  task = h.service.getTask(h.supervisor, scope());
  await h.service.finishCancel(h.supervisor, scope(), task.revision, task.lease);
  assert.equal(h.service.getTask(h.owner, scope()).state, 'CANCELLED');
});

test('M15 provider unknown outcome keeps exact integer reservation and blocks retry', async () => {
  const h = harness(); await h.running(); const intent = await h.intent(); await h.dispatch(intent.scope);
  const broker = h.service.session('act_broker'), task = h.service.getTask(h.owner, scope()), p = h.service.getProject(h.owner, 'prj_alpha');
  const price = {schema_version: '1.0.0', contract: 'provider-price', price_profile_id: 'price_canary', status: 'QUOTED', seller: 'seller_canary',
    model: 'model_canary', currency: 'USD', input_micros_per_million: '100', output_micros_per_million: '200',
    quote_ref: digest({canary_quote: true}), checked_at: h.now(), expires_at: '2026-11-05T13:00:00.000Z', reason: null};
  const receipt = dto('attempt-receipt', broker, intent.scope, task.spec, p.epochs, task.revision, h.now(), {
    attempt_id: 'att_canary', logical_request_id: 'llm_canary', attempt_number: 1, kind: 'MAIN',
    payload_hash: intent.op.binding.payload_hash, reservation_micros: '999999999999999999999', settled_micros: null,
    uncertain: true, status: 'OUTCOME_UNKNOWN', price, usage_tokens: null
  });
  const op = await h.service.recordAttemptReceipt(broker, receipt);
  assert.equal(op.status, 'OUTCOME_UNKNOWN'); assert.equal(op.reservation_micros, receipt.reservation_micros);
  await rejects(h.dispatch(intent.scope), 'EFFECT_STATE_DENIED');
});

test('E0 effect gateway denies by default and ignores mock ALLOW; no executor entry point', async () => {
  for (const pep of [undefined, () => ({decision: 'ALLOW'})]) {
    const observed = [];
    const h = harness({serviceOptions: {pep: boundary => {observed.push(boundary); return pep?.(boundary) ?? {decision: 'DENY'};}}});
    await h.running(); const intent = await h.intent(); const task = h.service.getTask(h.supervisor, scope());
    const before = h.storage.snapshot();
    const result = h.service.requestEffect(h.supervisor, intent.scope, task.lease);
    assert.equal(result.decision, 'DENY'); assert.equal(result.boundary.payload_hash, intent.op.binding.payload_hash);
    assert.equal(observed.length, 1); assert.equal(h.storage.snapshot(), before);
    assert.equal(h.service.getOperation(h.owner, intent.scope).attempts, 0);
  }
});

test('M15 repeated recovery is stable after lost lease and never dispatches', async () => {
  const h = harness(); await h.running(); const intent = await h.intent(); await h.dispatch(intent.scope); h.tick(10001);
  const first = await h.service.recover(h.state, 'prj_alpha'), task = h.service.getTask(h.owner, scope());
  assert.equal(first.recovered.length, 1);
  const second = await h.service.recover(h.state, 'prj_alpha');
  assert.deepEqual(second.recovered, []); assert.deepEqual(h.service.getTask(h.owner, scope()), task);
  assert.equal(h.service.getOperation(h.owner, intent.scope).attempts, 1);
});

test('M06 crash in waiting preserves subscription and wakes after a fresh lease', async () => {
  const h = harness(); await h.running(); await h.action(); const sub = await h.subscribe(); await h.verifyAction();
  const restarted = harness({storage: new MemoryStorage({snapshot: h.storage.snapshot()})}); restarted.tick(10001);
  await restarted.service.recover(restarted.state, 'prj_alpha');
  assert.equal(restarted.service.getTask(restarted.owner, scope()).state, 'WAITING_FOR_OWNER');
  await restarted.lease(); await restarted.wake(sub);
  assert.equal(restarted.service.getTask(restarted.owner, scope()).state, 'RUNNING');
});

for (const phase of ['before_commit', 'after_commit']) test(`M15 COMPLETE ${phase} crash keeps checkpoint and final outbox atomic`, async () => {
  let fault = '';
  const storage = new MemoryStorage({fault: actual => {if (actual === fault) {fault = ''; throw new Error('CRASH');}}});
  const h = harness({storage}); await h.running(); await h.go('QA_PENDING'); await h.go('PERSISTING');
  const task = h.service.getTask(h.supervisor, scope()); await h.service.checkpoint(h.supervisor, scope(), task.revision, task.lease);
  const command = h.transitionDto('COMPLETE'); fault = phase;
  await assert.rejects(h.service.transition(h.supervisor, command), /CRASH/);
  const finals = h.service.peekOutbox(h.state, 'prj_alpha').filter(item => item.body.kind === 'final-report');
  assert.equal(finals.length, phase === 'after_commit' ? 1 : 0);
  assert.equal(h.service.getTask(h.owner, scope()).state, phase === 'after_commit' ? 'COMPLETE' : 'PERSISTING');
  await h.service.transition(h.supervisor, command);
  assert.equal(h.service.peekOutbox(h.state, 'prj_alpha').filter(item => item.body.kind === 'final-report').length, 1);
});

test('queued commands snapshot input before caller mutation', async () => {
  const h = harness(); await h.running();
  const command = h.transitionDto('QA_PENDING'); const promise = h.service.transition(h.supervisor, command);
  command.to_state = 'FAILED'; command.scope.project_id = 'prj_beta';
  await promise; assert.equal(h.service.getTask(h.owner, scope()).state, 'QA_PENDING');
});

test('cross-task operation ID and forged tool receipt cannot consume another task', async () => {
  const h = harness(); await h.running(); const intent = await h.intent(); await h.dispatch(intent.scope);
  const spec = h.service.getTask(h.owner, scope()).spec;
  const otherScope = scope('prj_alpha', 'task_two', 'op_control_two'); await h.task(otherScope, [], spec);
  const receipt = h.receipt(intent.scope);
  await assert.rejects(h.service.recordToolReceipt(h.state, {...receipt, scope: {...intent.scope, task_id: 'task_two'}, expected_revision: 0}));
  const worker = h.service.session('act_worker');
  assert.throws(() => h.service.recordToolReceipt(worker, {...receipt, actor: worker}), error => error.code === 'ROLE_DENIED');
  assert.equal(h.service.getOperation(h.owner, intent.scope).status, 'DISPATCHED');
});

test('M15 payload/tool identity mismatch never confirms an operation', async () => {
  const h = harness(); await h.running(); const intent = await h.intent(); await h.dispatch(intent.scope);
  for (const changed of [{payload_hash: digest({changed: true})}, {tool_digest: digest({version: 2})}, {tool_id: 'tool_wrong'}]) {
    const before = h.storage.snapshot();
    await rejects(h.service.recordToolReceipt(h.state, h.receipt(intent.scope, 'CONFIRMED', changed)), 'OPERATION_BINDING_MISMATCH');
    assert.equal(h.storage.snapshot(), before);
  }
});

for (const phase of ['before_commit', 'after_commit']) test(`M15 checkpoint ${phase} fault is recoverable with no premature final report`, async () => {
  let fault = '';
  const storage = new MemoryStorage({fault: actual => {if (actual === fault) {fault = ''; throw new Error('CRASH');}}});
  const h = harness({storage}); await h.running(); await h.go('QA_PENDING'); await h.go('PERSISTING');
  const task = h.service.getTask(h.supervisor, scope()); fault = phase;
  await assert.rejects(h.service.checkpoint(h.supervisor, scope(), task.revision, task.lease), /CRASH/);
  assert.equal(h.service.peekOutbox(h.state, 'prj_alpha').filter(item => item.body.kind === 'final-report').length, 0);
  const current = h.service.getTask(h.supervisor, scope());
  assert.equal(current.checkpoint !== null, phase === 'after_commit');
  if (phase === 'before_commit') await h.service.checkpoint(h.supervisor, scope(), current.revision, current.lease);
  await h.go('COMPLETE');
});
