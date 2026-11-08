import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../../contracts/canonical.mjs';
import {createE0Bridge} from '../../awe/integration/bridge.mjs';
import {MemoryStorage} from '../../awe/state/memory-storage.mjs';
import {harness} from '../state/harness.mjs';
import {fixture, completeCanary} from './fixtures.mjs';

const noConsume = f => { const i = f.inspect(); assert.equal(i.effects.length, 0);
  assert(i.approvals.every(a => !a.used)); assert(i.quotas.every(q => q.remaining_micros === '100'));
  assert.equal(i.actual_external_dispatches, 0); };
async function denied(f, text = f.text, context = f.auth, handle = f.handle) {
  const before = f.inspect(), result = await f.dispatch(text, context, handle);
  assert.equal(result.decision, 'DENY', JSON.stringify(result)); assert.equal(result.physical_decision, 'DENY');
  assert.deepEqual(f.inspect(), before); return result;
}

for (const unknown of [false, true]) test(`I01 joint lifecycle ${unknown ? 'unknown/reconcile' : 'confirmed receipt'} to synthetic COMPLETE`, async () => {
  const f = await fixture();
  assert.equal(f.preflight.decision, 'DENY'); assert.equal(f.preflight.phase, 'UNARMED_PREFLIGHT');
  assert.equal(f.preflight.physical_decision, 'DENY');
  assert.equal((await f.review()).decision, 'ALLOW_SIMULATION'); noConsume(f);
  const result = await completeCanary(f, unknown);
  assert.equal(result.task.state, 'COMPLETE'); assert.equal(result.retained, unknown);
  assert(result.checkpoint.checkpoint_ref.startsWith('sha256:'));
  assert.equal(f.inspect().effects.length, 1); assert.equal(f.inspect().quotas[0].remaining_micros, '90');
  assert.equal(f.operation().attempts, 1); assert.equal(f.operation().retry_authorized, false);
  assert.equal(f.h.service.getOwnerActions(f.h.state, 'prj_alpha')[0].uses, 1);
  assert.equal(f.h.service.peekOutbox(f.h.state, 'prj_alpha').filter(x => x.body.kind === 'final-report').length, 1);
  assert.equal(f.bridge.worker.requestPhysicalEffect({decision: 'ALLOW'}).decision, 'DENY');
});

for (const beforeWait of [false, true]) test(`I02 event ordering beforeWait=${beforeWait}, wake/action consumed once`, async () => {
  const f = await fixture({beforeWait});
  await assert.rejects(f.h.wake(f.subscription));
  await assert.rejects(f.bridge.control.approve(f.ownerSession, f.handle, 'oa_integrated'));
  assert.equal((await f.dispatch()).decision, 'CANARY_RECORDED');
  await denied(f); assert.equal(f.inspect().effects.length, 1);
});
test('I03 unverified owner action does not wake or prepare', async () => {
  const f = await fixture({verified: false}); await assert.rejects(f.h.wake(f.subscription));
  await assert.rejects(f.bridge.control.prepare(f.opScope, f.payload), /EFFECT_STATE_DENIED/); noConsume(f);
});

const mutations = {
  foreign_project: i => { i.scope.project_id = 'prj_foreign'; },
  foreign_task: i => { i.scope.task_id = 'task_foreign'; },
  foreign_operation: i => { i.scope.operation_id = 'op_foreign'; },
  foreign_tool: i => { i.tool_id = 'tool_foreign'; },
  foreign_trace: i => { i.action = 'read'; i.resource = 'foreign:trace'; },
  local_raw_trace: i => { i.action = 'read'; i.resource = 'canary:trace'; },
  forged_actor: i => { i.actor.identity_id = 'act_owner'; i.actor.role = 'OWNER'; },
  stale_revision: i => { i.expected_revision--; }, stale_spec: i => { i.spec.revision++; },
  stale_epoch: i => { i.epochs.auth++; }, payload: i => { i.payload.content = 'changed'; },
  cheap_reservation: i => { i.reservation_micros = '0'; }, tool_digest: i => { i.tool_digest = digest({wrong: true}); }
};
for (const [name, mutate] of Object.entries(mutations)) test('I04 negative binding ' + name, async () => {
  const f = await fixture(), intent = structuredClone(f.intent); mutate(intent);
  await denied(f, JSON.stringify(intent)); noConsume(f);
});
test('I05 forged/serialized/cross-instance identities and handles fail closed', async () => {
  const f = await fixture(), other = await fixture();
  for (const context of [{}, structuredClone(f.auth), other.auth]) await denied(f, f.text, context);
  for (const handle of [{}, structuredClone(f.handle), other.handle]) await denied(f, f.text, f.auth, handle);
  assert.throws(() => f.bridge.worker.authenticate({}, f.opScope), /SESSION_INVALID/);
  assert.throws(() => f.bridge.worker.authenticate(f.h.supervisor, f.opScope), /SESSION_INVALID/);
  assert.equal(f.bridge.worker.directDispatch({}, f.text).decision, 'DENY'); noConsume(f);
});
for (const bad of ['duplicate', 'unknown', 'oversize']) test('I06 strict raw transport ' + bad, async () => {
  const f = await fixture();
  const text = bad === 'duplicate' ? f.text.replace('{', '{"actor":{},')
    : bad === 'unknown' ? f.text.replace('{', '{"extra":1,') : ' '.repeat(65537);
  await denied(f, text); noConsume(f);
});
for (const kind of ['approval', 'grant', 'identity', 'tool', 'policy', 'quote']) test('I07 revoke after PDP ' + kind, async () => {
  const f = await fixture({action: kind === 'quote' ? 'inference' : 'publish'});
  assert.equal((await f.review()).decision, 'ALLOW_SIMULATION');
  if (kind === 'approval') f.bridge.control.revokeApproval(f.intent.approval_id);
  if (kind === 'grant') f.bridge.control.revokeGrant(f.intent.run_id);
  if (kind === 'identity') f.bridge.control.revokeIdentity('act_worker');
  if (kind === 'tool') f.bridge.control.revokeTool(f.tool.id);
  if (kind === 'policy') f.bridge.control.setPolicy('unknown-policy');
  if (kind === 'quote') f.bridge.control.revokeQuote(f.intent.quote_id);
  await denied(f); noConsume(f);
});
for (const key of ['policy', 'auth', 'stop', 'owner']) test('I08 epoch propagation revokes handles ' + key, async () => {
  const f = await fixture(); await f.bridge.control.advanceEpoch(key);
  assert.equal(f.h.service.getProject(f.h.state, 'prj_alpha').epochs[key], f.intent.epochs[key] + 1);
  await denied(f); noConsume(f);
});
test('I09 state epoch changed independently denies unsynchronised D02', async () => {
  const f = await fixture(), p = f.h.service.getProject(f.h.state, 'prj_alpha');
  await f.h.service.syncEpochs(f.h.state, 'prj_alpha', p.revision, {...p.epochs, auth: 2});
  await denied(f); noConsume(f);
});
for (const cancelFirst of [true, false]) test(`I10 queued cancel vs effect cancelFirst=${cancelFirst}`, async () => {
  const f = await fixture(), t = f.task();
  const cancel = () => f.h.service.cancel(f.h.owner, f.taskScope, t.revision, 'cancel-race');
  const results = await Promise.allSettled(cancelFirst ? [cancel(), f.dispatch()] : [f.dispatch(), cancel()]);
  assert.equal(results.filter(x => x.status === 'fulfilled' && x.value?.decision === 'CANARY_RECORDED').length, 0);
  assert.equal(f.task().cancel_requested, true); await denied(f); noConsume(f);
});
test('I11 cancel after canary records no second effect and requires receipt reconciliation', async () => {
  const f = await fixture(); await f.dispatch(); const t = f.task();
  await f.h.service.cancel(f.h.owner, f.taskScope, t.revision, 'cancel-after');
  assert.equal(f.operation().status, 'DISPATCHED'); assert.equal(f.operation().retained_reservation, true);
  await denied(f); assert.equal(f.inspect().effects.length, 1);
  await f.h.reconcile(f.opScope, 'APPLIED'); const leased = await f.h.lease();
  await f.h.service.finishCancel(f.h.supervisor, f.taskScope, leased.revision, leased.lease);
  assert.equal(f.task().state, 'CANCELLED');
});
test('I12 revision/fence change and expired lease deny old admission', async () => {
  const f = await fixture(); f.h.tick(11000);
  await f.h.lease(); await denied(f); noConsume(f);
});
test('I13 task revision changed without epoch denies old approval', async () => {
  const f = await fixture(); await f.h.go('QA_PENDING'); await denied(f); noConsume(f);
});
test('I14 superseded spec invalidates active intent', async () => {
  const f = await fixture(); await f.h.spec('prj_alpha', {requirements: ['changed']}, f.task().spec);
  await denied(f); noConsume(f);
});
test('I15 store unavailable denies before consumption, restoration needs fresh review', async () => {
  const f = await fixture(); f.outage(false);
  await denied(f); assert.equal((await f.review()).decision, 'DENY'); noConsume(f);
  f.outage(true); assert.equal((await f.review()).decision, 'ALLOW_SIMULATION');
});
test('I16 unavailable store during epoch sync latches deny', async () => {
  const f = await fixture(); f.outage(false); await assert.rejects(f.bridge.control.advanceEpoch('auth'));
  f.outage(true); await denied(f); assert.equal(f.inspect().quarantined, true); noConsume(f);
});
for (const stage of ['before_commit', 'after_commit']) test('I17 split ledger failure quarantines and retains consumption ' + stage, async () => {
  const f = await fixture(); f.fault(stage);
  const result = await f.dispatch(); assert.equal(result.decision, 'OUTCOME_UNKNOWN');
  assert.equal(result.retained_consumption, true); assert.equal(f.inspect().effects.length, 1);
  assert.equal(f.inspect().approvals[0].used, true); assert.equal(f.inspect().quotas[0].remaining_micros, '90');
  f.fault(null); await denied(f); assert.equal(f.inspect().quarantined, true);
  assert.equal(f.operation().status, stage === 'after_commit' ? 'DISPATCHED' : 'INTENT');
});
test('I18 concurrent duplicate commands consume approval/quota once in one process', async () => {
  const f = await fixture(), results = await Promise.all(Array.from({length: 12}, () => f.dispatch()));
  assert.equal(results.filter(r => r.decision === 'CANARY_RECORDED').length, 1);
  assert.equal(results.filter(r => r.decision === 'DENY').length, 11);
  assert.equal(f.inspect().effects.length, 1); assert.equal(f.operation().attempts, 1);
});
test('I19 lost receipt cannot retry via new ID or fresh security instance', async () => {
  const f = await fixture(); await f.dispatch();
  await f.h.service.recordToolReceipt(f.h.state, f.h.receipt(f.opScope, 'OUTCOME_UNKNOWN'));
  assert.equal(f.operation().retained_reservation, true); await denied(f);
  let t = f.task();
  await assert.rejects(f.h.service.intent(f.h.supervisor, {...f.input, scope: {...f.opScope, operation_id: 'op_retry'}}, t.revision, t.lease, 'retry'));
  await f.h.reconcile(f.opScope, 'NOT_APPLIED'); t = f.task();
  await f.h.service.resume(f.h.supervisor, f.taskScope, t.revision, t.lease);
  assert.equal(f.operation().retry_authorized, false);
  const fresh = await createE0Bridge(f.bridgeOptions);
  await assert.rejects(fresh.control.prepare(f.opScope, f.payload), /PRE_HANDSHAKE_OPERATION_BLOCKED/);
});
test('I20 restored snapshot cannot restore old handles, leases or privileges', async () => {
  const f = await fixture(); await f.dispatch();
  const storage = new MemoryStorage({snapshot: f.h.storage.snapshot()}), h = harness({storage});
  const options = {...f.bridgeOptions, state: h.service, storage, supervisor: h.supervisor, reader: h.state};
  await assert.rejects(createE0Bridge(options), /HANDSHAKE_STATE_DENIED/);
  await h.service.recover(h.state, 'prj_alpha');
  assert.equal(h.service.getOperation(h.state, f.opScope).status, 'OUTCOME_UNKNOWN');
  await assert.rejects(createE0Bridge(options), /HANDSHAKE_STATE_DENIED/);
  assert.throws(() => h.service.getTask(f.h.state, f.taskScope), error => error.code === 'SESSION_UNTRUSTED');
});
test('I21 fresh process model with empty state cannot import old authorization', async () => {
  const f = await fixture(), h = harness();
  await assert.rejects(createE0Bridge({...f.bridgeOptions, state: h.service, supervisor: h.supervisor, reader: h.state}));
  const other = await fixture(); await denied(other, other.text, f.auth, f.handle); noConsume(other);
});
test('I22 failed quote/budget and unknown policy cannot record a canary', async () => {
  for (const options of [{quota: '0'}, {action: 'inference', quoteStatus: 'UNKNOWN'}, {policyId: 'unknown'}]) {
    const f = await fixture(options); assert.equal((await f.review()).decision, 'DENY');
    await denied(f); assert.equal(f.inspect().effects.length, 0);
  }
});
test('I23 publisher/Examiner/Auditor subjects must be independent', async () => {
  await assert.rejects(fixture({subjectsConflict: true}), /QA_SUBJECT_CONFLICT/);
  const f = await fixture();
  for (const id of ['act_examiner', 'act_auditor']) {
    const auth = f.bridge.worker.authenticate(f.bridge.control.issueSession(id), f.opScope);
    await denied(f, f.text, auth);
  }
  noConsume(f);
});
test('I24 scoped DAG waits for completed dependency and publishes one final outbox', async () => {
  const f = await fixture(), dependent = {...f.taskScope, task_id: 'task_dependent', operation_id: 'op_dependent_control'};
  await f.h.task(dependent, [f.taskScope.task_id], f.task().spec); await f.h.lease(dependent);
  await f.h.go('READY', dependent); await assert.rejects(f.h.go('RUNNING', dependent));
  await completeCanary(f); await f.h.go('RUNNING', dependent);
  assert.equal(f.h.service.getTask(f.h.state, dependent).state, 'RUNNING');
});
test('I25 async final port and mock physical ALLOW cannot authorize effects', async () => {
  const f = await fixture(), request = f.h.service.requestEffect.bind(f.h.service);
  f.h.service.requestEffect = async (...args) => request(...args);
  assert.equal((await denied(f)).reason, 'ASYNC_FINAL_BARRIER_BLOCKED'); noConsume(f);
  f.h.service.requestEffect = (...args) => ({...request(...args), decision: 'ALLOW'});
  assert.equal((await denied(f)).reason, 'PHYSICAL_DENY_REQUIRED'); noConsume(f);
});
test('I26 consumed D03 review is immutable; separate D02 approval remains revocable', async () => {
  const f = await fixture(); await assert.rejects(f.ownerAction('REVOKED'), error => error.code === 'OWNER_ACTION_TRANSITION');
  f.bridge.control.revokeApproval(f.intent.approval_id); await denied(f); noConsume(f);
});
test('I27 cannot infer approval from owner JSON or an Executor session', async () => {
  const f = await fixture();
  const prepared = await fixture({verified: false});
  assert.throws(() => prepared.bridge.worker.authenticate(structuredClone(f.ownerSession), f.opScope));
  await assert.rejects(f.bridge.control.approve(f.executorSession, f.handle, 'oa_integrated'));
  noConsume(f);
});
test('I28 revoke at final boundary is rechecked by D02 PEP', async () => {
  const f = await fixture(), original = f.h.service.requestEffect.bind(f.h.service);
  f.h.service.requestEffect = (...args) => { const result = original(...args);
    f.bridge.control.revokeApproval(f.intent.approval_id); return result; };
  assert.equal((await f.dispatch()).decision, 'DENY'); noConsume(f);
});
test('I29 cancel queued at final boundary quarantines split canary commit', async () => {
  const f = await fixture(), original = f.h.service.requestEffect.bind(f.h.service);
  let cancelling;
  f.h.service.requestEffect = (...args) => { const result = original(...args);
    cancelling = f.h.service.cancel(f.h.owner, f.taskScope, f.task().revision, 'final-cancel'); return result; };
  const result = await f.dispatch(); await cancelling;
  assert.equal(result.decision, 'OUTCOME_UNKNOWN'); assert.equal(f.inspect().effects.length, 1);
  assert.equal(f.inspect().quarantined, true); assert.equal(f.task().cancel_requested, true);
  assert.equal(f.operation().status, 'ABORTED'); assert.equal(result.physical_decision, 'DENY');
});
test('I30 restart before dispatch cannot rearm pre-handshake INTENT even with current state', async () => {
  const f = await fixture(), restarted = await createE0Bridge(f.bridgeOptions);
  await assert.rejects(restarted.control.prepare(f.opScope, f.payload), /PRE_HANDSHAKE_OPERATION_BLOCKED/);
  assert.equal(restarted.control.inspect().effects.length, 0); noConsume(f);
});
test('I31 project snapshot fault between reads and final barrier denies current-state mismatch', async () => {
  const f = await fixture(), original = f.h.service.getOperation.bind(f.h.service);
  f.h.service.getOperation = async (...args) => {
    const result = original(...args);
    await f.h.storage.transaction(db => { db.projects.prj_alpha.revision++; db.projects.prj_alpha.status = 'ERROR'; return null; });
    return result;
  };
  assert.equal((await denied(f)).reason, 'CURRENT_STATE_MISMATCH'); noConsume(f);
});
