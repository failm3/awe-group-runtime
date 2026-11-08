import test from 'node:test';
import assert from 'node:assert/strict';
import {canonicalize, digest} from '../../contracts/canonical.mjs';
import {bodyHash} from '../../awe/events/journal.mjs';
import {harness, scope} from './harness.mjs';

const rejects = (operation, code) => assert.rejects(operation, error => error.code === code || error.details?.includes(code));

async function waitingFixture(h, beforeWait = false) {
  await h.running(); await h.action();
  if (beforeWait) await h.verifyAction();
  const subscription = await h.subscribe();
  if (!beforeWait) await h.verifyAction();
  return subscription;
}

function callback(h, extra = {}) {
  const cursor = h.service.cursor(h.state, 'prj_alpha');
  const source = h.service.scanEvents(h.state, cursor).events.filter(event => event.event_type === 'owner-action.updated').at(-1);
  const payload = {owner_action_id: 'oa_canary', status: 'VERIFIED'};
  const task = h.service.getTask(h.state, scope());
  const event = {...source, actor: h.state, event_id: h.next('evt_external'), sequence: h.service.scanEvents(h.state, cursor).cursor.last_sequence + 1,
    created_at: h.now(), received_at: h.now(), expected_revision: task.revision,
    payload_ref: {...source.payload_ref, content_hash: digest(payload), bytes: Buffer.byteLength(canonicalize(payload))}, ...extra};
  h.receipts.set(event.event_id, {receipt_hash: event.producer_receipt_hash, body_hash: bodyHash(event)});
  return {event, payload};
}

for (const beforeWait of [true, false]) test(`M06 ${beforeWait ? 'event-before-wait' : 'wait-before-event'} resumes once with durable consume`, async () => {
  const h = harness(), subscription = await waitingFixture(h, beforeWait);
  assert.equal(h.service.getTask(h.owner, scope()).state, 'WAITING_FOR_OWNER');
  const stored = h.service.getSubscriptions(h.owner, 'prj_alpha')[0];
  assert.equal(stored.status, 'SIGNALLED');
  const task = await h.wake(subscription); assert.equal(task.state, 'RUNNING');
  assert.equal(h.service.getOwnerActions(h.owner, 'prj_alpha')[0].uses, 1);
  await rejects(h.wake(subscription), 'WAKE_DENIED');
  const inbox = JSON.parse(h.storage.snapshot()).data.projects.prj_alpha.inbox;
  assert.equal(Object.values(inbox).filter(item => item.status === 'CONSUMED').length, 1);
});

test('M06 concurrent wake contenders accept one resume and atomic consumer dedup', async () => {
  const h = harness(), subscription = await waitingFixture(h);
  const task = h.service.getTask(h.supervisor, scope());
  const call = () => h.service.wake(h.supervisor, 'prj_alpha', subscription.dto.subscription_id, task.revision, task.lease);
  const results = await Promise.allSettled([call(), call()]);
  assert.equal(results.filter(item => item.status === 'fulfilled').length, 1);
  assert.equal(h.service.getTask(h.owner, scope()).state, 'RUNNING');
});

test('M06 subscribe and callback serial orders cannot lose wake', async () => {
  for (const eventFirst of [true, false]) {
    const h = harness(); await h.running(); await h.action(); await h.verifyAction();
    const cursor = h.service.cursor(h.supervisor, 'prj_alpha',
      h.service.scanEvents(h.supervisor, h.service.cursor(h.supervisor, 'prj_alpha')).cursor.last_sequence);
    const {event, payload} = callback(h);
    // Callback sequence is allocated against current stream. If the wait commits first,
    // the source must resync its stream cursor; stale sequence is rejected, never lost.
    if (eventFirst) {
      const receiving = h.service.receiveEvent(h.state, event, payload);
      const subscribing = h.subscribe(scope(), cursor);
      await Promise.all([receiving, subscribing]);
    } else {
      await h.subscribe(scope(), cursor);
      const retry = callback(h);
      await h.service.receiveEvent(h.state, retry.event, retry.payload);
    }
    assert.equal(h.service.getSubscriptions(h.owner, 'prj_alpha')[0].status, 'SIGNALLED');
  }
});

test('M06 external inbox dedup rejects conflicting payload/forged producer/stale source version', async () => {
  const h = harness(); await waitingFixture(h);
  let {event, payload} = callback(h);
  const result = await h.service.receiveEvent(h.state, event, payload);
  assert.deepEqual(await h.service.receiveEvent(h.state, event, payload), result);
  await rejects(h.service.receiveEvent(h.state, event, {...payload, status: 'REVOKED'}), 'IDEMPOTENCY_CONFLICT');
  const forged = callback(h); h.receipts.delete(forged.event.event_id);
  await rejects(h.service.receiveEvent(h.state, forged.event, forged.payload), 'EVENT_PRODUCER_UNVERIFIED');
  const tampered = callback(h);
  tampered.event.expires_at = '2026-11-05T13:00:00.000Z';
  await rejects(h.service.receiveEvent(h.state, tampered.event, tampered.payload), 'EVENT_PRODUCER_UNVERIFIED');
  const wrongVersion = callback(h, {source_version: '0.9.0'});
  assert.throws(() => h.service.receiveEvent(h.state, wrongVersion.event, wrongVersion.payload), error => error.code === 'CONTRACT_INVALID');
});

test('M06 event scope/payload/sequence mismatch denied without mutations', async () => {
  const h = harness(); await waitingFixture(h);
  for (const overrides of [{sequence: 999}, {scope: scope('prj_alpha', 'task_missing')},
    {epochs: {policy: 1, auth: 2, stop: 0, owner: 1}}, {expires_at: '2026-11-05T11:59:00.000Z'}]) {
    const {event, payload} = callback(h, overrides), before = h.storage.snapshot();
    await assert.rejects(h.service.receiveEvent(h.state, event, payload));
    assert.equal(h.storage.snapshot(), before);
  }
  const c = callback(h);
  await rejects(h.service.receiveEvent(h.state, c.event, {...c.payload, unexpected: 'canary'}), 'EVENT_PAYLOAD_MISMATCH');
});

test('M06 arbitrary owner SUBMITTED event is not verification and cannot wake', async () => {
  const h = harness(); await h.running(); await h.action(); const sub = await h.subscribe();
  await h.action('SUBMITTED');
  assert.equal(h.service.getSubscriptions(h.owner, 'prj_alpha')[0].status, 'ACTIVE');
  await rejects(h.wake(sub), 'WAKE_NOT_READY');
  const action = h.service.getOwnerActions(h.owner, 'prj_alpha')[0].dto;
  const task = h.service.getTask(h.owner, scope());
  await rejects(h.service.storeOwnerAction(h.owner, {...action, request_id: 'req_forged', actor: h.owner,
    expected_revision: task.revision, status: 'VERIFIED', verification_receipt: digest({forged: true})}), 'OWNER_ACTION_TRANSITION');
});

test('M06 cancel wins against late callback and cannot be undone by wake/recovery', async () => {
  const h = harness(), sub = await waitingFixture(h);
  let task = h.service.getTask(h.owner, scope());
  await h.service.cancel(h.owner, scope(), task.revision, 'cancel');
  const late = callback(h);
  assert.equal((await h.service.receiveEvent(h.state, late.event, late.payload)).status, 'LATE_IGNORED');
  await rejects(h.wake(sub), 'WAKE_DENIED');
  await h.service.recover(h.state, 'prj_alpha');
  task = await h.lease();
  await h.service.finishCancel(h.supervisor, scope(), task.revision, task.lease);
  assert.equal(h.service.getTask(h.owner, scope()).state, 'CANCELLED');
  await assert.rejects(h.service.cancel(h.owner, scope(), h.service.getTask(h.owner, scope()).revision, 'cancel-again'));
});

test('M06 cancel versus wake same revision: one winner and cancel remains sticky on retry', async () => {
  for (const cancelFirst of [true, false]) {
    const h = harness(), sub = await waitingFixture(h), task = h.service.getTask(h.owner, scope());
    const cancel = () => h.service.cancel(h.owner, scope(), task.revision, 'race');
    const wake = () => h.service.wake(h.supervisor, 'prj_alpha', sub.dto.subscription_id, task.revision, task.lease);
    const result = await Promise.allSettled(cancelFirst ? [cancel(), wake()] : [wake(), cancel()]);
    assert.equal(result.filter(item => item.status === 'fulfilled').length, 1);
    if (!cancelFirst) {
      const current = h.service.getTask(h.owner, scope());
      await h.service.cancel(h.owner, scope(), current.revision, 'retry-cancel');
    }
    assert.equal(h.service.getTask(h.owner, scope()).cancel_requested, true);
  }
});

test('M06 deadline boundary denies wake; timeout blocks with new fence and no launch', async () => {
  const h = harness(), sub = await waitingFixture(h); h.tick(30000);
  await rejects(h.wake(sub), 'WAKE_NOT_READY');
  const task = h.service.getTask(h.state, scope());
  const blocked = await h.service.expireSubscription(h.state, 'prj_alpha', sub.dto.subscription_id, task.revision);
  assert.equal(blocked.state, 'BLOCKED'); assert(blocked.fence > task.fence);
  await rejects(h.wake(sub), 'WAKE_DENIED');
  const leased = await h.lease();
  await rejects(h.service.resume(h.supervisor, scope(), leased.revision, leased.lease), 'WAIT_REQUIRES_VERIFIED_WAKE');
});

test('M06 callback and timeout at exact deadline accept timeout; no resume', async () => {
  const h = harness(); await h.running(); await h.action(); await h.verifyAction();
  const cursor = h.service.cursor(h.supervisor, 'prj_alpha', h.service.scanEvents(h.supervisor,
    h.service.cursor(h.supervisor, 'prj_alpha')).cursor.last_sequence);
  const sub = await h.subscribe(scope(), cursor); h.tick(30000);
  const c = callback(h), task = h.service.getTask(h.state, scope());
  await Promise.all([h.service.receiveEvent(h.state, c.event, c.payload),
    h.service.expireSubscription(h.state, 'prj_alpha', sub.dto.subscription_id, task.revision)]);
  assert.equal(h.service.getTask(h.owner, scope()).state, 'BLOCKED');
  assert.equal(h.service.getSubscriptions(h.owner, 'prj_alpha')[0].status, 'EXPIRED');
});

test('M06 revoked owner action and epoch changes invalidate signalled wake', async () => {
  const h = harness(), sub = await waitingFixture(h);
  await h.action('REVOKED'); await rejects(h.wake(sub), 'OWNER_ACTION_UNUSABLE');
  const p = h.service.getProject(h.state, 'prj_alpha');
  await h.service.syncEpochs(h.state, 'prj_alpha', p.revision, {...p.epochs, owner: 2});
  assert.equal(h.service.getSubscriptions(h.owner, 'prj_alpha')[0].status, 'REVOKED');
  await assert.rejects(h.wake(sub));
});

test('M06 foreign recipient cursor/subscription and action binding reject atomically', async () => {
  const h = harness(); await h.running(); await h.action();
  const foreignCursor = h.service.cursor(h.owner, 'prj_alpha');
  const before = h.storage.snapshot();
  await rejects(h.subscribe(scope(), foreignCursor), 'ACTOR_CONTEXT_MISMATCH');
  assert.equal(h.storage.snapshot(), before);
  await rejects(h.subscribe(scope(), h.service.cursor(h.supervisor, 'prj_alpha'), 'owner-action.updated', 'oa_missing'), 'OWNER_ACTION_UNUSABLE');
});

test('M15 outbox crash after delivery before ACK redelivers same key; stale ACK rejected', async () => {
  const h = harness(); await h.running(); const key = h.service.peekOutbox(h.state, 'prj_alpha')[0].key;
  const delivered = new Set(); let effects = 0;
  const consume = item => {if (!delivered.has(item.key)) {delivered.add(item.key); effects++;}};
  const first = await h.service.claimOutbox(h.state, 'prj_alpha', key, 1000); consume(first);
  h.tick(1001);
  const second = await h.service.claimOutbox(h.state, 'prj_alpha', key, 1000); consume(second);
  assert.equal(effects, 1); assert.equal(second.attempts, 2);
  await rejects(h.service.ackOutbox(h.state, 'prj_alpha', key, first.delivery_fence), 'OUTBOX_STALE_FENCE');
  await h.service.ackOutbox(h.state, 'prj_alpha', key, second.delivery_fence);
  assert.equal(h.service.peekOutbox(h.state, 'prj_alpha').find(item => item.key === key).status, 'ACKNOWLEDGED');
});
