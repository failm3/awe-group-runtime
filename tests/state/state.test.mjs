import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {MemoryStorage} from '../../awe/state/memory-storage.mjs';
import {digest} from '../../contracts/canonical.mjs';
import {validateShape} from '../../contracts/schema-validator.mjs';
import {harness, scope, evidence, dto} from './harness.mjs';

const rejects = (operation, code) => assert.rejects(operation, error => error.code === code || error.details?.includes(code));
const rejected = (operation, code) => assert.throws(operation, error => error.code === code || error.details?.includes(code));

test('M04 concurrent identical create has one project/config owner/provision operation', async () => {
  const h = harness(), input = {project_id: 'prj_alpha', name: 'Synthetic', config_owner: 'act_owner', config: {canary: 1}};
  const results = await Promise.all(Array.from({length: 20}, () => h.service.createProject(h.owner, input, 'same')));
  assert(results.every(item => JSON.stringify(item) === JSON.stringify(results[0])));
  const data = JSON.parse(h.storage.snapshot()).data;
  assert.equal(Object.keys(data.projects).length, 1);
  assert.equal(Object.keys(data.projects.prj_alpha.configs).length, 1);
  assert.equal(data.projects.prj_alpha.status, 'PROVISIONING');
  await rejects(h.service.createProject(h.owner, {...input, config: {canary: 2}}, 'other'), 'PROJECT_CREATION_CONFLICT');
});

test('M04 worker cannot create or own project configuration', async () => {
  const h = harness(), worker = h.service.session('act_worker');
  const input = {project_id: 'prj_alpha', name: 'Canary', config_owner: 'act_owner', config: {canary: true}};
  assert.throws(() => h.service.createProject(worker, input, 'key'), error => error.code === 'ROLE_DENIED');
  assert.throws(() => h.service.createProject(h.owner, {...input, config_owner: 'act_worker'}, 'key'), error => error.code === 'CONFIG_OWNER_INVALID');
});

test('M04 partial provision stays non-READY, rejects forged QA02, recovers and compensates own resources', async () => {
  const h = harness(); await h.project('prj_alpha', false); await h.project('prj_beta', false);
  const alpha = await h.service.provision(h.owner, 'prj_alpha', 0);
  assert.equal(alpha.status, 'PROVISIONING');
  const before = h.storage.snapshot();
  await rejects(h.service.provision(h.owner, 'prj_alpha', alpha.revision, digest({forged: true})), 'QA02_UNVERIFIED');
  assert.equal(h.storage.snapshot(), before);
  await h.service.recover(h.state, 'prj_alpha');
  assert.equal(h.service.getProject(h.owner, 'prj_alpha').provision.recovery_required, true);
  await h.service.compensate(h.owner, 'prj_alpha', alpha.revision);
  const data = JSON.parse(h.storage.snapshot()).data.projects;
  assert.equal(data.prj_alpha.resources.length, 0);
  assert.equal(data.prj_alpha.status, 'ERROR');
  assert.equal(data.prj_beta.status, 'PROVISIONING');
  assert.equal(data.prj_beta.provision.phase, 'INTENT');
});

test('M04 config revisions immutable and QA02 invalidated; active task pins config', async () => {
  const h = harness(); let p = await h.project();
  p = await h.service.reviseConfig(h.owner, 'prj_alpha', p.revision, {template: 'v2'});
  assert.equal(p.status, 'PROVISIONING'); assert.equal(p.qa02, null);
  assert.equal(p.config_revision, 2);
  const data = JSON.parse(h.storage.snapshot()).data.projects.prj_alpha;
  assert.deepEqual(data.configs['1'].content, {template: 'offline-canary-v1'});
  await h.task();
  await rejects(h.service.reviseConfig(h.owner, 'prj_alpha', h.service.getProject(h.owner, 'prj_alpha').revision, {template: 'v3'}), 'ACTIVE_TASKS_CONFIG_PINNED');
});

test('M05 missing dependency and DAG cycle roll back, shared names remain project scoped', async () => {
  const h = harness(); await h.project(); const spec = await h.spec();
  const before = h.storage.snapshot();
  await rejects(h.task(scope(), ['task_missing'], spec), 'DEPENDENCY_MISSING');
  assert.equal(h.storage.snapshot(), before);
  await h.task(scope(), [], spec);
  await h.task(scope('prj_alpha', 'task_two', 'op_control_two'), ['task_one'], spec);
  await rejects(h.service.setDependencies(h.supervisor, scope(), 0, ['task_two']), 'DAG_CYCLE');
  assert.deepEqual(h.service.getTask(h.supervisor, scope()).dependencies, []);
  await h.project('prj_beta'); await h.task(scope('prj_beta'));
  assert.equal(h.service.getTask(h.owner, scope('prj_beta')).name, h.service.getTask(h.owner, scope()).name);
});

test('M05 incomplete/failed dependency cannot satisfy RUNNING fan-in', async () => {
  const h = harness(); await h.project(); const spec = await h.spec();
  await h.task(scope(), [], spec); const downstream = scope('prj_alpha', 'task_downstream', 'op_control_downstream');
  await h.task(downstream, ['task_one'], spec); await h.lease(downstream); await h.go('READY', downstream);
  await rejects(h.go('RUNNING', downstream), 'GUARD_EVIDENCE_MISSING');
  await h.lease(); await h.go('FAILED');
  await rejects(h.go('RUNNING', downstream), 'GUARD_EVIDENCE_MISSING');
});

test('M05 two CAS transitions from one revision accept exactly one and one outbox event', async () => {
  const h = harness(); await h.project(); await h.task(); await h.lease();
  const a = h.transitionDto('READY'), b = h.transitionDto('READY');
  const result = await Promise.allSettled([h.service.transition(h.supervisor, a), h.service.transition(h.supervisor, b)]);
  assert.equal(result.filter(item => item.status === 'fulfilled').length, 1);
  assert.equal(result.filter(item => item.status === 'rejected').length, 1);
  assert.equal(h.service.scanEvents(h.supervisor, h.service.cursor(h.supervisor, 'prj_alpha')).events.length, 1);
  assert.equal(h.service.peekOutbox(h.state, 'prj_alpha').length, 1);
});

test('M05 transition event replay dedup and conflicting reuse reject', async () => {
  const h = harness(); await h.project(); await h.task(); await h.lease();
  const command = h.transitionDto('READY');
  const first = await h.service.transition(h.supervisor, command);
  assert.deepEqual(await h.service.transition(h.supervisor, command), first);
  await rejects(h.service.transition(h.supervisor, {...command, reason: 'Changed payload'}), 'IDEMPOTENCY_CONFLICT');
  assert.equal(h.service.getTask(h.owner, scope()).revision, first.revision);
});

test('M05 expired lease, stolen holder and stale fence rejected after takeover', async () => {
  const h = harness(); await h.running(); const stale = h.transitionDto('QA_PENDING');
  const other = h.service.session('act_other_supervisor');
  await rejects(h.service.transition(other, {...stale, actor: other}), 'STALE_LEASE_OR_FENCE');
  h.tick(10001);
  await rejects(h.service.transition(h.supervisor, stale), 'STALE_LEASE_OR_FENCE');
  const newTask = await h.lease(scope(), other);
  assert(newTask.fence > stale.fence);
  await rejects(h.service.transition(h.supervisor, {...stale, expected_revision: newTask.revision}), 'STALE_LEASE_OR_FENCE');
  const current = h.transitionDto('QA_PENDING', scope(), other);
  await h.service.transition(other, current);
});

test('M05 concurrent lease grants have one current holder', async () => {
  const h = harness(); await h.project(); await h.task();
  const other = h.service.session('act_other_supervisor');
  const results = await Promise.allSettled([h.lease(), h.lease(scope(), other)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(h.service.getTask(h.owner, scope()).fence, 1);
});

test('M05 checkpoint is invalid after a lease takeover', async () => {
  const h = harness(); await h.running(); await h.go('QA_PENDING'); await h.go('PERSISTING');
  let task = h.service.getTask(h.supervisor, scope());
  await h.service.checkpoint(h.supervisor, scope(), task.revision, task.lease);
  h.tick(10001); await h.lease();
  await rejects(h.go('COMPLETE'), 'GUARD_EVIDENCE_MISSING');
});

test('M05 COMPLETE requires checkpoint/readback/outbox and records final report after checkpoint', async () => {
  const h = harness(); await h.running(); await h.go('QA_PENDING'); await h.go('PERSISTING');
  await rejects(h.go('COMPLETE'), 'GUARD_EVIDENCE_MISSING');
  let task = h.service.getTask(h.supervisor, scope());
  const cp = await h.service.checkpoint(h.supervisor, scope(), task.revision, task.lease);
  task = await h.go('COMPLETE'); assert.equal(task.state, 'COMPLETE');
  const final = h.service.peekOutbox(h.state, 'prj_alpha').find(item => item.body.kind === 'final-report');
  assert.equal(final.body.checkpoint, cp.checkpoint_ref);
  assert.equal(final.body.revision, task.revision);
  assert.equal(digest(final.body), cp.outbox_ref);
  await rejects(h.go('FAILED'), 'TERMINAL_IMMUTABLE');
});

test('M05 missing trusted QA evidence blocks PERSISTING; missing readback blocks checkpoint', async () => {
  let missing = 'examiner_qa';
  const h = harness({evidence: binding => {const result = evidence(binding); delete result[missing]; return result;}});
  await h.running(); await h.go('QA_PENDING');
  await rejects(h.go('PERSISTING'), 'GUARD_EVIDENCE_MISSING');
  missing = 'independent_readback'; await h.go('PERSISTING');
  const task = h.service.getTask(h.supervisor, scope());
  await rejects(h.service.checkpoint(h.supervisor, scope(), task.revision, task.lease), 'READBACK_REQUIRED');
});

test('M05 rework counter persists and second rework is bounded', async () => {
  const h = harness(); await h.running(); await h.go('QA_PENDING'); await h.go('REWORK');
  await h.go('READY'); await h.go('RUNNING'); await h.go('QA_PENDING');
  await rejects(h.go('REWORK'), 'REWORK_LIMIT');
  assert.equal(h.service.getTask(h.owner, scope()).rework_count, 1);
});

test('immutable full spec hashes and sequential supersession reject stale task work', async () => {
  const h = harness(); await h.running(); const task = h.service.getTask(h.owner, scope());
  const p = h.service.getProject(h.owner, 'prj_alpha');
  const forged = dto('spec-revision', h.owner, scope(), task.spec, p.epochs, p.revision, h.now(),
    {status: 'APPROVED', requirements: ['reqmt_canary'], norms: ['constitution:0.1-draft:C-01'], supersedes: null});
  await rejects(h.service.storeSpec(h.owner, forged, {changed: true}), 'IMMUTABLE_SPEC_REVISION');
  const next = await h.spec('prj_alpha', {requirements: ['new canary'], acceptance: ['offline']}, task.spec);
  assert.equal(next.revision, 2);
  await rejects(h.go('QA_PENDING'), 'SPEC_SUPERSEDED');
  assert.equal(h.service.getTask(h.owner, scope()).spec.revision, 1);
});

test('M18 all GET/query/cursor calls are read-only and return detached results', async () => {
  const h = harness(); await h.running(); const intent = await h.intent();
  const before = h.storage.snapshot();
  for (let i = 0; i < 50; i++) {
    const project = h.service.getProject(h.owner, 'prj_alpha'); project.status = 'ARCHIVED';
    const task = h.service.getTask(h.owner, scope()); task.dependencies.push('task_forged');
    h.service.getTransitionContext(h.supervisor, scope()); h.service.getOperation(h.owner, intent.scope);
    h.service.getOwnerActions(h.owner, 'prj_alpha'); h.service.getSubscriptions(h.owner, 'prj_alpha');
    h.service.peekOutbox(h.state, 'prj_alpha');
    const cursor = h.service.cursor(h.owner, 'prj_alpha'); h.service.scanEvents(h.owner, cursor, 1);
  }
  assert.equal(h.storage.snapshot(), before);
  assert.equal(h.service.getOperation(h.owner, intent.scope).attempts, 0);
});

test('M18 foreign project scans, forged session and cursor recipient/stream/future rejected', async () => {
  const h = harness(); await h.running(); await h.project('prj_beta');
  const foreign = h.service.session('act_foreign');
  rejected(() => h.service.getProject(foreign, 'prj_alpha'), 'SCOPE_DENIED');
  rejected(() => h.service.getTask(foreign, scope()), 'SCOPE_DENIED');
  rejected(() => h.service.getTask({...h.supervisor}, scope()), 'SESSION_UNTRUSTED');
  const cursor = h.service.cursor(h.owner, 'prj_alpha');
  rejected(() => h.service.scanEvents(foreign, cursor), 'SCOPE_DENIED');
  rejected(() => h.service.scanEvents(h.supervisor, cursor), 'ACTOR_CONTEXT_MISMATCH');
  rejected(() => h.service.scanEvents(h.owner, {...cursor, stream_id: 'stream_forged'}), 'CURSOR_STREAM_MISMATCH');
  rejected(() => h.service.scanEvents(h.owner, {...cursor, last_sequence: 1000}), 'CURSOR_STREAM_MISMATCH');
  h.tick(60001); rejected(() => h.service.scanEvents(h.owner, cursor), 'EXPIRED');
});

test('schema/version/epoch/spec mismatch fail without state changes', async () => {
  const h = harness(); await h.running();
  for (const change of [{schema_version: '2.0.0'}, {epochs: {policy: 2, auth: 1, stop: 0, owner: 1}},
    {spec: {spec_id: 'spec_wrong', revision: 1, content_hash: digest({wrong: true})}}]) {
    const before = h.storage.snapshot();
    await assert.rejects(async () => h.service.transition(h.supervisor, {...h.transitionDto('QA_PENDING'), ...change}));
    assert.equal(h.storage.snapshot(), before);
  }
});

test('epoch sync revokes active lease, pauses on stop, rejects epoch rollback', async () => {
  const h = harness(); await h.running(); const old = h.transitionDto('QA_PENDING');
  let p = h.service.getProject(h.state, 'prj_alpha');
  p = await h.service.syncEpochs(h.state, 'prj_alpha', p.revision, {...p.epochs, auth: 2, stop: 1});
  assert.equal(p.status, 'PAUSED');
  await assert.rejects(h.service.transition(h.supervisor, old));
  await rejects(h.service.syncEpochs(h.state, 'prj_alpha', p.revision, {...p.epochs, auth: 1}), 'EPOCH_NOT_MONOTONIC');
});

test('storage rollback and lost commit ACK; queue survives rejected transaction', async () => {
  let fault = '';
  const storage = new MemoryStorage({fault: phase => {if (fault === phase) {fault = ''; throw new Error(phase);}}});
  const h = harness({storage});
  fault = 'before_commit'; await assert.rejects(h.project('prj_alpha', false), /before_commit/);
  rejected(() => h.service.getProject(h.owner, 'prj_alpha'), 'PROJECT_MISSING');
  fault = 'after_commit'; await assert.rejects(h.project('prj_alpha', false), /after_commit/);
  assert.equal(h.service.getProject(h.owner, 'prj_alpha').status, 'PROVISIONING');
  await h.project('prj_alpha', false);
});

test('storage forbids async reducers and does not expose committed aliases', async () => {
  const storage = new MemoryStorage(); const retained = {};
  await storage.transaction(db => {db.projects = retained; return db;}); retained.poison = true;
  assert.deepEqual(storage.read(db => db.projects), {});
  await rejects(storage.transaction(async db => {db.projects.poison = true;}), 'ASYNC_TRANSACTION_FORBIDDEN');
  assert.deepEqual(storage.read(db => db.projects), {});
});

test('snapshot restore rejects corruption/version/content mismatch and preserves immutable data', async () => {
  const h = harness(); await h.running(); const snapshot = h.storage.snapshot();
  const restored = JSON.parse(new MemoryStorage({snapshot}).snapshot()).data.projects.prj_alpha;
  assert.deepEqual(restored.tasks.task_one.spec, h.service.getTask(h.owner, scope()).spec);
  assert.equal(restored.tasks.task_one.restore_pending, true);
  rejected(() => new MemoryStorage({snapshot: snapshot.slice(0, -1)}), 'SNAPSHOT_JSON');
  let record = JSON.parse(snapshot); record.data.projects.prj_alpha.name = 'damaged';
  rejected(() => new MemoryStorage({snapshot: JSON.stringify(record)}), 'SNAPSHOT_CHECKSUM');
  record = JSON.parse(snapshot); record.snapshot_version = 2;
  rejected(() => new MemoryStorage({snapshot: JSON.stringify(record)}), 'SNAPSHOT_CHECKSUM');
  record = JSON.parse(snapshot); Object.values(record.data.projects.prj_alpha.specs)[0].content = {damaged: true};
  record.checksum = createHash('sha256').update(JSON.stringify(record.data)).digest('hex');
  rejected(() => new MemoryStorage({snapshot: JSON.stringify(record)}), 'SNAPSHOT_SPEC');
});

test('stored events conform to untouched D-01 schema', async () => {
  const h = harness(); await h.running();
  for (const event of h.service.scanEvents(h.owner, h.service.cursor(h.owner, 'prj_alpha')).events)
    assert.deepEqual(validateShape('event-envelope', event), []);
});
