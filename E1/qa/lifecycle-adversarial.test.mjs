import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {infra} from '../index.mjs';
import {runtimeConfig, removeScratch, c1Denied} from './helpers.mjs';

function setup() {
  const config = runtimeConfig();
  let now = 1000;
  const context = role => ({principal_id: config.principals[role].principal_id, project_id: config.project_id, origin: config.origin});
  const grant = {grant_id: 'grant_e1_worker', principal_id: config.principals.worker.principal_id, project_id: config.project_id,
    origin: config.origin, purpose: 'worker-data', expires_at: 2000};
  const vault = infra.createScopedVault({config, grants: [grant], now: () => now, available: true});
  const handle = vault.issueHandle(grant.grant_id, context('issuer'));
  const supervisor = () => infra.createFixtureSupervisor({config, vault, vault_access: {handle, context: context('worker')}});
  return {config, vault, context, grant, supervisor, setTime(value) { now = value; }};
}

async function cleanup(f, supervisors) {
  for (const supervisor of supervisors) await supervisor.stop();
  if (fs.existsSync(f.config.paths.root)) removeScratch(f.config.paths.root);
}

test('QA real fixed child start is idempotent and graceful restart restores the exact local fixture cursor', async () => {
  const f = setup(), first = f.supervisor(), supervisors = [first];
  const secretMarker = 'SYNTHETIC_PRIVATE_MAIL_BODY';
  try {
    const started = await first.start({workload_id: 'SYNTHETIC_PRIVATE_CV', initial_cursor: {offset: 7, body: secretMarker}});
    assert.equal(started.status, 'RUNNING');
    assert.equal(started.ready, false);
    assert.equal(started.live_ready, false);
    assert.equal(started.fixture_ready, true);
    assert.equal(JSON.stringify(started).includes('SYNTHETIC_PRIVATE'), false);
    const repeated = await first.start();
    assert.equal(repeated.generation, started.generation);
    const cursor = {offset: 8, body: secretMarker};
    first.checkpoint(cursor); cursor.offset = 999;
    assert.equal(first.readFixtureCursor().offset, 8);
    await first.stop();
    const second = f.supervisor(); supervisors.push(second);
    const restarted = await second.start({workload_id: 'SYNTHETIC_PRIVATE_CV', initial_cursor: {offset: 0}});
    assert.equal(restarted.status, 'RUNNING');
    assert.equal(second.readFixtureCursor().offset, 8);
    assert.equal(second.readFixtureCursor().body, secretMarker);
    assert.equal(fs.existsSync(f.config.paths.pgdata), false);
    await assert.rejects(second.start({workload_id: 'other-workload'}), error => error.code === 'C1_WORKLOAD_SCOPE_MISMATCH');
    assert.equal(second.readFixtureCursor().offset, 8);
  } finally { await cleanup(f, supervisors); }
});

test('QA real child crash consumes bounded restart allowance and stop cannot reset exhaustion', async () => {
  const f = setup(), first = f.supervisor(), supervisors = [first];
  try {
    await first.start({workload_id: 'qa-crash', initial_cursor: {offset: 4}});
    assert.equal((await first.crashFixture()).status, 'CRASHED');
    const resumed = await first.start();
    assert.equal(resumed.status, 'RUNNING');
    assert.equal(resumed.restarts, 1);
    assert.deepEqual(first.readFixtureCursor(), {offset: 4});
    await first.crashFixture();
    const blocked = await first.start();
    assert.equal(blocked.status, 'WAIT');
    assert.equal(blocked.reason, 'RESTART_LIMIT');
    await first.stop();
    const second = f.supervisor(); supervisors.push(second);
    const persistedLimit = await second.start();
    assert.equal(persistedLimit.status, 'WAIT');
    assert.equal(persistedLimit.reason, 'RESTART_LIMIT');
    assert.deepEqual(second.readFixtureCursor(), {offset: 4});
  } finally { await cleanup(f, supervisors); }
});

test('QA vault outage and revocation hold the exact cursor rather than clearing or advancing it', async () => {
  const f = setup(), supervisor = f.supervisor();
  try {
    await supervisor.start({workload_id: 'qa-vault-wait', initial_cursor: {offset: 12}});
    supervisor.checkpoint({offset: 13});
    f.vault.setAvailable(false);
    c1Denied(() => supervisor.checkpoint({offset: 99}), 'C1_CHECKPOINT_VAULT_WAIT');
    assert.deepEqual(supervisor.readFixtureCursor(), {offset: 13});
    const waiting = await supervisor.start();
    assert.equal(waiting.status, 'WAIT');
    assert.equal(waiting.reason, 'VAULT_UNAVAILABLE');
    assert.deepEqual(supervisor.readFixtureCursor(), {offset: 13});
    f.vault.setAvailable(true);
    assert.equal((await supervisor.start()).status, 'RUNNING');
    assert.deepEqual(supervisor.readFixtureCursor(), {offset: 13});
    f.vault.revoke(f.grant.grant_id, f.context('owner'));
    assert.equal((await supervisor.start()).reason, 'VAULT_REVOKED');
    assert.deepEqual(supervisor.readFixtureCursor(), {offset: 13});
  } finally { await cleanup(f, [supervisor]); }
});

test('QA a second supervisor cannot claim an already owned local namespace', async () => {
  const f = setup(), first = f.supervisor(), second = f.supervisor();
  try {
    await first.start({workload_id: 'qa-exclusive', initial_cursor: {offset: 3}});
    await assert.rejects(second.start(), error => error.code === 'C1_SUPERVISOR_ALREADY_OWNED');
    assert.deepEqual(first.readFixtureCursor(), {offset: 3});
    assert.equal(first.status().status, 'RUNNING');
  } finally { await cleanup(f, [first, second]); }
});

test('QA corrupted local checkpoint holds on recovery and never silently resets its workload', async () => {
  const f = setup(), first = f.supervisor(), supervisors = [first];
  try {
    await first.start({workload_id: 'qa-corrupt', initial_cursor: {offset: 15}});
    await first.stop();
    const filename = path.join(f.config.paths.state, 'lifecycle.json');
    const saved = JSON.parse(fs.readFileSync(filename, 'utf8'));
    saved.body.cursor = {offset: 0};
    fs.writeFileSync(filename, JSON.stringify(saved));
    const second = f.supervisor(); supervisors.push(second);
    await assert.rejects(second.start(), error => error.code === 'C1_CHECKPOINT_INTEGRITY_FAILED');
    assert.equal(JSON.parse(fs.readFileSync(filename, 'utf8')).body.cursor.offset, 0);
    assert.equal(fs.existsSync(f.config.paths.pgdata), false);
  } finally { await cleanup(f, supervisors); }
});

test('QA independent object copy/restore verifies bytes, scope and corruption; no DB restore is claimed', () => {
  const config = runtimeConfig();
  try {
    const store = infra.createFixtureObjectStore(config), input = Buffer.from('SYNTHETIC_QA_OBJECT');
    const ref = store.put(input); input.fill(0);
    assert.equal(store.read(ref).toString(), 'SYNTHETIC_QA_OBJECT');
    const backup = store.backup(ref);
    assert.equal(backup.database_backup, 'NOT_RUN');
    const objectFile = path.join(config.paths.objects, ref.digest.slice(7) + '.blob');
    fs.unlinkSync(objectFile);
    assert.equal(store.restore(ref).database_restore, 'BLOCKED');
    assert.equal(store.read(ref).toString(), 'SYNTHETIC_QA_OBJECT');
    c1Denied(() => store.read({...ref, scope_digest: 'sha256:' + '0'.repeat(64)}));
    c1Denied(() => store.read({...ref, bytes: ref.bytes + 1}));
    fs.writeFileSync(objectFile, 'CORRUPTED_OBJECT');
    c1Denied(() => store.read(ref));
    assert.equal(fs.existsSync(config.paths.pgdata), false);
    const migrations = infra.migrationPlan(config);
    assert.equal(migrations.execution, 'BLOCKED');
    assert.equal(migrations.migration_test, 'NOT_RUN');
    assert.equal(migrations.runtime_database_connections, 0);
  } finally { if (fs.existsSync(config.paths.root)) removeScratch(config.paths.root); }
});
