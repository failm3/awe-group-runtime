import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {digest} from '../../../contracts/canonical.mjs';
import {createFixtureSupervisor} from '../../infra/index.mjs';
import {scratch, vaultFixture} from './fixtures/helpers.mjs';

test('real local child start is idempotent and graceful restart retains workload/cursor', async t => {
  const {config} = scratch(t), {vault} = vaultFixture(config);
  const first = createFixtureSupervisor({config, vault});
  try {
    const started = await first.start({workload_id: 'fixture-workload', initial_cursor: {offset: 1, opaque: 'PRIVATE_CURSOR_SENTINEL'}});
    assert.equal(started.status, 'RUNNING'); assert.equal(started.fixture_ready, true); assert.equal(started.ready, false);
    assert.equal(started.generation, 1); assert.equal((await first.start()).generation, 1);
    first.checkpoint({offset: 2, opaque: 'PRIVATE_CURSOR_SENTINEL'});
    const health = first.status(); assert.ok(!JSON.stringify(health).includes('PRIVATE_'));
    assert.equal(health.active_workload.cursor_digest, digest({offset: 2, opaque: 'PRIVATE_CURSOR_SENTINEL'}));
    assert.equal(fs.existsSync(config.paths.pgdata), false);
    await first.stop();
  } finally { await first.stop(); }
  const second = createFixtureSupervisor({config, vault});
  try {
    const restarted = await second.start();
    assert.equal(restarted.status, 'RUNNING'); assert.equal(restarted.generation, 2);
    assert.deepEqual(second.readFixtureCursor(), {offset: 2, opaque: 'PRIVATE_CURSOR_SENTINEL'});
    assert.equal(fs.existsSync(config.paths.pgdata), false);
  } finally { await second.stop(); }
});

test('crashed fixed child recovers within bounded local restart budget', async t => {
  const {config} = scratch(t, c => c.supervisor.max_restarts = 1), {vault} = vaultFixture(config);
  const supervisor = createFixtureSupervisor({config, vault});
  try {
    await supervisor.start({workload_id: 'fixture-crash', initial_cursor: {offset: 7}});
    assert.equal((await supervisor.crashFixture()).status, 'CRASHED');
    const recovered = await supervisor.start();
    assert.equal(recovered.status, 'RUNNING'); assert.equal(recovered.restarts, 1);
    assert.deepEqual(supervisor.readFixtureCursor(), {offset: 7});
    await supervisor.crashFixture();
    assert.equal((await supervisor.start()).reason, 'RESTART_LIMIT');
    vault.setAvailable(false); assert.equal((await supervisor.start()).reason, 'VAULT_UNAVAILABLE');
    vault.setAvailable(true); assert.equal((await supervisor.start()).reason, 'RESTART_LIMIT');
  } finally { await supervisor.stop(); }
});

test('locked/revoked scoped vault causes WAIT without resetting persisted cursor', async t => {
  const {config} = scratch(t), {vault, issuer, worker, owner} = vaultFixture(config, {available: false});
  const waiting = createFixtureSupervisor({config, vault});
  try {
    const initial = await waiting.start({workload_id: 'fixture-wait', initial_cursor: {offset: 11}});
    assert.equal(initial.status, 'WAIT'); assert.equal(initial.reason, 'VAULT_UNAVAILABLE'); assert.equal(initial.generation, 0);
    vault.setAvailable(true); await waiting.start(); waiting.checkpoint({offset: 12});
  } finally { await waiting.stop(); }
  const handle = vault.issueHandle('grant_e1_worker', issuer);
  const scoped = createFixtureSupervisor({config, vault, vault_access: {handle, context: worker}});
  try {
    await scoped.start(); assert.deepEqual(scoped.readFixtureCursor(), {offset: 12});
    vault.revoke(handle.handle_id, owner);
    assert.throws(() => scoped.checkpoint({offset: 13}), /C1_CHECKPOINT_VAULT_WAIT/);
    assert.equal(scoped.status().status, 'WAIT'); assert.equal(scoped.status().reason, 'VAULT_REVOKED');
    assert.deepEqual(scoped.readFixtureCursor(), {offset: 12});
    assert.equal((await scoped.start()).reason, 'VAULT_REVOKED');
  } finally { await scoped.stop(); }
});

test('concurrent supervisor is denied and cannot overwrite owned checkpoint', async t => {
  const {config} = scratch(t), {vault} = vaultFixture(config);
  const first = createFixtureSupervisor({config, vault}), other = createFixtureSupervisor({config, vault});
  try {
    await first.start({workload_id: 'fixture-owner', initial_cursor: {offset: 4}});
    const before = fs.readFileSync(path.join(config.paths.state, 'lifecycle.json'));
    await assert.rejects(other.start(), /C1_SUPERVISOR_ALREADY_OWNED/);
    assert.deepEqual(fs.readFileSync(path.join(config.paths.state, 'lifecycle.json')), before);
  } finally { await first.stop(); await other.stop(); }
});

test('corrupt checkpoint holds without child launch or silent reset', async t => {
  const {config} = scratch(t), {vault} = vaultFixture(config);
  const first = createFixtureSupervisor({config, vault});
  await first.start({workload_id: 'fixture-corruption', initial_cursor: {offset: 15}}); await first.stop();
  const filename = path.join(config.paths.state, 'lifecycle.json'), bytes = JSON.parse(fs.readFileSync(filename, 'utf8'));
  bytes.body.cursor.offset = 999; fs.writeFileSync(filename, JSON.stringify(bytes));
  const other = createFixtureSupervisor({config, vault});
  await assert.rejects(other.start(), /C1_CHECKPOINT_INTEGRITY_FAILED/);
  assert.equal(other.status().generation, 0);
  assert.equal(JSON.parse(fs.readFileSync(filename, 'utf8')).body.cursor.offset, 999);
});

test('live/foreign vault binding is rejected rather than invoked', t => {
  const {config} = scratch(t); let called = 0;
  assert.throws(() => createFixtureSupervisor({config, vault: {kind: 'REAL_VAULT', status() { called++; }} }), /C1_FIXTURE_VAULT_REQUIRED/);
  assert.equal(called, 0);
});
