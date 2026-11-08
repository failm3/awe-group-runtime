import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {digest} from '../../../contracts/canonical.mjs';
import {validateInfraConfig, preflight, withLocalRoot, canonicalLocalPath, loadInfraConfig, createReleaseManifest, validateReleaseManifest, migrationPlan, createFixtureSupervisor, sanitizedStatus} from '../../infra/index.mjs';
import {scratch, template} from './fixtures/helpers.mjs';

test('portable template requires explicit local root; preflight performs no writes', t => {
  assert.equal(template.paths.root, '${E1_ROOT}');
  assert.throws(() => validateInfraConfig(template), /C1_ABSOLUTE_PATH_REQUIRED/);
  const {config, root} = scratch(t);
  const before = fs.readdirSync(root);
  const report = preflight(config);
  assert.equal(report.isolation, 'PASS'); assert.equal(report.ready, false); assert.equal(report.live_ready, false);
  assert.ok(report.blockers.includes('E1_POSTGRESQL_NOT_AUTHORIZED'));
  assert.deepEqual(report.performed, {database_connections: 0, clusters_created: 0, services_started: 0, model_calls: 0, external_effects: 0});
  assert.deepEqual(fs.readdirSync(root), before); assert.ok(Object.isFrozen(config.principals.worker));
});

test('rejects historical projects, origins, database identities and unsafe switches', t => {
  const {config} = scratch(t);
  const attacks = [c => c.project_id = 'prj_master01', c => c.project_id = 'project_e0', c => c.origin = 'https://master01.invalid',
    c => c.origin = 'https://awe-e1.invalid@e0.invalid', c => c.origin = 'https://awe-e1.invalid/private', c => c.origin = 'https://awe-e1.invalid?secret=bad',
    c => c.origin = 'http://127.0.0.1:5432', c => c.origin = 'https://awe-e1.invalid:443',
    c => c.database.name = 'master01', c => c.database.host = 'localhost', c => c.database.enabled = true, c => c.database.port = 5432,
    c => c.database.dsn = 'postgres://PRIVATE_SENTINEL', c => c.mode = 'LIVE', c => c.composition = 'AUTO01_MOCK_ONLY',
    c => c.model.enabled = true, c => c.model.endpoint = 'https://cloud.invalid', c => c.source_commit = 'f'.repeat(40),
    c => c.principals.qa.principal_id = c.principals.worker.principal_id,
    c => c.principals.qa.os_account_ref = c.principals.worker.os_account_ref];
  for (const mutate of attacks) { const changed = structuredClone(config); mutate(changed); assert.throws(() => validateInfraConfig(changed), /^InfraError: C1_/); }
});

test('path traversal, Windows aliases, E0 and storage overlap fail closed', t => {
  const {config} = scratch(t);
  const attacks = ['C:/Users/1/.codex/worktrees/92EF/AWE-GROUP-INT04/pgdata', 'C:/temp/awe_e1/a/../pgdata',
    'C:/temp/awe_e1/pgdata.', 'C:/temp/awe_e1/pgdata ', '\\\\?\\C:\\temp\\awe_e1', '\\\\host\\share\\awe_e1',
    'C:/temp/AWEE1~1/pgdata', 'C:/temp/awe_e1/state:secret', 'C:/temp/awe_e1/con.txt', 'file:///C:/temp/awe_e1',
    'C:/temp/awe_e1/%2e%2e/pgdata', 'C:relative', '/tmp/awe-e1/./state'];
  for (const attack of attacks) assert.throws(() => canonicalLocalPath(attack), /^InfraError: C1_/);
  for (const name of ['state', 'objects', 'backup', 'pgdata']) {
    const changed = structuredClone(config); changed.paths[name] = path.dirname(config.paths.root);
    assert.throws(() => validateInfraConfig(changed), /C1_PATH_OUTSIDE_NAMESPACE/);
  }
  const changed = structuredClone(config); changed.paths.backup = path.join(changed.paths.objects, 'nested');
  assert.throws(() => validateInfraConfig(changed), /C1_STORAGE_OVERLAP/);
});

test('actual filesystem junction/symlink aliases are denied when platform permits', t => {
  const {config, root} = scratch(t);
  const other = path.join(root, 'other'); fs.mkdirSync(other);
  const linked = path.join(root, 'linked');
  try { fs.symlinkSync(other, linked, process.platform === 'win32' ? 'junction' : 'dir'); }
  catch (error) { if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error.code)) { t.skip('junction/symlink creation denied by host; NOT_RUN'); return; } throw error; }
  const changed = structuredClone(config); changed.paths.state = linked;
  assert.throws(() => validateInfraConfig(changed), /C1_(LINK_PATH|PATH_ALIAS)_DENIED/);
});

test('actual hardlinked config is denied when platform permits', t => {
  const {config, root} = scratch(t);
  const original = path.join(root, 'original.json'), alias = path.join(root, 'alias.json');
  fs.writeFileSync(original, JSON.stringify(config));
  try { fs.linkSync(original, alias); }
  catch (error) { if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error.code)) { t.skip('hardlink creation denied by host; NOT_RUN'); return; } throw error; }
  assert.throws(() => loadInfraConfig(alias), /C1_CONFIG_FILE_DENIED/);
});

test('config load has bounded bytes, strict keys and sanitized failures', t => {
  const {config, root} = scratch(t);
  const filename = path.join(root, 'config.json'); fs.writeFileSync(filename, JSON.stringify(config));
  assert.equal(loadInfraConfig(filename).composition, 'AWE_E1');
  fs.writeFileSync(filename, '{PRIVATE_SENTINEL');
  assert.throws(() => loadInfraConfig(filename), error => error.code === 'C1_CONFIG_FILE_DENIED' && !error.message.includes('PRIVATE_SENTINEL'));
});

test('release manifest is deterministic, immutable, pinned and tamper-evident', t => {
  const {config} = scratch(t), build_digest = digest({fixture: 'C1'});
  const manifest = createReleaseManifest({config, build_digest, registry_version: 'registry/1', policy_version: 'policy/1'});
  assert.deepEqual(manifest, createReleaseManifest({config, build_digest, registry_version: 'registry/1', policy_version: 'policy/1'}));
  assert.equal(manifest.migration_status, 'BLOCKED'); assert.equal(manifest.authority_uptime, 'UNKNOWN');
  for (const field of ['release', 'source_commit', 'live_ready', 'model_status', 'manifest_digest', 'project_id', 'namespace']) {
    const changed = structuredClone(manifest); changed[field] = field === 'live_ready' ? true : 'tampered';
    assert.throws(() => createFixtureSupervisor({config, manifest: changed}), /^InfraError: C1_/);
  }
  const forged = {...manifest, live_ready: true}; delete forged.manifest_digest; forged.manifest_digest = digest(forged);
  assert.throws(() => validateReleaseManifest(config, forged), /C1_MANIFEST_INTEGRITY_FAILED/);
});

test('migration plan is text-only, pinned and explicitly NOT_RUN', t => {
  const {config} = scratch(t); const plan = migrationPlan(config);
  assert.equal(plan.execution, 'BLOCKED'); assert.equal(plan.migration_test, 'NOT_RUN'); assert.equal(plan.postgres_restore_test, 'NOT_RUN');
  assert.equal(plan.files.length, 2); assert.equal(plan.runtime_database_connections, 0);
  for (const file of plan.files) assert.match(file.digest, /^sha256:[a-f0-9]{64}$/);
  assert.ok(plan.strategy.includes('PRESERVE_D03_D09_AND_OUTBOX'));
});

test('health/status allowlists fields and hashes all active workload references', () => {
  const status = sanitizedStatus({status: 'RUNNING', reason: 'FIXTURE_RUNNING', workload_digest: 'PRIVATE_CV_SENTINEL', cursor_digest: 'PRIVATE_EMAIL_SENTINEL',
    raw: {cv: 'PRIVATE_CV_SENTINEL'}, env: {key: 'PRIVATE_KEY_SENTINEL'}, receipt: 'PRIVATE_RECEIPT_SENTINEL', live_ready: true});
  const json = JSON.stringify(status);
  assert.ok(!json.includes('PRIVATE_')); assert.equal(status.live_ready, false); assert.equal(status.ready, false);
  assert.deepEqual(status.active_workload, {workload_digest: null, cursor_digest: null});
});
