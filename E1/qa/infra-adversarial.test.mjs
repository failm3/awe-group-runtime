import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {infra, digest} from '../index.mjs';
import {independentConfig as config, removeScratch} from './helpers.mjs';

function reject(mutate, code) {
  const candidate = config();
  mutate(candidate);
  assert.throws(() => infra.validateInfraConfig(candidate), error => error?.code?.startsWith('C1_') && (!code || error.code === code));
}

test('QA C1 positive preflight validates only; no storage or services are created', () => {
  const input = config();
  const before = JSON.stringify(input);
  const valid = infra.validateInfraConfig(input);
  const result = infra.preflight(input);
  assert.equal(JSON.stringify(input), before);
  assert.ok(Object.isFrozen(valid));
  assert.ok(Object.isFrozen(valid.paths));
  assert.equal(fs.existsSync(input.paths.root), false);
  assert.equal(result.ready, false);
  assert.equal(result.live_ready, false);
  assert.equal(result.fixture_ready, true);
  assert.deepEqual(result.performed, {database_connections: 0, clusters_created: 0, services_started: 0, model_calls: 0, external_effects: 0});
  assert.ok(result.blockers.includes('E1_POSTGRESQL_NOT_AUTHORIZED'));
});

for (const [label, mutate] of [
  ['extra DSN', c => { c.database.dsn = 'postgresql://127.0.0.1/forbidden'; }],
  ['DB enabled', c => { c.database.enabled = true; }],
  ['historical DB', c => { c.database.name = 'awe_e0_master01'; }],
  ['historical namespace', c => { c.namespace = 'awe_e1_master01'; }],
  ['historical project', c => { c.project_id = 'prj_e0'; }],
  ['remote DB host', c => { c.database.host = 'awe-e1.invalid'; }],
  ['historical low port', c => { c.database.port = 5432; }],
  ['wrong source pin', c => { c.source_commit = 'c53d1fb3606218a4f3961f37f57ebc41ac6681ef'; }],
  ['live mode', c => { c.mode = 'LIVE'; }],
  ['historical composition', c => { c.composition = 'AUTO01_MOCK_ONLY'; }],
  ['model enabled', c => { c.model.enabled = true; }],
  ['private model endpoint', c => { c.model.endpoint = 'https://private.invalid'; }],
  ['QA worker same identity', c => { c.principals.qa.principal_id = c.principals.worker.principal_id; }],
  ['QA worker same OS account', c => { c.principals.qa.os_account_ref = c.principals.worker.os_account_ref; }],
  ['prototype shape', c => { Object.setPrototypeOf(c.paths, {escape: true}); }],
  ['hidden field', c => { Object.defineProperty(c, 'private_body', {value: 'PRIVATE_SYNTHETIC', enumerable: false}); }],
  ['excessive restarts', c => { c.supervisor.max_restarts = 999; }],
  ['storage overlap', c => { c.paths.backup = c.paths.objects; }],
  ['nested PG storage', c => { c.paths.objects = path.join(c.paths.pgdata, 'objects'); }],
  ['escaped state', c => { c.paths.state = path.dirname(c.paths.root); }],
  ['relative root', c => { c.paths.root = 'relative/awe-e1-qa'; }],
  ['path traversal', c => { c.paths.state = c.paths.root + path.sep + '..' + path.sep + 'state'; }],
  ['E0 original', c => { c.paths.root = 'C:\\Users\\1\\.codex\\worktrees\\92ef\\AWE-GROUP-INT04'; }],
  ['E0 case alias', c => { c.paths.root = 'c:\\users\\1\\.codex\\WORKTREES\\92EF\\awe-group-int04'; }],
  ['device path', c => { c.paths.root = '\\\\?\\C:\\Users\\1\\AppData\\Local\\Temp\\awe-e1-qa'; }],
  ['UNC path', c => { c.paths.root = '\\\\localhost\\C$\\awe-e1-qa'; }],
  ['file URL path', c => { c.paths.root = 'file:///C:/awe-e1-qa'; }],
  ['drive relative', c => { c.paths.root = 'C:awe-e1-qa'; }],
  ['trailing dot alias', c => { c.paths.state += '.'; }],
  ['trailing space alias', c => { c.paths.state += ' '; }],
  ['Windows stream', c => { c.paths.state += ':stream'; }],
  ['reserved device', c => { c.paths.state = path.join(c.paths.root, 'CON.txt'); }],
  ['short-name alias', c => { c.paths.state = path.join(c.paths.root, 'STATE~1'); }],
  ['encoded traversal', c => { c.paths.state = path.join(c.paths.root, '%2e%2e', 'state'); }],
]) test('QA C1 rejects config attack: ' + label, () => reject(mutate));

for (const origin of [
  'https://awe-e1.invalid.evil.invalid', 'https://worker@qa.awe-e1.invalid',
  'https://qa.awe-e1.invalid:443', 'http://qa.awe-e1.invalid',
  'https://qa.awe-e1.invalid/path', 'https://qa.awe-e1.invalid?private=1',
  'https://qa.awe-e1.invalid#private', 'https://qa.awe-e1.invalid.',
  'https://QA.awe-e1.invalid', 'https://qa%2eawe-e1.invalid',
  'https://qa.awe-e1.invalid\\@evil.invalid', 'https://e0.awe-e1.invalid',
]) test('QA C1 rejects noncanonical or out-of-scope origin: ' + origin, () => reject(c => { c.origin = origin; }));

test('QA C1 rejects an existing junction/symlink without following its storage', t => {
  const input = config();
  fs.mkdirSync(input.paths.root);
  try {
    const target = path.join(input.paths.root, 'target');
    fs.mkdirSync(target);
    const alias = path.join(input.paths.root, 'alias');
    try { fs.symlinkSync(target, alias, process.platform === 'win32' ? 'junction' : 'dir'); }
    catch (error) {
      if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error.code)) {
        t.skip('NOT_RUN: environment denies creation of a real junction/symlink (' + error.code + ')');
        return;
      }
      throw error;
    }
    fs.writeFileSync(path.join(target, 'sentinel.txt'), 'UNCHANGED');
    input.paths.state = path.join(alias, 'state');
    assert.throws(() => infra.validateInfraConfig(input), error => /^C1_(?:LINK_PATH|PATH_ALIAS)_DENIED$/.test(error.code));
    assert.equal(fs.readFileSync(path.join(target, 'sentinel.txt'), 'utf8'), 'UNCHANGED');
  } finally { removeScratch(input.paths.root); }
});

test('QA C1 supervisor rejects a manifest whose release body was altered after hashing', () => {
  const input = config();
  const original = infra.createReleaseManifest({config: input});
  const tampered = {...original, release: 'AWE_E0/9', source_commit: '0'.repeat(40), live_ready: true};
  assert.throws(() => infra.createFixtureSupervisor({config: input, manifest: tampered}), error => error?.code?.startsWith('C1_'));
  assert.equal(fs.existsSync(input.paths.root), false);
});

test('QA C1 supervisor rejects a forged manifest digest on an otherwise valid body', () => {
  const input = config();
  const original = infra.createReleaseManifest({config: input});
  assert.throws(() => infra.createFixtureSupervisor({config: input, manifest: {...original, manifest_digest: 'sha256:' + '0'.repeat(64)}}), error => error?.code?.startsWith('C1_'));
  assert.equal(fs.existsSync(input.paths.root), false);
});

test('QA C1 recomputing a tampered manifest checksum cannot override fixed release pins', () => {
  const input = config(), original = infra.createReleaseManifest({config: input});
  const body = {...original, source_commit: '0'.repeat(40), release: 'AWE_E0/9'};
  delete body.manifest_digest;
  assert.throws(() => infra.createFixtureSupervisor({config: input, manifest: {...body, manifest_digest: digest(body)}}), error => error?.code?.startsWith('C1_'));
  assert.equal(fs.existsSync(input.paths.root), false);
});

test('QA C1 health projection excludes synthetic PII in every untrusted field', () => {
  const marker = 'SYNTHETIC_PRIVATE_CV_EMAIL_BODY_KEY';
  const status = infra.sanitizedStatus({status: marker, reason: marker, manifest_digest: marker,
    generation: marker, restarts: marker, workload_digest: marker, cursor_digest: marker,
    private_receipt: marker, cv: marker, secret: marker, active_workload: {body: marker}});
  assert.equal(JSON.stringify(status).includes(marker), false);
  assert.equal(status.ready, false);
  assert.equal(status.live_ready, false);
  assert.equal(status.status, 'HOLD');
});
