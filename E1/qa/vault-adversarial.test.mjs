import test from 'node:test';
import assert from 'node:assert/strict';
import {infra} from '../index.mjs';
import {independentConfig, c1Denied} from './helpers.mjs';

function fixture() {
  const config = independentConfig();
  let now = 1000;
  const context = role => ({principal_id: config.principals[role].principal_id, project_id: config.project_id, origin: config.origin});
  const grants = ['worker', 'qa'].map(role => ({grant_id: 'grant_e1_' + role, principal_id: config.principals[role].principal_id,
    project_id: config.project_id, origin: config.origin, purpose: role === 'qa' ? 'qa-signing' : 'worker-data', expires_at: 2000}));
  const vault = infra.createScopedVault({config, grants, now: () => now, available: true});
  return {config, context, vault, grants, setTime: value => { now = value; }};
}

test('QA vault handle is scoped, immutable, and contains no secret or OS authentication claim', () => {
  const f = fixture();
  const handle = f.vault.issueHandle('grant_e1_worker', f.context('issuer'));
  assert.ok(Object.isFrozen(handle));
  assert.deepEqual(Object.keys(handle).sort(), ['handle_id', 'schema', 'scope_digest']);
  const ready = f.vault.resolveHandle(handle, f.context('worker'));
  assert.equal(ready.status, 'READY');
  assert.equal(ready.live_ready, false);
  assert.equal(ready.authenticated_os_principal, false);
  assert.equal(ready.binding.purpose, 'worker-data');
  assert.equal(ready.binding.project_id, f.config.project_id);
  assert.equal(ready.binding.origin, f.config.origin);
});

for (const [label, mutate] of [
  ['wrong role at issuer port', f => c1Denied(() => f.vault.issueHandle('grant_e1_worker', f.context('worker')))],
  ['worker reads QA handle', f => c1Denied(() => f.vault.resolveHandle(f.vault.issueHandle('grant_e1_qa', f.context('issuer')), f.context('worker')))],
  ['QA reads worker handle', f => c1Denied(() => f.vault.resolveHandle(f.vault.issueHandle('grant_e1_worker', f.context('issuer')), f.context('qa')))],
  ['forged handle digest', f => {
    const handle = f.vault.issueHandle('grant_e1_worker', f.context('issuer'));
    c1Denied(() => f.vault.resolveHandle({...handle, scope_digest: 'sha256:' + '0'.repeat(64)}, f.context('worker')));
  }],
  ['handle body extension', f => {
    const handle = f.vault.issueHandle('grant_e1_worker', f.context('issuer'));
    c1Denied(() => f.vault.resolveHandle({...handle, secret: 'SYNTHETIC'}, f.context('worker')));
  }],
  ['worker attempts revocation', f => c1Denied(() => f.vault.revoke('grant_e1_worker', f.context('worker')))],
  ['unknown principal', f => c1Denied(() => f.vault.issueHandle('grant_e1_worker', {...f.context('issuer'), principal_id: 'id_e1_unknown'}))],
  ['cross project', f => c1Denied(() => f.vault.issueHandle('grant_e1_worker', {...f.context('issuer'), project_id: 'project_other'}))],
  ['cross origin', f => c1Denied(() => f.vault.issueHandle('grant_e1_worker', {...f.context('issuer'), origin: 'https://other.awe-e1.invalid'}))],
  ['userinfo origin', f => c1Denied(() => f.vault.issueHandle('grant_e1_worker', {...f.context('issuer'), origin: 'https://worker@qa.awe-e1.invalid'}))],
  ['handle from independent vault', f => {
    const other = fixture();
    const handle = other.vault.issueHandle('grant_e1_worker', other.context('issuer'));
    c1Denied(() => f.vault.resolveHandle(handle, f.context('worker')));
  }],
]) test('QA vault rejects: ' + label, () => mutate(fixture()));

for (const type of ['grant', 'handle']) test('QA vault checks current ' + type + ' revocation at every resolution', () => {
  const f = fixture();
  const handle = f.vault.issueHandle('grant_e1_worker', f.context('issuer'));
  assert.equal(f.vault.resolveHandle(handle, f.context('worker')).status, 'READY');
  f.vault.revoke(type === 'grant' ? 'grant_e1_worker' : handle.handle_id, f.context('owner'));
  const result = f.vault.resolveHandle(handle, f.context('worker'));
  assert.equal(result.status, 'WAIT');
  assert.equal(result.reason, 'VAULT_REVOKED');
  assert.equal(result.binding, undefined);
});

test('QA vault expiry is exclusive, with no cached authorization after clock advancement', () => {
  const f = fixture();
  const handle = f.vault.issueHandle('grant_e1_worker', f.context('issuer'));
  f.setTime(1999);
  assert.equal(f.vault.resolveHandle(handle, f.context('worker')).status, 'READY');
  f.setTime(2000);
  const result = f.vault.resolveHandle(handle, f.context('worker'));
  assert.equal(result.status, 'WAIT');
  assert.equal(result.reason, 'VAULT_GRANT_EXPIRED');
  c1Denied(() => f.vault.issueHandle('grant_e1_worker', f.context('issuer')));
});

test('QA vault outage cannot resolve an issued handle; availability recovery retains its scope', () => {
  const f = fixture();
  const handle = f.vault.issueHandle('grant_e1_worker', f.context('issuer'));
  f.vault.setAvailable(false);
  assert.equal(f.vault.resolveHandle(handle, f.context('worker')).status, 'WAIT');
  assert.equal(f.vault.issueHandle('grant_e1_worker', f.context('issuer')).status, 'WAIT');
  f.vault.setAvailable(true);
  const result = f.vault.resolveHandle(handle, f.context('worker'));
  assert.equal(result.status, 'READY');
  assert.equal(result.binding.project_id, f.config.project_id);
});

test('QA vault snapshots initial grants instead of retaining mutable caller policy', () => {
  const f = fixture();
  f.grants[0].principal_id = f.config.principals.qa.principal_id;
  f.grants[0].expires_at = 999999;
  const handle = f.vault.issueHandle('grant_e1_worker', f.context('issuer'));
  c1Denied(() => f.vault.resolveHandle(handle, f.context('qa')));
  f.setTime(2000);
  assert.equal(f.vault.resolveHandle(handle, f.context('worker')).status, 'WAIT');
});

test('QA vault clock rollback cannot resurrect an expired handle', () => {
  const f = fixture(), handle = f.vault.issueHandle('grant_e1_worker', f.context('issuer'));
  f.setTime(2000);
  assert.equal(f.vault.resolveHandle(handle, f.context('worker')).reason, 'VAULT_GRANT_EXPIRED');
  f.setTime(1500);
  c1Denied(() => f.vault.resolveHandle(handle, f.context('worker')), 'C1_VAULT_CLOCK_INVALID');
});
