import test from 'node:test';
import assert from 'node:assert/strict';
import {createScopedVault} from '../../infra/index.mjs';
import {scratch, context, vaultFixture} from './fixtures/helpers.mjs';

test('scoped handles separate issuer/worker/QA and never disclose credentials', t => {
  const {config} = scratch(t), {vault, issuer, worker, qa, owner, grants} = vaultFixture(config);
  const workerHandle = vault.issueHandle('grant_e1_worker', issuer), qaHandle = vault.issueHandle('grant_e1_qa', issuer);
  assert.equal(vault.resolveHandle(structuredClone(workerHandle), worker).status, 'READY');
  assert.equal(vault.resolveHandle(qaHandle, qa).binding.purpose, 'qa-signing');
  assert.throws(() => vault.resolveHandle(qaHandle, worker), /C1_VAULT_PRINCIPAL_DENIED/);
  assert.throws(() => vault.issueHandle('grant_e1_worker', worker), /C1_VAULT_ISSUER_REQUIRED/);
  assert.throws(() => vault.revoke(workerHandle.handle_id, worker), /C1_VAULT_OWNER_REQUIRED/);
  assert.throws(() => vault.resolveHandle({...workerHandle, scope_digest: 'sha256:' + '0'.repeat(64)}, worker), /C1_VAULT_HANDLE_DENIED/);
  grants[0].principal_id = qa.principal_id;
  assert.equal(vault.resolveHandle(workerHandle, worker).status, 'READY');
  for (const caller of [{...worker, project_id: 'prj_e1_product'}, {...worker, origin: 'https://other.awe-e1.invalid'}, {...worker, principal_id: 'id_e1_unknown'}])
    assert.throws(() => vault.resolveHandle(workerHandle, caller), /^InfraError: C1_/);
  const output = vault.resolveHandle(workerHandle, worker);
  assert.equal(output.live_ready, false); assert.equal(output.authenticated_os_principal, false);
  assert.ok(!JSON.stringify(output).includes('secret'));
  assert.equal(vault.revoke(workerHandle.handle_id, owner).status, 'WAIT');
  assert.equal(vault.resolveHandle(workerHandle, worker).reason, 'VAULT_REVOKED');
});

test('vault unavailability/expiry and backwards clock never reactivate a handle', t => {
  const {config} = scratch(t); let clock = 1000;
  const {vault, issuer, worker} = vaultFixture(config, {now: () => clock});
  const handle = vault.issueHandle('grant_e1_worker', issuer);
  vault.setAvailable(false); assert.equal(vault.resolveHandle(handle, worker).reason, 'VAULT_UNAVAILABLE');
  vault.setAvailable(true); clock = 2000; assert.equal(vault.resolveHandle(handle, worker).reason, 'VAULT_GRANT_EXPIRED');
  clock = 1001; assert.throws(() => vault.resolveHandle(handle, worker), /C1_VAULT_CLOCK_INVALID/);
  assert.throws(() => vault.issueHandle('grant_e1_worker', issuer), /C1_VAULT_CLOCK_INVALID/);
});

test('vault refuses undeclared principals, wrong role/origin grants and raw secret fields', t => {
  const {config} = scratch(t), {grants} = vaultFixture(config);
  for (const mutate of [g => g.principal_id = 'id_e1_unknown', g => g.purpose = 'unknown', g => g.purpose = 'qa-signing',
    g => g.origin = 'https://foreign.invalid', g => g.project_id = 'prj_master01', g => g.secret = 'PRIVATE_KEY_SENTINEL']) {
    const changed = structuredClone(grants); mutate(changed[0]);
    assert.throws(() => createScopedVault({config, grants: changed}), /^InfraError: C1_/);
  }
  const unavailable = createScopedVault({config, grants, now: () => 1000});
  assert.deepEqual(unavailable.issueHandle('grant_e1_worker', context(config, 'issuer')), {status: 'WAIT', reason: 'VAULT_UNAVAILABLE', kind: 'SCOPED_HANDLE_FIXTURE', live_ready: false});
});
