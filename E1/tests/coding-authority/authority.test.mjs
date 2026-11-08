import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../../contracts/index.mjs';
import {createCodingMission} from '../../host/coding/mission.mjs';
import {createCodingGrantAuthority} from '../../host/coding/grant-authority.mjs';
import {CODING_HOST_PROTECTED_ROOTS, validateCodingHostPolicy} from '../../host/coding/policy.mjs';
import {CODING_CONTRACT_VERSION_V2, CODING_PERMISSIONS, PATCH_PROPOSAL_SCHEMA_DIGEST, validateCodingTaskGrantV2} from '../../executors/coding/contracts.mjs';

function fixture({verifyNativeClaim = async () => true} = {}) {
  let now = '2026-11-08T10:00:00.000Z';
  const repository = {owner: 'failm3', name: 'awe-group-runtime'};
  const value = {repository, issue_number: 2001, title: 'Synthetic G1 brief', body: 'Implement the two-file synthetic component. No effects.'};
  const issue = {...value, digest: digest(value)}, profile = 'sha256:' + '1'.repeat(64);
  const f = createCodingMission({run_id: 'authority_test', issue, rubric: {checks: ['schema', 'sources', 'scope'], oracle_commitment: profile}, now, clock: () => now});
  const grant = {contract_version: CODING_CONTRACT_VERSION_V2, grant_id: 'code_authority_test', owner_id: f.spec.owner_id, project_id: f.spec.project_id, mission_id: f.spec.mission_id, task_id: 'code_r01', producer_id: 'e1_worker', repository, issue_number: issue.issue_number, issue_digest: issue.digest, base_sha: 'a'.repeat(40), branch_prefix: 'codex/', path_allowlist: ['normalizer.py', 'cli.py'], read_allowlist: ['normalizer.py', 'cli.py'], test_profile_digest: profile, model_capability: {capability_id: 'e1.coding.patch', version: '1.0.0', route_id: 'ollama.local.qwen3-4b-instruct', output_schema_digest: PATCH_PROPOSAL_SCHEMA_DIGEST}, test_capabilities: [{capability_id: 'e1.coding.public-tests', version: '1.0.0', command_digest: profile, timeout_ms: 20000}], budget: {currency: 'NONE', amount_micros: 0}, issued_at: now, expires_at: f.spec.deadline, max_steps: 16, max_model_attempts: 1, max_patch_bytes: 32768, max_files: 2, permissions: [...CODING_PERMISSIONS]};
  const policy = {schema: 'awe.e1.coding-host-policy/1', repository, issue_digest: issue.digest, base_sha: grant.base_sha, path_allowlist: grant.path_allowlist, read_allowlist: grant.read_allowlist, test_profile_digest: profile, owner_grant_digest: digest(f.grant), model_capability_id: 'e1.coding.patch'};
  const auth = createCodingGrantAuthority({authority: f.authority, spec: f.spec, ownerGrant: f.grant, policy, verifyNativeClaim, clock: () => now});
  return {...f, codingGrant: grant, policy, auth, expire: () => { now = '2026-11-08T13:00:00.000Z'; }};
}
test('host delegation binds existing A1 and an actual claim verifier; validation alone is insufficient', async () => {
  let nativeChecks = 0;
  const f = fixture({verifyNativeClaim: async ({grant, principal}) => { nativeChecks++; return grant.task_id === 'code_r01' && principal.role === 'EXECUTOR'; }});
  const ref = f.auth.issue(f.codingGrant, f.contexts.owner);
  assert.equal((await f.auth.resolve(ref, f.contexts.executor)).issue_digest, f.codingGrant.issue_digest);
  assert.equal(nativeChecks, 1);
  await assert.rejects(f.auth.resolve(ref, {principal_id: 'e1_worker', project_id: f.spec.project_id}), /E1_AUTH_CONTEXT/);
  await assert.rejects(f.auth.resolve(ref, f.contexts.qa), /CODING_EXECUTOR_CONTEXT/);
});
test('negative native claim, revocation and expiry deny execution', async () => {
  const f = fixture({verifyNativeClaim: async () => false}), ref = f.auth.issue(f.codingGrant, f.contexts.owner);
  await assert.rejects(f.auth.resolve(ref, f.contexts.executor), /CODING_NATIVE_CLAIM_REQUIRED/);
  f.auth.revoke(ref, f.contexts.owner); assert.equal(await f.auth.resolve(ref, f.contexts.executor), null);
  const g = fixture(), other = g.auth.issue(g.codingGrant, g.contexts.owner); g.expire();
  await assert.rejects(g.auth.resolve(other, g.contexts.executor));
});
test('immutable task meaning and scope cannot be expanded by producer or owner-context JSON', () => {
  const f = fixture();
  assert.throws(() => f.auth.issue(f.codingGrant, f.contexts.executor), /CODING_OWNER_CONTEXT/);
  assert.throws(() => f.auth.issue({...f.codingGrant, issue_digest: 'sha256:' + '2'.repeat(64)}, f.contexts.owner), /CODING_HOST_POLICY_MISMATCH/);
  assert.throws(() => f.auth.issue({...f.codingGrant, max_model_attempts: 2}, f.contexts.owner), /CODING_GRANT_BOUNDS/);
  assert.throws(() => f.auth.issue({...f.codingGrant, expires_at: '2026-11-08T14:00:00.000Z'}, f.contexts.owner), /CODING_PARENT_SCOPE/);
});
test('private, QA and core paths excluded from both read and write scopes', () => {
  const f = fixture();
  for (const p of ['.private/config.json', 'E1/qa-coding/oracle.mjs', 'E1/host/coding/policy.mjs', 'awe/tool_registry/discovery.mjs', '../cli.py', 'CLI.py/../x']) {
    assert.throws(() => validateCodingTaskGrantV2({...f.codingGrant, read_allowlist: [...f.codingGrant.read_allowlist, p]}, {now: f.codingGrant.issued_at, hostProtectedRoots: CODING_HOST_PROTECTED_ROOTS}));
  }
  assert.throws(() => validateCodingHostPolicy({...f.policy, path_allowlist: ['.private/key']}));
});
test('revoking original principal invalidates the derived credential', async () => {
  const f = fixture(), ref = f.auth.issue(f.codingGrant, f.contexts.owner);
  f.authority.revokePrincipal('e1_owner');
  await assert.rejects(f.auth.resolve(ref, f.contexts.executor), /E1_ACTOR_SCOPE/);
});
