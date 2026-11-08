import {digest, immutable, need, exact} from '../../contracts/index.mjs';
import {assertUnprotected, safeRepositoryPath} from '../../executors/coding/contracts.mjs';

// Host policy is deliberately outside the model's write/read allowlist.
export const CODING_HOST_PROTECTED_ROOTS = Object.freeze([
  '.private', '.reference', '.npmrc', '.gitignore', '.node-version',
  'E1', 'awe', 'release', 'tests', 'package.json', 'TOOLS-02', 'QA-02',
  'AUTO-01', 'RT-02', 'FUSE-01', 'DATA-02', 'INTEGRATION-01', 'OWNER-02', 'llm02'
]);
const hash = x => typeof x === 'string' && /^sha256:[a-f0-9]{64}$/.test(x);
export function validateCodingHostPolicy(input) {
  exact(input, ['schema', 'repository', 'issue_digest', 'base_sha', 'path_allowlist', 'read_allowlist', 'test_profile_digest', 'owner_grant_digest', 'model_capability_id']);
  need(input.schema === 'awe.e1.coding-host-policy/1' && hash(input.issue_digest) && hash(input.test_profile_digest) && hash(input.owner_grant_digest), 'CODING_HOST_POLICY');
  exact(input.repository, ['owner', 'name']);
  need(/^[a-f0-9]{40}$/.test(input.base_sha) && input.model_capability_id === 'e1.coding.patch', 'CODING_HOST_POLICY_SCOPE');
  for (const key of ['path_allowlist', 'read_allowlist']) {
    need(Array.isArray(input[key]) && input[key].length > 0 && input[key].length <= 32 && new Set(input[key]).size === input[key].length, 'CODING_HOST_POLICY_PATHS');
    for (const p of input[key]) { safeRepositoryPath(p); assertUnprotected(p, CODING_HOST_PROTECTED_ROOTS); }
  }
  need(input.path_allowlist.every(p => input.read_allowlist.includes(p)), 'CODING_HOST_POLICY_READ_SCOPE');
  return immutable(input);
}
export function assertCodingPolicy(grant, policy) {
  validateCodingHostPolicy(policy);
  for (const key of ['repository', 'issue_digest', 'base_sha', 'path_allowlist', 'read_allowlist', 'test_profile_digest'])
    need(digest(grant[key]) === digest(policy[key]), 'CODING_HOST_POLICY_MISMATCH:' + key);
  need(grant.model_capability.capability_id === policy.model_capability_id, 'CODING_HOST_POLICY_CAPABILITY');
}
