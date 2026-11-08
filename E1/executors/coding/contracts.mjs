import {createHash} from 'node:crypto';
import {canonicalize, digest, immutable, need, exact, utc, inspectBoundSchema} from '../../contracts/index.mjs';

export const CODING_CONTRACT_VERSION = 'awe.e1.coding-executor/1';
export const CODING_CONTRACT_VERSION_V2 = 'awe.e1.coding-executor/2';
export const CODING_PERMISSIONS = Object.freeze(['issue.read', 'repository.read', 'worktree.create', 'branch.create', 'patch.apply', 'tests.run', 'qa.request', 'draft_pr.prepare']);
export const PROTECTED_ROOTS = Object.freeze(['.git', '.github', '.codex', '.agents', '.aws', '.ssh', '.gitattributes', '.gitmodules', 'contracts', 'baseline', 'E1/contracts', 'E1/coordinator', 'E1/mission', 'E1/broker', 'E1/infra', 'E1/host', 'E1/release', 'E1/executors/coding', 'E1/index.mjs', 'E1/cli.mjs', 'E1/package.json']);
const SHA = /^[a-f0-9]{40}$/;
const HASH = /^sha256:[a-f0-9]{64}$/;
const id = value => typeof value === 'string' && /^[a-z][a-z0-9_.-]{0,79}$/.test(value);
const int = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
export const byteDigest = text => 'sha256:' + createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');

export function safeRepositoryPath(path) {
  need(typeof path === 'string' && path.length > 0 && path.length <= 240 && !/[\\\x00-\x1f\x7f:%?#]/.test(path) && !path.startsWith('/') && !path.endsWith('/'), 'CODING_PATH_UNSAFE');
  const pieces = path.split('/');
  need(pieces.every(piece => piece && piece !== '.' && piece !== '..' && !/[. ]$/.test(piece) && !/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(piece)), 'CODING_PATH_UNSAFE');
  need(!pieces.some(piece => /^\.env(?:\.|$)/i.test(piece) || ['agents.md', 'skill.md'].includes(piece.toLowerCase())), 'CODING_PROTECTED_PATH');
  return path;
}
export function assertUnprotected(path, hostProtectedRoots = []) {
  safeRepositoryPath(path); const lower = path.toLowerCase();
  need(![...PROTECTED_ROOTS, ...hostProtectedRoots].some(root => lower === root.toLowerCase() || lower.startsWith(root.toLowerCase() + '/')), 'CODING_PROTECTED_PATH');
}

/** Data validation is not grant authentication. Only the host authority can resolve an owner grant. */
export function validateCodingTaskGrant(input, {now = new Date().toISOString(), hostProtectedRoots = []} = {}) {
  exact(input, ['contract_version', 'grant_id', 'owner_id', 'project_id', 'mission_id', 'task_id', 'producer_id', 'repository', 'issue_number', 'base_sha', 'branch_prefix', 'path_allowlist', 'model_capability', 'test_capabilities', 'budget', 'issued_at', 'expires_at', 'max_steps', 'max_model_attempts', 'max_patch_bytes', 'max_files', 'permissions']);
  need(input.contract_version === CODING_CONTRACT_VERSION && ['grant_id', 'owner_id', 'project_id', 'mission_id', 'task_id', 'producer_id'].every(key => id(input[key])), 'CODING_GRANT_ID');
  exact(input.repository, ['owner', 'name']);
  need(typeof input.repository.owner === 'string' && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(input.repository.owner) && typeof input.repository.name === 'string' && /^[A-Za-z0-9_.-]{1,100}$/.test(input.repository.name) && !['.', '..'].includes(input.repository.name), 'CODING_REPOSITORY');
  need(int(input.issue_number, 1, 1000000000) && SHA.test(input.base_sha), 'CODING_ISSUE_OR_BASE');
  need(typeof input.branch_prefix === 'string' && /^codex\/(?:[a-z0-9_-]{1,24}\/)?$/.test(input.branch_prefix), 'CODING_BRANCH_PREFIX');
  need(Array.isArray(input.path_allowlist) && input.path_allowlist.length > 0 && input.path_allowlist.length <= 32 && new Set(input.path_allowlist.map(path => typeof path === 'string' ? path.toLowerCase() : path)).size === input.path_allowlist.length, 'CODING_PATH_ALLOWLIST');
  input.path_allowlist.forEach(path => assertUnprotected(path, hostProtectedRoots));
  exact(input.model_capability, ['capability_id', 'version', 'route_id', 'output_schema_digest']);
  need(id(input.model_capability.capability_id) && /^\d+\.\d+\.\d+$/.test(input.model_capability.version) && input.model_capability.route_id === 'ollama.local.qwen3-4b-instruct' && HASH.test(input.model_capability.output_schema_digest), 'CODING_MODEL_CAPABILITY');
  need(Array.isArray(input.test_capabilities) && input.test_capabilities.length > 0 && input.test_capabilities.length <= 8, 'CODING_TEST_CAPABILITIES');
  for (const cap of input.test_capabilities) { exact(cap, ['capability_id', 'version', 'command_digest', 'timeout_ms']); need(id(cap.capability_id) && /^\d+\.\d+\.\d+$/.test(cap.version) && HASH.test(cap.command_digest) && int(cap.timeout_ms, 1, 120000), 'CODING_TEST_CAPABILITY'); }
  need(new Set(input.test_capabilities.map(x => x.capability_id)).size === input.test_capabilities.length, 'CODING_TEST_DUPLICATE');
  exact(input.budget, ['currency', 'amount_micros']); need(input.budget.currency === 'NONE' && input.budget.amount_micros === 0, 'CODING_PAID_ROUTE_DENIED');
  utc(input.issued_at); utc(input.expires_at); utc(now); need(input.issued_at <= now && now < input.expires_at, 'CODING_GRANT_EXPIRED');
  need(int(input.max_steps, 1, 24) && input.max_model_attempts === 1 && int(input.max_patch_bytes, 1, 32768) && int(input.max_files, 1, 16) && input.max_files <= input.path_allowlist.length, 'CODING_GRANT_BOUNDS');
  need(Array.isArray(input.permissions) && input.permissions.length === CODING_PERMISSIONS.length && new Set(input.permissions).size === input.permissions.length && CODING_PERMISSIONS.every(permission => input.permissions.includes(permission)), 'CODING_PERMISSION_DENIED');
  return immutable(input);
}

/** Additive host-bound contract. V1 remains readable for offline replay. */
export function validateCodingTaskGrantV2(input, options = {}) {
  need(input?.contract_version === CODING_CONTRACT_VERSION_V2, 'CODING_V2_REQUIRED');
  const {issue_digest, read_allowlist, test_profile_digest, ...legacy} = input;
  validateCodingTaskGrant({...legacy, contract_version: CODING_CONTRACT_VERSION}, options);
  need(HASH.test(issue_digest) && HASH.test(test_profile_digest), 'CODING_V2_DIGEST');
  need(Array.isArray(read_allowlist) && read_allowlist.length > 0 && read_allowlist.length <= 32 &&
    new Set(read_allowlist.map(p => typeof p === 'string' ? p.toLowerCase() : p)).size === read_allowlist.length, 'CODING_READ_ALLOWLIST');
  read_allowlist.forEach(p => assertUnprotected(p, options.hostProtectedRoots ?? []));
  need(input.path_allowlist.every(p => read_allowlist.includes(p)), 'CODING_READ_SCOPE');
  return immutable(input);
}

export function validateCodingGrant(input, options = {}) {
  return input?.contract_version === CODING_CONTRACT_VERSION_V2
    ? validateCodingTaskGrantV2(input, options) : validateCodingTaskGrant(input, options);
}

export function validatePatchProposal(proposal, {grant, baseline, hostProtectedRoots = []}) {
  exact(proposal, ['base_sha', 'summary', 'changes']); need(proposal.base_sha === grant.base_sha && baseline?.base_sha === grant.base_sha, 'CODING_BASE_SHA_MISMATCH');
  need(typeof proposal.summary === 'string' && proposal.summary.trim().length > 0 && proposal.summary.length <= 1024 && Array.isArray(proposal.changes) && proposal.changes.length > 0 && proposal.changes.length <= grant.max_files, 'CODING_PATCH_BOUNDS');
  need(Array.isArray(baseline.files), 'CODING_BASELINE_REQUIRED');
  const byPath = new Map(baseline.files.map(file => [file.path, file]));
  const seen = new Set(); let bytes = 0;
  const changes = proposal.changes.map(change => {
    exact(change, ['path', 'before_digest', 'after_text']); assertUnprotected(change.path, hostProtectedRoots);
    need(grant.path_allowlist.includes(change.path) && !seen.has(change.path.toLowerCase()), 'CODING_PATH_DENIED'); seen.add(change.path.toLowerCase());
    const before = byPath.get(change.path);
    need(before && before.ancestry_verified === true && before.ancestor_symlinks === false && ['file', 'missing'].includes(before.kind) && (before.kind === 'missing' || ['100644', '100755'].includes(before.mode)), 'CODING_SYMLINK_OR_BASELINE_DENIED');
    if (before.kind === 'missing') need(change.before_digest === 'ABSENT' && before.digest === null, 'CODING_BEFORE_DIGEST');
    else need(HASH.test(change.before_digest) && change.before_digest === before.digest && typeof before.content_utf8 === 'string' && byteDigest(before.content_utf8) === before.digest, 'CODING_BEFORE_DIGEST');
    need(typeof change.after_text === 'string' && !change.after_text.includes('\0') && Buffer.from(change.after_text, 'utf8').toString('utf8') === change.after_text && Buffer.byteLength(change.after_text, 'utf8') <= 65536, 'CODING_PATCH_ENCODING');
    bytes += Buffer.byteLength(change.after_text, 'utf8'); need(bytes <= grant.max_patch_bytes, 'CODING_PATCH_BYTE_LIMIT');
    const after_digest = byteDigest(change.after_text); need(after_digest !== change.before_digest, 'CODING_NO_CHANGE');
    return {path: change.path, before_digest: change.before_digest, after_text: change.after_text, after_digest};
  });
  const value = {base_sha: proposal.base_sha, summary: proposal.summary, changes, patch_bytes: bytes};
  return immutable({...value, patch_digest: digest(value)});
}

export const PATCH_PROPOSAL_SCHEMA = inspectBoundSchema({type: 'object', properties: {base_sha: {type: 'string', minLength: 40, maxLength: 40, pattern: '^[a-f0-9]{40}$'}, summary: {type: 'string', minLength: 1, maxLength: 1024}, changes: {type: 'array', minItems: 1, maxItems: 16, items: {type: 'object', properties: {path: {type: 'string', minLength: 1, maxLength: 240}, before_digest: {type: 'string', minLength: 6, maxLength: 71, pattern: '^(?:sha256:[a-f0-9]{64}|ABSENT)$'}, after_text: {type: 'string', maxLength: 65536}}, required: ['path', 'before_digest', 'after_text'], additionalProperties: false}}}, required: ['base_sha', 'summary', 'changes'], additionalProperties: false});
export const PATCH_PROPOSAL_SCHEMA_DIGEST = digest(PATCH_PROPOSAL_SCHEMA);
export function freezeCodingArtifact(value) { canonicalize(value); return immutable({...value, artifact_digest: digest(value), accepted: false}); }
