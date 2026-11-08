import {canonicalize, digest} from '../../contracts/canonical.mjs';
import {COMPOSITION, RELEASE, E0_RUNTIME_COMMIT, validateInfraConfig, LIVE_BLOCKERS} from './config.mjs';
import {deepFreeze, deny, exactKeys} from './errors.mjs';

const hash = value => value === null || /^sha256:[0-9a-f]{64}$/.test(value ?? '');
const version = value => value === null || (typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_./-]{0,63}$/.test(value));

export function createReleaseManifest(input) {
  exactKeys(input, ['config'], ['build_digest', 'registry_version', 'policy_version']);
  const config = validateInfraConfig(input.config);
  const build_digest = input.build_digest ?? null, registry_version = input.registry_version ?? null, policy_version = input.policy_version ?? null;
  if (!hash(build_digest) || !version(registry_version) || !version(policy_version)) deny('C1_MANIFEST_INVALID');
  const body = {schema: 'awe-e1.release-manifest.v1', composition: COMPOSITION, release: RELEASE,
    source_commit: config.source_commit, e0_runtime_source_commit: E0_RUNTIME_COMMIT, build_digest,
    migration_version: '0001', migration_status: 'BLOCKED', model_id: null, model_digest: null, model_status: 'BLOCKED',
    registry_version, policy_version, worker_ids: [config.principals.worker.principal_id],
    namespace: config.namespace, project_id: config.project_id,
    identity_status: 'DECLARED_NOT_PROVISIONED', vault_status: 'REAL_VAULT_NOT_BOUND', authority_uptime: 'UNKNOWN',
    live_ready: false, independent_acceptance: 'NOT_SUBMITTED', blockers: [...LIVE_BLOCKERS]};
  return deepFreeze({...body, manifest_digest: digest(body)});
}

export function validateReleaseManifest(config, manifest) {
  try { canonicalize(manifest); } catch { deny('C1_MANIFEST_INVALID'); }
  const expected = createReleaseManifest({config, build_digest: manifest.build_digest,
    registry_version: manifest.registry_version, policy_version: manifest.policy_version});
  if (canonicalize(manifest) !== canonicalize(expected)) deny('C1_MANIFEST_INTEGRITY_FAILED');
  return expected;
}

const states = new Set(['STOPPED', 'STARTING', 'RUNNING', 'WAIT', 'HOLD', 'CRASHED']);
const reasons = new Set(['IDLE', 'FIXTURE_RUNNING', 'FIXTURE_STOPPED', 'FIXTURE_CRASHED', 'VAULT_UNAVAILABLE', 'VAULT_REVOKED', 'VAULT_GRANT_EXPIRED', 'RESTART_LIMIT', 'STORAGE_FAILURE', 'CHECKPOINT_INVALID', 'START_FAILED']);
// Never spread arbitrary state or errors into a health projection.
export function sanitizedStatus(input = {}) {
  const hashOrNull = value => typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value) ? value : null;
  const count = value => Number.isSafeInteger(value) && value >= 0 && value <= 1000000 ? value : 0;
  return deepFreeze({schema: 'awe-e1.health.v1', composition: COMPOSITION, release: RELEASE,
    kind: 'LOCAL_PROCESS_FIXTURE', status: states.has(input.status) ? input.status : 'HOLD',
    reason: reasons.has(input.reason) ? input.reason : 'CHECKPOINT_INVALID',
    live_ready: false, ready: false, fixture_ready: input.status === 'RUNNING',
    runtime_version: RELEASE, manifest_digest: hashOrNull(input.manifest_digest),
    generation: count(input.generation), restarts: count(input.restarts),
    active_workload: input.workload_digest ? {workload_digest: hashOrNull(input.workload_digest), cursor_digest: hashOrNull(input.cursor_digest)} : null,
    blockers: [...LIVE_BLOCKERS]});
}
