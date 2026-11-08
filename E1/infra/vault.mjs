import {randomUUID} from 'node:crypto';
import {digest} from '../../contracts/canonical.mjs';
import {validateInfraConfig, configScope, normalizeOrigin, validateProjectId} from './config.mjs';
import {deepFreeze, deny, exactKeys} from './errors.mjs';

const purposes = Object.freeze({'worker-data': 'worker', 'qa-signing': 'qa', 'issuer-signing': 'issuer', 'coordinator-storage': 'coordinator', 'security-audit': 'security'});

// This is a scoped HANDLE fixture, not a secret store. It accepts no credentials
// and cannot return a signing key. Real OS/vault authentication is unbound.
export function createScopedVault({config: input, grants = [], now = Date.now, available = false} = {}) {
  const config = validateInfraConfig(input), scope = configScope(config);
  if (typeof now !== 'function' || typeof available !== 'boolean' || !Array.isArray(grants) || grants.length > 64) deny('C1_VAULT_OPTIONS_INVALID');
  const enrolled = new Map(Object.entries(config.principals).map(([role, value]) => [value.principal_id, role]));
  const policies = new Map(), handles = new Map(), revoked = new Set();
  let lastTimestamp = -1;
  for (const candidate of grants) {
    exactKeys(candidate, ['grant_id', 'principal_id', 'project_id', 'origin', 'purpose', 'expires_at']);
    if (!/^grant_e1_[a-z0-9_]{1,48}$/.test(candidate.grant_id ?? '') || policies.has(candidate.grant_id) ||
        candidate.project_id !== config.project_id || normalizeOrigin(candidate.origin) !== config.origin ||
        !Object.hasOwn(purposes, candidate.purpose) || !enrolled.has(candidate.principal_id) ||
        enrolled.get(candidate.principal_id) !== purposes[candidate.purpose] || !Number.isSafeInteger(candidate.expires_at) || candidate.expires_at <= 0) deny('C1_VAULT_GRANT_DENIED');
    policies.set(candidate.grant_id, deepFreeze({...structuredClone(candidate), origin: config.origin}));
  }
  function timestamp() {
    const value = now();
    if (!Number.isSafeInteger(value) || value < 0 || value < lastTimestamp) deny('C1_VAULT_CLOCK_INVALID');
    lastTimestamp = value;
    return value;
  }
  function context(value) {
    exactKeys(value, ['principal_id', 'project_id', 'origin']);
    if (!enrolled.has(value.principal_id) || validateProjectId(value.project_id) !== config.project_id || normalizeOrigin(value.origin) !== config.origin) deny('C1_VAULT_SCOPE_DENIED');
    return {principal_id: value.principal_id, project_id: value.project_id, origin: config.origin};
  }
  const result = (status, reason) => deepFreeze({status, reason, kind: 'SCOPED_HANDLE_FIXTURE', live_ready: false});
  return Object.freeze({
    kind: 'SCOPED_HANDLE_FIXTURE', live_ready: false,
    issueHandle(grantId, caller) {
      const principal = context(caller);
      if (principal.principal_id !== config.principals.issuer.principal_id) deny('C1_VAULT_ISSUER_REQUIRED');
      const grant = policies.get(grantId);
      if (!grant || revoked.has(grantId) || grant.expires_at <= timestamp()) deny('C1_VAULT_GRANT_INACTIVE');
      if (!available) return result('WAIT', 'VAULT_UNAVAILABLE');
      const handle_id = 'vh_e1_' + randomUUID();
      const handle = deepFreeze({schema: 'awe-e1.vault-handle.v1', handle_id, scope_digest: digest({scope, grant})});
      handles.set(handle_id, {handle, grant_id: grantId});
      return handle;
    },
    resolveHandle(handle, caller) {
      const principal = context(caller);
      exactKeys(handle, ['schema', 'handle_id', 'scope_digest']);
      const entry = handles.get(handle.handle_id);
      if (!entry || handle.schema !== entry.handle.schema || handle.scope_digest !== entry.handle.scope_digest) deny('C1_VAULT_HANDLE_DENIED');
      const grant = policies.get(entry.grant_id);
      if (principal.principal_id !== grant.principal_id) deny('C1_VAULT_PRINCIPAL_DENIED');
      // Current grant, revocation and clock are checked on EVERY resolution.
      if (revoked.has(entry.grant_id) || revoked.has(handle.handle_id)) return result('WAIT', 'VAULT_REVOKED');
      if (grant.expires_at <= timestamp()) return result('WAIT', 'VAULT_GRANT_EXPIRED');
      if (!available) return result('WAIT', 'VAULT_UNAVAILABLE');
      return deepFreeze({...result('READY', 'FIXTURE_HANDLE_RESOLVED'), binding: {handle_id: handle.handle_id, project_id: grant.project_id, origin: grant.origin, purpose: grant.purpose}, authenticated_os_principal: false});
    },
    revoke(id, caller) {
      const principal = context(caller);
      if (principal.principal_id !== config.principals.owner.principal_id) deny('C1_VAULT_OWNER_REQUIRED');
      if (!policies.has(id) && !handles.has(id)) deny('C1_VAULT_HANDLE_DENIED');
      revoked.add(id);
      return result('WAIT', 'VAULT_REVOKED');
    },
    setAvailable(value) {
      if (typeof value !== 'boolean') deny('C1_VAULT_OPTIONS_INVALID');
      available = value;
      return result(value ? 'READY' : 'WAIT', value ? 'FIXTURE_VAULT_AVAILABLE' : 'VAULT_UNAVAILABLE');
    },
    status() { return result(available ? 'READY' : 'WAIT', available ? 'FIXTURE_VAULT_AVAILABLE' : 'VAULT_UNAVAILABLE'); }
  });
}
