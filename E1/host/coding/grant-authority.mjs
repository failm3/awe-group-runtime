import {digest, immutable, need, validateMissionBinding} from '../../contracts/index.mjs';
import {authorityPorts} from '../../mission/authority.mjs';
import {validateCodingTaskGrantV2} from '../../executors/coding/contracts.mjs';
import {CODING_HOST_PROTECTED_ROOTS, validateCodingHostPolicy, assertCodingPolicy} from './policy.mjs';

/** Host-local staging delegation. A1 bootstrap is not production human AuthN.
 * The issuing context stays host-owned; JSON cannot manufacture its identity.
 * The separate native claim verifier must check the current project/task/fence.
 */
export function createCodingGrantAuthority({authority, spec: suppliedSpec, ownerGrant: suppliedGrant, policy: suppliedPolicy, verifyNativeClaim, clock = () => new Date().toISOString()}) {
  const spec = immutable(suppliedSpec), ownerGrant = immutable(suppliedGrant), policy = immutable(suppliedPolicy);
  const auth = authorityPorts(authority), records = new Map();
  validateCodingHostPolicy(policy);
  need(digest(ownerGrant) === policy.owner_grant_digest && typeof verifyNativeClaim === 'function', 'CODING_AUTHORITY_BINDING');
  function checkParent() {
    validateMissionBinding(spec, ownerGrant, clock());
    need(['artifact.read', 'artifact.write', 'qa.evaluate'].every(p => ownerGrant.permissions.includes(p)), 'CODING_PARENT_PERMISSION');
    need(ownerGrant.allowed_effect_classes.includes('NONE') && spec.max_actions === 0 && ownerGrant.max_actions === 0, 'CODING_PARENT_EFFECT');
  }
  function checkGrant(grant) {
    checkParent(); validateCodingTaskGrantV2(grant, {now: clock(), hostProtectedRoots: CODING_HOST_PROTECTED_ROOTS});
    assertCodingPolicy(grant, policy);
    need(grant.project_id === spec.project_id && grant.mission_id === spec.mission_id && grant.owner_id === spec.owner_id &&
      grant.expires_at <= ownerGrant.expires_at && grant.expires_at <= spec.deadline && grant.issued_at >= ownerGrant.issued_at &&
      ownerGrant.allowed_principals.includes(grant.producer_id), 'CODING_PARENT_SCOPE');
    const ref = ownerGrant.allowed_capabilities.find(c => c.capability_id === grant.model_capability.capability_id && c.version === grant.model_capability.version);
    need(ref && ref.output_schema.digest === grant.model_capability.output_schema_digest && spec.requested_capabilities.some(c => digest(c) === digest(ref)), 'CODING_PARENT_CAPABILITY');
  }
  return Object.freeze({kind: 'OWNER_TASK_GRANT_AUTHORITY', profile: 'AWE_E1_LOCAL_STAGING',
    issue(grant, ownerContext) {
      const principal = auth.verify(ownerContext);
      need(principal.role === 'OWNER' && principal.principal_id === ownerGrant.issued_by && principal.project_id === spec.project_id, 'CODING_OWNER_CONTEXT');
      checkGrant(grant); need(!records.has(grant.grant_id), 'CODING_GRANT_DUPLICATE');
      records.set(grant.grant_id, {grant: immutable(grant), ownerContext, active: true});
      return grant.grant_id;
    },
    revoke(grantRef, ownerContext) {
      const p = auth.verify(ownerContext); need(p.role === 'OWNER' && p.principal_id === ownerGrant.issued_by && p.project_id === spec.project_id, 'CODING_OWNER_CONTEXT');
      const record = records.get(grantRef); need(record, 'CODING_GRANT_UNKNOWN'); record.active = false;
    },
    async resolve(grantRef, context) {
      const record = records.get(grantRef); if (!record?.active) return null;
      const p = auth.verify(context), owner = auth.verify(record.ownerContext); checkGrant(record.grant);
      need(owner.role === 'OWNER' && p.role === 'EXECUTOR' && p.principal_id === record.grant.producer_id && p.project_id === spec.project_id, 'CODING_EXECUTOR_CONTEXT');
      need(await verifyNativeClaim({grant: record.grant, principal: p}) === true, 'CODING_NATIVE_CLAIM_REQUIRED');
      // Native reads yield to the event loop: revoke/expiry/context changes must
      // be observed again before releasing an executable derived authority.
      need(record.active && records.get(grantRef) === record, 'CODING_GRANT_REVOKED');
      auth.verify(record.ownerContext); auth.verify(context); checkGrant(record.grant);
      return record.grant;
    }
  });
}
