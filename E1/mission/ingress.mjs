import {RELEASE, CONTRACT_VERSION, digest, exact, immutable, immutableCollection, need, utc, sealContract, validateContract, validateMissionBinding, validateDomainBinding, validateCapabilityDescriptor, validatePlanRevision, assertNarrowerGrant, capabilityKey, capabilityRegistryDigest} from '../contracts/index.mjs';
import {authorityPorts} from './authority.mjs';
export {createOfflineAuthority} from './authority.mjs';
export const MAX_MISSION_REVISIONS = 16;

/** One mission/plan contract boundary, deliberately not a scheduler or ledger.
 * State/history is process-local and cannot authorize execution. D03/D09 A2 must
 * atomically persist/claim/recheck these digests before any actual attempt.
 */
export function createMissionIngress({clock = () => new Date().toISOString(), authority, capabilities, projectId, domainManifests = []}) {
  const auth = authorityPorts(authority), missions = new Map();
  if (projectId !== undefined) need(typeof projectId === 'string' && /^[a-z][a-z0-9_.-]{0,79}$/.test(projectId), 'E1_PROJECT_ID');
  need(Array.isArray(capabilities) && capabilities.length > 0 && capabilities.length <= 128, 'E1_CAPABILITIES');
  const registry = capabilities.map(validateCapabilityDescriptor);
  need(Array.isArray(domainManifests) && domainManifests.length <= 32, 'E1_DOMAIN_MANIFESTS');
  const manifests = domainManifests.map(value => validateContract('DomainManifest', value));
  need(new Set(manifests.map(digest)).size === manifests.length, 'E1_DUPLICATE_DOMAIN_MANIFEST');
  function domain(spec) { const manifest = manifests.find(value => digest(value) === spec.domain_manifest.digest); return validateDomainBinding(spec, manifest); }
  need(new Set(registry.map(x => capabilityKey(x.ref))).size === registry.length, 'E1_DUPLICATE_CAPABILITY');
  const registryDigest = capabilityRegistryDigest(registry); let lastNow = '';
  function now() { const time = utc(clock()); need(time >= lastNow, 'E1_CLOCK_ROLLBACK'); lastNow = time; return time; }
  function authenticate(context) { const principal = auth.verify(context); need(projectId === undefined || principal.project_id === projectId, 'E1_INSTANCE_PROJECT'); return principal; }
  function actor(context, requestedProjectId, requiredRole) { const principal = authenticate(context); need(principal.project_id === requestedProjectId, 'E1_ACTOR_PROJECT'); if (requiredRole) need(principal.role === requiredRole, 'E1_ACTOR_ROLE'); return principal; }
  function current(missionId, context, role) { const principal = authenticate(context), record = missions.get(missionId); need(record && record.spec.value.project_id === principal.project_id, 'E1_MISSION_SCOPE'); if (role) need(principal.role === role, 'E1_ACTOR_ROLE'); need(record.status === 'ACTIVE', 'E1_MISSION_REVOKED'); return {record, principal}; }
  function permitted(record, principal, permission, time) { validateMissionBinding(record.spec.value, record.grant.value, time); const grant = record.grant.value; need(grant.allowed_principals.includes(principal.principal_id) && grant.permissions.includes(permission), 'E1_PERMISSION'); auth.lookup(grant.issued_by, grant.project_id); grant.allowed_principals.forEach(id => auth.lookup(id, grant.project_id)); }
  function ownerCheck(spec, grant, context) { const principal = actor(context, spec.project_id, 'OWNER'); need(principal.principal_id === spec.owner_id && grant.issued_by === principal.principal_id && grant.owner_id === principal.principal_id, 'E1_OWNER_OR_ISSUER'); const issuer = auth.lookup(grant.issued_by, grant.project_id); need(issuer.role === 'OWNER' && issuer.principal_id === spec.owner_id, 'E1_GRANT_ISSUER'); grant.allowed_principals.forEach(id => auth.lookup(id, grant.project_id)); return principal; }
  function event(record, action, principal, time, objectDigest, reason) { const previous = record.events.at(-1); const value = immutable({sequence: record.events.length + 1, action, actor_id: principal.principal_id, at: time, object_digest: objectDigest, previous_event_digest: previous?.digest ?? null, reason}); const item = immutable({digest: digest(value), value}); record.events.push(item); return item; }
  function view(record) { return immutableCollection({mission_id: record.spec.value.mission_id, project_id: record.spec.value.project_id, status: record.status, spec: record.spec, grant: record.grant, spec_history: record.specs, grant_history: record.grants, plans: record.plans, published_digest: record.published_digest, history: record.events, accepted: false, effects: 0, execution_authorized: false}); }
  function staged(record) { return structuredClone(record); }
  function commit(record) { const result = view(record); missions.set(record.spec.value.mission_id, record); return result; }
  function checkExpected(record, request) { need(request.expected_spec_digest === record.spec.digest && request.expected_grant_digest === record.grant.digest, 'E1_STALE_MISSION'); }
  const mission = Object.freeze({
    create(request, context) {
      exact(request, ['spec', 'grant']); const time = now(); const {spec, grant} = validateMissionBinding(request.spec, request.grant, time); const principal = ownerCheck(spec, grant, context); domain(spec);
      need(spec.revision === 1 && grant.grant_version === 1, 'E1_INITIAL_REVISION'); need(!missions.has(spec.mission_id), 'E1_MISSION_EXISTS');
      const sealedSpec = sealContract('MissionSpec', spec), sealedGrant = sealContract('MissionGrant', grant); const record = {status: 'ACTIVE', spec: sealedSpec, grant: sealedGrant, specs: [sealedSpec], grants: [sealedGrant], plans: [], published_digest: null, events: []};
      permitted(record, principal, 'mission.create', time); event(record, 'mission.create', principal, time, sealedSpec.digest, 'OWNER_CREATE'); return commit(record);
    },
    revise(request, context) {
      exact(request, ['spec', 'grant', 'expected_spec_digest', 'expected_grant_digest', 'reason']); need(typeof request.reason === 'string' && request.reason.trim().length > 0 && request.reason.length <= 2048, 'E1_REVISION_REASON');
      const time = now(), spec = validateContract('MissionSpec', request.spec), grant = validateContract('MissionGrant', request.grant), currentState = current(spec.mission_id, context, 'OWNER'), principal = currentState.principal, record = staged(currentState.record); permitted(record, principal, 'mission.revise', time); checkExpected(record, request); ownerCheck(spec, grant, context);
      need(spec.project_id === record.spec.value.project_id && spec.owner_id === record.spec.value.owner_id && spec.revision === record.spec.value.revision + 1 && spec.revision <= MAX_MISSION_REVISIONS, 'E1_SPEC_REVISION'); assertNarrowerGrant(record.grant.value, grant); validateMissionBinding(spec, grant, time); domain(spec);
      // Revisions cannot silently widen the mission even inside the old grant.
      need(spec.budget.currency === record.spec.value.budget.currency && BigInt(spec.budget.amount_micros) <= BigInt(record.spec.value.budget.amount_micros) && spec.deadline <= record.spec.value.deadline && spec.max_replans <= record.spec.value.max_replans && spec.max_actions <= record.spec.value.max_actions, 'E1_MISSION_SELF_ELEVATION');
      for (const key of ['requested_capabilities', 'data_classes', 'allowed_origins']) need(spec[key].every(value => record.spec.value[key].some(old => digest(value) === digest(old))), 'E1_MISSION_SELF_ELEVATION');
      record.spec = sealContract('MissionSpec', spec); record.grant = sealContract('MissionGrant', grant); record.specs.push(record.spec); record.grants.push(record.grant); record.published_digest = null;
      event(record, 'mission.revise', principal, time, record.spec.digest, request.reason); return commit(record);
    },
    revoke(request, context) {
      exact(request, ['mission_id', 'expected_spec_digest', 'expected_grant_digest', 'reason']); need(typeof request.reason === 'string' && request.reason.trim().length > 0 && request.reason.length <= 2048, 'E1_REVOCATION_REASON');
      const time = now(), currentState = current(request.mission_id, context, 'OWNER'), principal = currentState.principal, record = staged(currentState.record); need(principal.principal_id === record.spec.value.owner_id, 'E1_OWNER_OR_ISSUER'); checkExpected(record, request);
      // Stop remains available after grant expiry; it never grants new work.
      need(record.grant.value.permissions.includes('mission.revoke'), 'E1_PERMISSION');
      const grant = {...record.grant.value, grant_version: record.grant.value.grant_version + 1, revoked_at: time, revocation_reason: request.reason}; record.grant = sealContract('MissionGrant', grant); record.grants.push(record.grant); record.status = 'REVOKED'; record.published_digest = null;
      event(record, 'mission.revoke', principal, time, record.grant.digest, request.reason); return commit(record);
    }
  });
  function selected(request, context) { exact(request, ['mission_id', 'plan_digest']); const time = now(), currentState = current(request.mission_id, context, 'COORDINATOR'), principal = currentState.principal, record = staged(currentState.record); const entry = record.plans.at(-1); need(entry && entry.contract.digest === request.plan_digest, 'E1_STALE_PLAN'); return {record, principal, entry, time}; }
  const plan = Object.freeze({
    propose(request, context) {
      exact(request, ['plan']); const proposal = validateContract('PlanRevision', request.plan), time = now(), currentState = current(proposal.mission_id, context, 'HEAD'), principal = currentState.principal, record = staged(currentState.record); permitted(record, principal, 'plan.propose', time);
      need(proposal.proposed_by === principal.principal_id, 'E1_PLAN_ACTOR'); need(proposal.project_id === record.spec.value.project_id && proposal.spec_digest === record.spec.digest && proposal.grant_digest === record.grant.digest && proposal.grant_version === record.grant.value.grant_version, 'E1_PLAN_BINDING');
      const previous = record.plans.at(-1); need(proposal.revision === record.plans.length + 1 && proposal.previous_digest === (previous?.contract.digest ?? null) && (!previous || proposal.plan_id === previous.contract.value.plan_id), 'E1_PLAN_REVISION');
      need(proposal.revision <= Math.min(record.spec.value.max_replans, record.grant.value.max_replans) + 1, 'E1_REPLAN_EXHAUSTED'); need(proposal.created_at <= time && proposal.created_at >= record.grant.value.issued_at, 'E1_PLAN_TIME');
      const contract = sealContract('PlanRevision', proposal); record.plans.push({contract, validation: null, status: 'PROPOSED'}); record.published_digest = null; event(record, 'plan.propose', principal, time, contract.digest, proposal.reason); const result = immutable({decision: 'PROPOSED', plan: contract, accepted: false, execution_authorized: false}); commit(record); return result;
    },
    validate(request, context) {
      const {record, principal, entry, time} = selected(request, context); permitted(record, principal, 'plan.validate', time);
      const result = validatePlanRevision(entry.contract.value, {spec: record.spec.value, grant: record.grant.value, capabilities: registry, domainManifest: domain(record.spec.value), now: time});
      if (entry.validation) return immutable({decision: 'VALIDATED', validation: entry.validation, accepted: false, execution_authorized: false});
      const value = immutable({...result, validated_at: time, validator_id: principal.principal_id}); const validation = immutable({digest: digest(value), value}); entry.validation = validation; entry.status = 'VALIDATED'; event(record, 'plan.validate', principal, time, validation.digest, 'CODE_PREFLIGHT'); const response = immutable({decision: 'VALIDATED', validation, accepted: false, execution_authorized: false}); commit(record); return response;
    },
    publish(request, context) {
      exact(request, ['mission_id', 'plan_digest', 'validation_digest']); const {record, principal, entry, time} = selected({mission_id: request.mission_id, plan_digest: request.plan_digest}, context); permitted(record, principal, 'plan.publish', time);
      need(['VALIDATED', 'PUBLISHED_PREFLIGHT_ONLY'].includes(entry.status) && entry.validation?.digest === request.validation_digest, 'E1_VALIDATION_REQUIRED');
      // A certificate is never a bypass: time, registry, scope and grant recheck.
      const result = validatePlanRevision(entry.contract.value, {spec: record.spec.value, grant: record.grant.value, capabilities: registry, domainManifest: domain(record.spec.value), now: time}); need(result.registry_digest === registryDigest && entry.validation.value.spec_digest === record.spec.digest && entry.validation.value.grant_digest === record.grant.digest, 'E1_STALE_VALIDATION');
      const repeated = entry.status === 'PUBLISHED_PREFLIGHT_ONLY'; entry.status = 'PUBLISHED_PREFLIGHT_ONLY'; record.published_digest = entry.contract.digest; if (!repeated) event(record, 'plan.publish', principal, time, entry.contract.digest, 'READY_FOR_D03_ADMISSION');
      const response = immutable({decision: 'PUBLISHED_PREFLIGHT_ONLY', release: RELEASE, contract_version: CONTRACT_VERSION, plan_digest: entry.contract.digest, spec_digest: record.spec.digest, grant_digest: record.grant.digest, validation_digest: entry.validation.digest, accepted: false, effects: 0, execution_authorized: false}); commit(record); return response;
    }
  });
  return Object.freeze({release: RELEASE, mode: 'CONTRACT_PREFLIGHT_ONLY', mission, plan,
    snapshot(context) { const principal = authenticate(context); const visible = [...missions.values()].filter(record => record.spec.value.project_id === principal.project_id && (record.spec.value.owner_id === principal.principal_id || record.grant.value.allowed_principals.includes(principal.principal_id))); return immutableCollection({release: RELEASE, registry_digest: registryDigest, missions: visible.map(view), accepted: false, effects: 0, execution_authorized: false}); },
    history(mission_id, context) { const principal = authenticate(context), record = missions.get(mission_id); need(record && record.spec.value.project_id === principal.project_id && (record.spec.value.owner_id === principal.principal_id || record.grant.value.allowed_principals.includes(principal.principal_id)), 'E1_MISSION_SCOPE'); return immutableCollection(record.events); }
  });
}
