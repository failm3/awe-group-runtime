import {digest, canonicalize, validatePlanRevision, capabilityKey, validateCapabilityDescriptor} from '../contracts/index.mjs';
import {check, integer} from './errors.mjs';
const bridges = new WeakMap();
const identifier = value => typeof value === 'string' && /^[a-z][a-z0-9_.-]{0,79}$/.test(value);
const unseal = value => value?.value ?? value;

/** A host-owned adapter over the normal A1 publication and authenticated owner
 * grant store. Neither publication JSON nor A1's offline credential issuer is
 * execution authority. The host supplies all four ports outside leaf processes.
 */
export function createAdmissionBridge({authenticate, resolvePublication, verifyGrant, policy, clock = () => new Date().toISOString()}) {
  check([authenticate, resolvePublication, verifyGrant].every(value => typeof value === 'function'), 'A2_TRUSTED_ADMISSION_PORTS');
  const admit = async (request, context) => {
    const principal = await authenticate(context);
    check(principal && identifier(principal.principal_id) && identifier(principal.project_id) && ['OWNER','COORDINATOR'].includes(principal.role), 'A2_AUTHENTICATED_ADMITTER');
    const source = await resolvePublication(request, principal);
    check(source && source.publication?.decision === 'PUBLISHED_PREFLIGHT_ONLY', 'A2_PUBLICATION_REQUIRED');
    const spec = unseal(source.spec), grant = unseal(source.grant), plan = unseal(source.plan);
    check(spec.project_id === principal.project_id && (principal.role !== 'OWNER' || spec.owner_id === principal.principal_id), 'A2_ADMISSION_PROJECT');
    check(await verifyGrant({spec, grant, principal, context}), 'A2_CURRENT_OWNER_GRANT_REQUIRED');
    const capabilities = source.capabilities.map(validateCapabilityDescriptor);
    const validation = validatePlanRevision(plan, {spec, grant, capabilities, domainManifest: source.domainManifest, now: clock()});
    const publication = source.publication;
    check(publication.plan_digest === digest(plan) && publication.spec_digest === digest(spec) && publication.grant_digest === digest(grant), 'A2_PUBLICATION_BINDING');
    const certificate = unseal(source.validation);
    check(certificate && digest(certificate) === publication.validation_digest && certificate.registry_digest === validation.registry_digest && certificate.plan_digest === digest(plan) && certificate.grant_digest === digest(grant), 'A2_VALIDATION_BINDING');
    const trustedPolicy = typeof policy === 'function' ? await policy({spec, grant, principal}) : structuredClone(policy);
    check(trustedPolicy && Number.isSafeInteger(trustedPolicy.max_parallel) && trustedPolicy.max_parallel >= 1 && trustedPolicy.max_parallel <= 32, 'A2_POLICY_PARALLEL');
    trustedPolicy.budget_cap_micros = integer(trustedPolicy.budget_cap_micros, 'A2_POLICY_BUDGET');
    trustedPolicy.quota_cap = integer(trustedPolicy.quota_cap, 'A2_POLICY_QUOTA'); check(BigInt(trustedPolicy.quota_cap) > 0n, 'A2_POLICY_QUOTA');
    check(trustedPolicy.resource_limits && Object.keys(trustedPolicy.resource_limits).length <= 16, 'A2_RESOURCE_POLICY');
    for (const [key, limit] of Object.entries(trustedPolicy.resource_limits)) check(identifier(key) && Number.isSafeInteger(limit) && limit >= 1 && limit <= 32, 'A2_RESOURCE_POLICY');
    const registry = new Map(capabilities.map(cap => [capabilityKey(cap.ref), cap]));
    const tasks = plan.tasks.map(spec => {
      const cap = registry.get(capabilityKey(spec.capability)), runtime = trustedPolicy.capabilities?.[cap.ref.capability_id] ?? {};
      const resource_keys = runtime.resource_keys ?? [];
      check(Array.isArray(resource_keys) && resource_keys.length <= 16 && new Set(resource_keys).size === resource_keys.length && resource_keys.every(key => Object.hasOwn(trustedPolicy.resource_limits, key)), 'A2_TASK_RESOURCE_POLICY');
      const model_routes = runtime.model_routes ?? (cap.executor_kind === 'llm' ? ['ollama.local.qwen3-4b-instruct'] : []);
      check(Array.isArray(model_routes) && model_routes.length <= 4 && (cap.executor_kind === 'llm' || model_routes.length === 0) && model_routes.every(route => route === 'ollama.local.qwen3-4b-instruct'), 'A2_MODEL_ROUTE_POLICY');
      const max_claims = runtime.max_claims ?? spec.retry.max_attempts;
      check(Number.isSafeInteger(max_claims) && max_claims >= 1 && max_claims <= spec.retry.max_attempts && (spec.effect.effect_class === 'NONE' || max_claims === 1), 'A2_RETRY_POLICY');
      const priority = runtime.priority ?? 0; check(Number.isSafeInteger(priority) && priority >= -100 && priority <= 100, 'A2_PRIORITY_POLICY');
      return {spec, executor_kind: cap.executor_kind, resource_keys, model_routes, max_claims, priority, output_schema:cap.output_schema};
    });
    const payload = {project_id: spec.project_id, spec, grant, plan, publication, capabilities, spec_digest: digest(spec), grant_digest: digest(grant), plan_digest: digest(plan), admitted_by: principal.principal_id, tasks,
      policy: {budget_cap_micros: trustedPolicy.budget_cap_micros, quota_cap: trustedPolicy.quota_cap, max_parallel: trustedPolicy.max_parallel, resource_limits: trustedPolicy.resource_limits}};
    // Contracts have per-entity limits; this transport collection has a separate cap.
    check(Buffer.byteLength(JSON.stringify(payload)) <= 512 * 1024, 'A2_ADMISSION_SIZE');
    return structuredClone(payload);
  };
  const bridge = Object.freeze({kind: 'TRUSTED_A1_DURABLE_ADMISSION_BRIDGE'}); bridges.set(bridge, admit); return bridge;
}
export function admissionPort(bridge) { const port = bridges.get(bridge); check(port, 'A2_ADMISSION_BRIDGE_REQUIRED'); return port; }
