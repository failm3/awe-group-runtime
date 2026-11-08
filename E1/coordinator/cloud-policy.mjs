import {canonicalize, digest} from '../contracts/index.mjs';
import {check, integer} from './errors.mjs';

export const CLOUD_BUDGET_GROUP = 'router.cheap.shared/1';
export const CLOUD_TASK_POLICY_SCHEMA = 'awe.e1.cloud-task-policy/1';
const ports = new WeakMap();
const sha = value => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
const identifier = value => typeof value === 'string' && /^[a-z][a-z0-9_.-]{0,79}$/.test(value);

/** This host object never crosses the worker RPC boundary. Authentication and
 * evidence verification must come from the installation's actual host services.
 * Accepting a JSON document alone is deliberately insufficient to fund a key.
 */
export function createCloudBudgetAuthority({authenticateHost, verifyOwnerFunding, verifyProviderLimit}) {
  check([authenticateHost, verifyOwnerFunding, verifyProviderLimit].every(fn => typeof fn === 'function'), 'A2_CLOUD_HOST_PORTS');
  const authority = Object.freeze({kind: 'TRUSTED_CLOUD_BUDGET_AUTHORITY'});
  ports.set(authority, async (request, context) => {
    const principal = await authenticateHost(context);
    check(principal?.role === 'HOST_COORDINATOR' && identifier(principal.principal_id), 'A2_CLOUD_HOST_AUTH_REQUIRED');
    const value = structuredClone(request);
    validateCloudBudgetProvision(value);
    check(await verifyOwnerFunding({grant: value.grant, grant_digest: value.grant_digest, principal, context}), 'A2_CLOUD_OWNER_FUNDING_REQUIRED');
    check(await verifyProviderLimit({evidence: value.provider_limit_evidence, evidence_digest: value.provider_limit_evidence_digest, grant: value.grant, principal, context}), 'A2_CLOUD_HARD_PROVIDER_CAP_REQUIRED');
    return value;
  });
  return authority;
}

export async function cloudBudgetProvisionPort(authority, request, context) {
  const port = ports.get(authority);
  check(port, 'A2_CLOUD_HOST_AUTH_REQUIRED');
  return port(request, context);
}

export function validateCloudBudgetProvision(value) {
  canonicalize(value);
  check(Buffer.byteLength(JSON.stringify(value)) <= 32768, 'A2_CLOUD_FUNDING_SCHEMA');
  const grant = value?.grant, proof = value?.provider_limit_evidence;
  check(grant?.schema === 'awe.e1.cloud-funding-grant/1' && grant.budget_group_id === CLOUD_BUDGET_GROUP && identifier(grant.key_binding_id) && identifier(grant.owner_id), 'A2_CLOUD_FUNDING_SCHEMA');
  check(sha(value.grant_digest) && value.grant_digest === digest(grant), 'A2_CLOUD_FUNDING_DIGEST');
  check(Array.isArray(grant.project_ids) && grant.project_ids.length >= 1 && grant.project_ids.length <= 32 && grant.project_ids.every(identifier) && new Set(grant.project_ids).size === grant.project_ids.length, 'A2_CLOUD_FUNDING_PROJECTS');
  for (const key of ['budget_cap_micros', 'per_attempt_cap_micros', 'attempts_cap']) check(BigInt(integer(grant[key], 'A2_CLOUD_FUNDING_LIMIT')) > 0n, 'A2_CLOUD_FUNDING_LIMIT');
  check(BigInt(grant.per_attempt_cap_micros) <= BigInt(grant.budget_cap_micros), 'A2_CLOUD_FUNDING_LIMIT');
  check(sha(grant.owner_grant_digest) && ['AUTHENTICATED_HOST', 'EXPLICIT_SYNTHETIC'].includes(grant.evidence_mode) && typeof grant.funding_ref === 'string' && grant.funding_ref.length <= 256, 'A2_CLOUD_FUNDING_SCHEMA');
  check(proof?.schema === 'awe.e1.provider-hard-charge-limit/1' && proof.provider === 'router.cheap' && proof.key_binding_id === grant.key_binding_id && proof.currency === 'USD' && proof.enforcement === 'HARD_ACTUAL_CHARGE' && proof.request_hard_cap_supported === true && proof.evidence_mode === grant.evidence_mode, 'A2_CLOUD_HARD_PROVIDER_CAP_REQUIRED');
  check(value.provider_limit_evidence_digest === digest(proof) && sha(proof.account_binding_digest) && typeof proof.limit_ref === 'string' && proof.limit_ref.length <= 256, 'A2_CLOUD_HARD_PROVIDER_CAP_REQUIRED');
  for (const key of ['actual_charge_cap_micros', 'max_request_actual_charge_micros']) integer(proof[key], 'A2_CLOUD_HARD_PROVIDER_CAP_REQUIRED');
  check(BigInt(proof.actual_charge_cap_micros) >= BigInt(grant.budget_cap_micros) && BigInt(proof.max_request_actual_charge_micros) >= BigInt(grant.per_attempt_cap_micros), 'A2_CLOUD_HARD_PROVIDER_CAP_REQUIRED');
  for (const doc of [grant, proof]) check(Number.isFinite(Date.parse(doc.issued_at)) && Number.isFinite(Date.parse(doc.expires_at)) && Date.parse(doc.issued_at) < Date.parse(doc.expires_at), 'A2_CLOUD_FUNDING_EXPIRY');
  if (grant.evidence_mode === 'EXPLICIT_SYNTHETIC') check(grant.key_binding_id.startsWith('synthetic_') && grant.project_ids.every(id => /^prj_(cloud|qa3)_/.test(id)) && grant.funding_ref.startsWith('synthetic:') && proof.limit_ref.startsWith('synthetic:'), 'A2_CLOUD_SYNTHETIC_SCOPE');
  else check(!grant.key_binding_id.startsWith('synthetic_') && !grant.funding_ref.startsWith('synthetic:') && !proof.limit_ref.startsWith('synthetic:'), 'A2_CLOUD_SYNTHETIC_SCOPE');
  return value;
}

export function validateCloudTaskPolicy(value, {grant_digest, model_routes}) {
  canonicalize(value);
  check(value?.schema === CLOUD_TASK_POLICY_SCHEMA && value.budget_group_id === CLOUD_BUDGET_GROUP && identifier(value.key_binding_id) && sha(value.funding_grant_digest) && value.owner_grant_digest === grant_digest, 'A2_CLOUD_TASK_POLICY');
  check(Array.isArray(value.routes) && value.routes.length >= 1 && value.routes.length <= 4 && new Set(value.routes.map(route => route.route_id)).size === value.routes.length, 'A2_CLOUD_TASK_POLICY');
  for (const route of value.routes) {
    check(/^router[.]cheap[.]chat[.][a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}$/.test(route.route_id) && route.snapshot && typeof route.snapshot === 'object' && route.snapshot_digest === digest(route.snapshot), 'A2_CLOUD_ROUTE_SNAPSHOT');
    check(route.snapshot.route_id === route.route_id && route.snapshot.provider === 'router.cheap', 'A2_CLOUD_ROUTE_SNAPSHOT');
  }
  check(model_routes.every(route => route === 'ollama.local.qwen3-4b-instruct' || value.routes.some(snapshot => snapshot.route_id === route)) && value.routes.every(snapshot => model_routes.includes(snapshot.route_id)), 'A2_MODEL_ROUTE_POLICY');
  check(Buffer.byteLength(JSON.stringify(value)) <= 32768, 'A2_CLOUD_TASK_POLICY');
  return structuredClone(value);
}
