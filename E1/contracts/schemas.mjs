// Single source of E1 JSON Schema definitions. No network or external $refs.
export const RELEASE = 'AWE_E1/1';
export const CONTRACT_VERSION = 'awe.e1.contracts/1';
const str = (maxLength = 2048) => ({type: 'string', minLength: 1, maxLength, pattern: '\\S'});
const id = {type: 'string', pattern: '^[a-z][a-z0-9_.-]{0,79}$(?![\\s\\S])', maxLength: 80};
const hash = {type: 'string', pattern: '^sha256:[a-f0-9]{64}$(?![\\s\\S])'};
const timestamp = {type: 'string', format: 'date-time'};
const integer = (minimum, maximum) => ({type: 'integer', minimum, maximum});
const oneOf = (...branches) => ({oneOf: branches});
const nullable = child => oneOf(child, {type: 'null'});
const array = (items, minItems = 0, maxItems = 32) => ({type: 'array', items, minItems, maxItems, uniqueItems: true});
const ref = name => ({$ref: '#/$defs/' + name});
const object = properties => ({type: 'object', properties, required: Object.keys(properties), additionalProperties: false});
const enumeration = values => ({type: 'string', enum: values});
const versioned = properties => object({contract_version: {const: CONTRACT_VERSION}, release: {const: RELEASE}, ...properties});
export const DATA_CLASSES = Object.freeze(['PUBLIC', 'PROJECT', 'PERSONAL', 'SECRET']);
export const ORIGINS = Object.freeze(['OWNER', 'PROJECT', 'EXTERNAL', 'INFERRED', 'UNKNOWN']);
export const EFFECT_CLASSES = Object.freeze(['NONE', 'LOCAL_READ', 'LOCAL_WRITE', 'EXTERNAL_READ', 'EXTERNAL_WRITE']);
export const PERMISSIONS = Object.freeze(['mission.create', 'mission.revise', 'mission.revoke', 'plan.propose', 'plan.validate', 'plan.publish', 'artifact.read', 'artifact.write', 'effect.local', 'effect.external_read', 'effect.external_write', 'qa.evaluate']);
const budget = object({currency: enumeration(['NONE', 'RUB', 'USD', 'EUR']), amount_micros: {type: 'string', pattern: '^(0|[1-9][0-9]{0,17})$(?![\\s\\S])'}});
const schemaBinding = object({schema_id: id, version: str(32), digest: hash});
const capabilityRef = versioned({capability_id: id, version: {type: 'string', pattern: '^[0-9]+[.][0-9]+[.][0-9]+$(?![\\s\\S])', maxLength: 32}, manifest_digest: hash, input_schema: ref('SchemaBinding'), output_schema: ref('SchemaBinding')});
const artifactRef = versioned({artifact_id: id, project_id: id, mission_id: id, uri: {type: 'string', pattern: '^artifact:[a-z][a-z0-9._/-]{0,127}$(?![\\s\\S])'}, digest: hash, media_type: str(128), schema: ref('SchemaBinding'), data_class: enumeration(DATA_CLASSES), origin: enumeration(ORIGINS), producer_id: id, created_at: timestamp});
const effectIntent = versioned({effect_id: id, mission_id: id, project_id: id, task_id: id, effect_class: enumeration(EFFECT_CLASSES), permission: nullable(enumeration(PERMISSIONS)), destination: nullable(str(256)), business_key: nullable(str(256)), payload_digest: hash, max_actions: integer(0, 1), reconcile_capability: nullable(ref('CapabilityRef')), unknown_policy: {const: 'HOLD'}, outcome: enumeration(['NOT_STARTED', 'OUTCOME_UNKNOWN', 'CONFIRMED', 'NO_EFFECT'])});
const retry = object({max_attempts: integer(1, 4), retry_on: array(enumeration(['TRANSIENT_NO_EFFECT']), 0, 1), on_unknown: {const: 'HOLD'}});
const taskSpec = versioned({task_id: id, title: str(256), capability: ref('CapabilityRef'), input: {type: 'object', additionalProperties: true}, depends_on: array(id), dependency_bindings: array(object({task_id: id, output_schema: ref('SchemaBinding')})), criterion_ids: array(id, 1), budget, deadline: timestamp, timeout_ms: integer(1, 600000), data_classes: array(enumeration(DATA_CLASSES), 1, 4), origin: object({kind: enumeration(ORIGINS), source_digests: array(hash, 1)}), effect: ref('EffectIntent'), retry: ref('Retry'), qa: object({rubric_id: id, rubric_digest: hash, required_checks: array(id, 1), reviewer_role: {const: 'QA'}})});
const missionSpec = versioned({mission_id: id, project_id: id, owner_id: id, revision: integer(1, 1000000), goal: str(4096), criteria: array(object({criterion_id: id, text: str()}), 1), facts_refs: array(ref('ArtifactRef'), 1), domain_manifest: object({manifest_id: id, version: str(32), digest: hash}), requested_capabilities: array(ref('CapabilityRef'), 1), budget, deadline: timestamp, data_classes: array(enumeration(DATA_CLASSES), 1, 4), allowed_origins: array(enumeration(ORIGINS), 1, 5), max_replans: integer(0, 8), max_actions: integer(0, 64)});
const missionGrant = versioned({grant_id: id, grant_version: integer(1, 1000000), mission_id: id, project_id: id, owner_id: id, issued_by: id, spec_digest: hash, issued_at: timestamp, expires_at: timestamp, revoked_at: nullable(timestamp), revocation_reason: nullable(str()), allowed_principals: array(id, 1, 64), permissions: array(enumeration(PERMISSIONS), 1), allowed_capabilities: array(ref('CapabilityRef'), 1), allowed_data_classes: array(enumeration(DATA_CLASSES), 1, 4), allowed_origins: array(enumeration(ORIGINS), 1, 5), allowed_effect_classes: array(enumeration(EFFECT_CLASSES), 1, 5), destinations: array(str(256), 0, 64), max_tasks: integer(1, 32), max_actions: integer(0, 64), max_replans: integer(0, 8), budget_cap: budget});
const planRevision = versioned({plan_id: id, mission_id: id, project_id: id, revision: integer(1, 9), spec_digest: hash, grant_digest: hash, grant_version: integer(1, 1000000), previous_digest: nullable(hash), proposed_by: id, reason: str(), created_at: timestamp, budget, deadline: timestamp, tasks: array(ref('TaskSpec'), 1)});
const qaResult = versioned({qa_id: id, mission_id: id, project_id: id, task_id: id, artifact_digest: hash, plan_digest: hash, rubric_digest: hash, evaluator_id: id, producer_id: id, evaluated_at: timestamp, verdict: enumeration(['PASS', 'FAIL', 'UNKNOWN']), checks: array(object({check_id: id, passed: {type: 'boolean'}, evidence_refs: array(ref('ArtifactRef'), 1)}), 1), accepted: {const: false}});
const domainManifest = versioned({manifest_id: id, version: str(32), project_id: id, domain: id, description: str(), capabilities: array(ref('CapabilityRef'), 1), qa_rubric: object({rubric_id: id, digest: hash, checks: array(id, 1)})});
export const SCHEMA_DOCUMENT = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://awe.invalid/e1/awe-e1-1.schema.json',
  $defs: {Budget: budget, SchemaBinding: schemaBinding, Retry: retry, CapabilityRef: capabilityRef, ArtifactRef: artifactRef, EffectIntent: effectIntent, TaskSpec: taskSpec, MissionSpec: missionSpec, MissionGrant: missionGrant, PlanRevision: planRevision, QAResult: qaResult, DomainManifest: domainManifest}
};
function freeze(value) { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; }
freeze(SCHEMA_DOCUMENT);
export const CONTRACT_TYPES = Object.freeze(['MissionSpec', 'MissionGrant', 'PlanRevision', 'TaskSpec', 'CapabilityRef', 'ArtifactRef', 'EffectIntent', 'QAResult', 'DomainManifest']);
export function contractSchema(type) {
  if (!CONTRACT_TYPES.includes(type)) throw new TypeError('E1_UNKNOWN_CONTRACT');
  return freeze({...SCHEMA_DOCUMENT, $ref: '#/$defs/' + type});
}
