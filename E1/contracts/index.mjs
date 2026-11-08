import {canonicalize as canonicalizeBase, digest as digestBase, CANONICALIZATION} from '../../contracts/canonical.mjs';
import {validateDag} from '../../awe/project_factory/factory.mjs';
import {CONTRACT_VERSION, RELEASE, CONTRACT_TYPES, SCHEMA_DOCUMENT, contractSchema, PERMISSIONS, DATA_CLASSES, ORIGINS, EFFECT_CLASSES} from './schemas.mjs';
export {CANONICALIZATION, CONTRACT_VERSION, RELEASE, CONTRACT_TYPES, SCHEMA_DOCUMENT, contractSchema};

// E0 canonicalization is reused unchanged. The E1 raw-JS boundary additionally
// rejects accessors/hidden or symbol properties on arrays before reading them.
function strictJson(value, depth = 0) {
  need(depth <= 32, 'E1_JSON_DEPTH');
  if (!value || typeof value !== 'object') return;
  const descriptors = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(value);
  if (Array.isArray(value)) {
    need(Object.getPrototypeOf(value) === Array.prototype && keys.length === value.length + 1 && Object.keys(value).length === value.length, 'E1_JSON_ARRAY');
    for (let i = 0; i < value.length; i++) { const descriptor = descriptors[String(i)]; need(descriptor && Object.hasOwn(descriptor, 'value') && descriptor.enumerable, 'E1_JSON_ARRAY'); strictJson(descriptor.value, depth + 1); }
  } else {
    need(Object.getPrototypeOf(value) === Object.prototype && keys.every(key => typeof key === 'string' && !['__proto__', 'prototype', 'constructor'].includes(key)), 'E1_JSON_OBJECT');
    for (const key of keys) { const descriptor = descriptors[key]; need(Object.hasOwn(descriptor, 'value') && descriptor.enumerable, 'E1_JSON_PROPERTY'); strictJson(descriptor.value, depth + 1); }
  }
}
export function canonicalize(value) { strictJson(value); return canonicalizeBase(value); }
export function digest(value) { strictJson(value); return digestBase(value); }

export class ContractError extends Error {
  constructor(code, disposition = 'REJECT', path = '$') { super(code); this.name = 'ContractError'; this.code = code; this.disposition = disposition; this.path = path; }
}
export function need(ok, code, disposition = 'REJECT', path) { if (!ok) throw new ContractError(code, disposition, path); }
function freezeCopy(value) { const copy = structuredClone(value); const freeze = v => { if (v && typeof v === 'object') { Object.values(v).forEach(freeze); Object.freeze(v); } return v; }; return freeze(copy); }
export function immutable(value) { canonicalize(value); return freezeCopy(value); }
// Snapshot/history collections contain independently bounded contracts. They are
// not one canonical-hash payload and can exceed the per-entity 64 KiB limit.
export function immutableCollection(value) { strictJson(value); return freezeCopy(value); }
export function exact(value, fields) { canonicalize(value); need(value && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length === fields.length && fields.every(k => Object.hasOwn(value, k)), 'E1_REQUEST_SHAPE'); }
export function utc(value) { need(typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[.]\d{3}Z$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value, 'E1_UTC_TIMESTAMP'); return value; }
const same = (a, b) => digest(a) === digest(b);
const subset = (values, allowed) => values.every(value => allowed.some(x => same(x, value)));
const uniqueBy = (values, select, code) => need(new Set(values.map(select)).size === values.length, code);
export const capabilityKey = value => value.capability_id + '@' + value.version;
export const capabilityRegistryDigest = values => digest(values.map(value => ({capability: capabilityKey(value.ref), manifest_digest: value.ref.manifest_digest})).sort((a, b) => a.capability < b.capability ? -1 : a.capability > b.capability ? 1 : 0));
export const schemaDigest = type => digest(contractSchema(type));

// Deliberately bounded JSON Schema subset, also used for capability input validation.
// Unsupported vocabulary/$refs fails closed; never fetches a remote schema.
const keywords = new Set(['$schema', '$id', '$defs', '$ref', 'type', 'properties', 'required', 'additionalProperties', 'const', 'enum', 'oneOf', 'items', 'minItems', 'maxItems', 'uniqueItems', 'minimum', 'maximum', 'minLength', 'maxLength', 'pattern', 'format']);
function walk(schema, value, root, path, depth = 0) {
  need(depth <= 32, 'E1_SCHEMA_DEPTH', 'REJECT', path);
  if (schema.$ref) { need(/^#\/\$defs\/[A-Za-z]+$/.test(schema.$ref), 'E1_SCHEMA_REF'); const target = root.$defs?.[schema.$ref.split('/').at(-1)]; need(target, 'E1_SCHEMA_REF'); return walk(target, value, root, path, depth + 1); }
  if (schema.oneOf) { let matched = 0; for (const branch of schema.oneOf) { try { walk(branch, value, root, path, depth + 1); matched++; } catch (error) { if (!(error instanceof ContractError)) throw error; } } need(matched === 1, 'E1_SCHEMA_ONE_OF', 'REJECT', path); }
  if (Object.hasOwn(schema, 'const')) need(same(value, schema.const), 'E1_SCHEMA_CONST', 'REJECT', path);
  if (schema.enum) need(schema.enum.some(x => same(x, value)), 'E1_SCHEMA_ENUM', 'REJECT', path);
  if (schema.type) {
    const matches = schema.type === 'null' ? value === null : schema.type === 'object' ? value !== null && Object.getPrototypeOf(value) === Object.prototype : schema.type === 'array' ? Array.isArray(value) : schema.type === 'integer' ? Number.isSafeInteger(value) : typeof value === schema.type;
    need(matches, 'E1_SCHEMA_TYPE', 'REJECT', path);
  }
  if (schema.type === 'object') {
    for (const key of schema.required ?? []) need(Object.hasOwn(value, key), 'E1_SCHEMA_REQUIRED', 'REJECT', path + '/' + key);
    for (const [key, child] of Object.entries(value)) { const childSchema = schema.properties?.[key]; if (childSchema) walk(childSchema, child, root, path + '/' + key, depth + 1); else need(schema.additionalProperties === true, 'E1_SCHEMA_EXTRA', 'REJECT', path + '/' + key); }
  }
  if (schema.type === 'array') {
    need(value.length >= (schema.minItems ?? 0) && value.length <= (schema.maxItems ?? 32), 'E1_SCHEMA_ITEM_COUNT', 'REJECT', path);
    if (schema.uniqueItems) uniqueBy(value, canonicalize, 'E1_SCHEMA_DUPLICATE');
    value.forEach((child, i) => walk(schema.items, child, root, path + '/' + i, depth + 1));
  }
  if (typeof value === 'string') {
    need(Array.from(value).length >= (schema.minLength ?? 0) && Array.from(value).length <= (schema.maxLength ?? Infinity) && (!schema.pattern || new RegExp(schema.pattern, 'u').test(value)), 'E1_SCHEMA_STRING', 'REJECT', path);
    if (schema.format === 'date-time') utc(value);
  }
  if (typeof value === 'number') need(value >= (schema.minimum ?? -Infinity) && value <= (schema.maximum ?? Infinity), 'E1_SCHEMA_RANGE', 'REJECT', path);
}
export function inspectBoundSchema(schema, depth = 0) {
  canonicalize(schema); need(depth <= 8 && schema && Object.getPrototypeOf(schema) === Object.prototype, 'E1_BOUND_SCHEMA');
  need(['object', 'array', 'string', 'integer', 'boolean', 'null'].includes(schema.type), 'E1_BOUND_SCHEMA_TYPE');
  const perType = {object: ['properties', 'required', 'additionalProperties'], array: ['items', 'minItems', 'maxItems', 'uniqueItems'], string: ['minLength', 'maxLength', 'pattern', 'format'], integer: ['minimum', 'maximum'], boolean: [], null: []};
  const allowed = new Set(['type', 'const', 'enum', ...perType[schema.type]]);
  need(Object.keys(schema).every(k => keywords.has(k) && allowed.has(k)), 'E1_BOUND_SCHEMA_VOCABULARY');
  if (Object.hasOwn(schema, 'const') || Object.hasOwn(schema, 'enum')) {
    need(!['object', 'array'].includes(schema.type), 'E1_BOUND_SCHEMA_ENUM');
    if (Object.hasOwn(schema, 'enum')) need(Array.isArray(schema.enum) && schema.enum.length > 0 && schema.enum.length <= 32 && new Set(schema.enum.map(canonicalize)).size === schema.enum.length, 'E1_BOUND_SCHEMA_ENUM');
    for (const literal of [...(Object.hasOwn(schema, 'const') ? [schema.const] : []), ...(schema.enum ?? [])]) {
      const testSchema = {...schema}; delete testSchema.const; delete testSchema.enum; walk(testSchema, literal, testSchema, '$');
    }
  }
  if (schema.type === 'object') {
    need(schema.additionalProperties === false && schema.properties && Object.getPrototypeOf(schema.properties) === Object.prototype && Array.isArray(schema.required) && schema.required.every(k => typeof k === 'string' && Object.hasOwn(schema.properties, k)), 'E1_BOUND_SCHEMA_OBJECT');
    need(Object.keys(schema.properties).length <= 32 && new Set(schema.required).size === schema.required.length, 'E1_BOUND_SCHEMA_OBJECT');
    Object.values(schema.properties).forEach(child => inspectBoundSchema(child, depth + 1));
  }
  if (schema.type === 'array') { need(Number.isSafeInteger(schema.maxItems) && schema.maxItems >= 0 && schema.maxItems <= 64 && schema.items && (!Object.hasOwn(schema, 'minItems') || Number.isSafeInteger(schema.minItems) && schema.minItems >= 0 && schema.minItems <= schema.maxItems) && (!Object.hasOwn(schema, 'uniqueItems') || typeof schema.uniqueItems === 'boolean'), 'E1_BOUND_SCHEMA_ARRAY'); inspectBoundSchema(schema.items, depth + 1); }
  if (schema.type === 'string') need(Number.isSafeInteger(schema.maxLength) && schema.maxLength >= 0 && schema.maxLength <= 65536 && (!Object.hasOwn(schema, 'minLength') || Number.isSafeInteger(schema.minLength) && schema.minLength >= 0 && schema.minLength <= schema.maxLength), 'E1_BOUND_SCHEMA_STRING');
  if (schema.type === 'integer') need(Number.isSafeInteger(schema.minimum) && Number.isSafeInteger(schema.maximum) && schema.minimum <= schema.maximum, 'E1_BOUND_SCHEMA_INTEGER');
  if (Object.hasOwn(schema, 'pattern')) { need(typeof schema.pattern === 'string' && schema.pattern.length <= 256, 'E1_BOUND_SCHEMA_PATTERN'); try { new RegExp(schema.pattern, 'u'); } catch { throw new ContractError('E1_BOUND_SCHEMA_PATTERN'); } }
  if (Object.hasOwn(schema, 'format')) need(schema.format === 'date-time', 'E1_BOUND_SCHEMA_FORMAT');
  return immutable(schema);
}
export function validateBoundValue(schema, value) { canonicalize(value); inspectBoundSchema(schema); walk(schema, value, schema, '$'); return immutable(value); }
export function validateContract(type, value) {
  try { canonicalize(value); } catch (error) { throw new ContractError('E1_INVALID_JSON:' + error.message); }
  walk(contractSchema(type), value, SCHEMA_DOCUMENT, '$');
  const contractBudget = type === 'MissionGrant' ? value.budget_cap : value.budget;
  if (contractBudget?.currency === 'NONE') need(contractBudget.amount_micros === '0', 'E1_NONE_BUDGET');
  if (type === 'MissionSpec') { uniqueBy(value.criteria, x => x.criterion_id, 'E1_DUPLICATE_CRITERION'); uniqueBy(value.facts_refs, x => x.artifact_id, 'E1_DUPLICATE_ARTIFACT'); uniqueBy(value.requested_capabilities, capabilityKey, 'E1_DUPLICATE_CAPABILITY'); }
  if (type === 'MissionSpec') { value.facts_refs.forEach(ref => validateContract('ArtifactRef', ref)); value.requested_capabilities.forEach(ref => validateContract('CapabilityRef', ref)); }
  if (type === 'MissionGrant' || type === 'DomainManifest') (value.allowed_capabilities ?? value.capabilities).forEach(ref => validateContract('CapabilityRef', ref));
  if (type === 'PlanRevision') value.tasks.forEach(task => validateContract('TaskSpec', task));
  if (type === 'TaskSpec') { validateContract('CapabilityRef', value.capability); validateContract('EffectIntent', value.effect); }
  if (type === 'EffectIntent' && value.reconcile_capability) validateContract('CapabilityRef', value.reconcile_capability);
  if (type === 'MissionGrant') { uniqueBy(value.allowed_capabilities, capabilityKey, 'E1_DUPLICATE_CAPABILITY'); need(value.issued_at < value.expires_at, 'E1_GRANT_TIME'); need((value.revoked_at === null) === (value.revocation_reason === null), 'E1_GRANT_REVOCATION'); if (value.revoked_at) need(value.revoked_at >= value.issued_at, 'E1_GRANT_REVOCATION'); }
  if (type === 'ArtifactRef') need(value.uri.slice('artifact:'.length).split('/').every(segment => segment.length > 0 && segment !== '.' && segment !== '..'), 'E1_ARTIFACT_URI');
  if (type === 'PlanRevision') uniqueBy(value.tasks, x => x.task_id, 'E1_DUPLICATE_TASK');
  if (type === 'QAResult') { need(value.evaluator_id !== value.producer_id, 'E1_QA_INDEPENDENCE'); uniqueBy(value.checks, x => x.check_id, 'E1_QA_DUPLICATE_CHECK'); if (value.verdict === 'PASS') need(value.checks.every(x => x.passed), 'E1_QA_FAILED_CHECK'); for (const check of value.checks) for (const evidence of check.evidence_refs) { validateContract('ArtifactRef', evidence); need(evidence.project_id === value.project_id && evidence.mission_id === value.mission_id, 'E1_QA_SCOPE'); need(evidence.digest === value.artifact_digest || evidence.origin !== 'UNKNOWN', 'E1_QA_EVIDENCE'); } }
  return immutable(value);
}
export function sealContract(type, value) { const validated = validateContract(type, value); return immutable({type, release: RELEASE, contract_version: CONTRACT_VERSION, schema_digest: schemaDigest(type), digest: digest(validated), value: validated}); }

export function capabilityManifestDigest(descriptor) {
  const copy = structuredClone(descriptor); delete copy.ref.manifest_digest; return digest(copy);
}
export function validateCapabilityDescriptor(value) {
  exact(value, ['ref', 'executor_kind', 'permissions', 'data_classes', 'origins', 'effect_class', 'health_until', 'state', 'max_attempts', 'timeout_ms', 'min_cost_micros', 'supports_reconcile', 'input_schema', 'output_schema']);
  validateContract('CapabilityRef', value.ref);
  need(['script', 'program', 'llm', 'agent', 'bot', 'human'].includes(value.executor_kind), 'E1_EXECUTOR_KIND');
  for (const [field, allowed] of [['permissions', PERMISSIONS], ['data_classes', DATA_CLASSES], ['origins', ORIGINS]]) need(Array.isArray(value[field]) && value[field].length > 0 && value[field].length <= 32 && new Set(value[field]).size === value[field].length && value[field].every(x => allowed.includes(x)), 'E1_CAPABILITY_' + field.toUpperCase());
  need(EFFECT_CLASSES.includes(value.effect_class) && ['ACTIVE', 'REVOKED'].includes(value.state), 'E1_CAPABILITY_STATE'); utc(value.health_until);
  need(Number.isSafeInteger(value.max_attempts) && value.max_attempts >= 1 && value.max_attempts <= 4 && Number.isSafeInteger(value.timeout_ms) && value.timeout_ms >= 1 && value.timeout_ms <= 600000 && typeof value.supports_reconcile === 'boolean' && typeof value.min_cost_micros === 'string' && /^(0|[1-9][0-9]{0,17})$(?![\s\S])/.test(value.min_cost_micros), 'E1_CAPABILITY_LIMITS');
  inspectBoundSchema(value.input_schema); inspectBoundSchema(value.output_schema);
  need(value.ref.input_schema.digest === digest(value.input_schema) && value.ref.output_schema.digest === digest(value.output_schema), 'E1_CAPABILITY_SCHEMA_DIGEST');
  need(value.ref.manifest_digest === capabilityManifestDigest(value), 'E1_CAPABILITY_MANIFEST_DIGEST');
  return immutable(value);
}
export function validateMissionBinding(specInput, grantInput, now) {
  const spec = validateContract('MissionSpec', specInput), grant = validateContract('MissionGrant', grantInput); utc(now);
  need(grant.revoked_at === null, 'E1_GRANT_REVOKED'); need(grant.issued_at <= now && now < grant.expires_at, 'E1_GRANT_EXPIRED');
  need(spec.mission_id === grant.mission_id && spec.project_id === grant.project_id && spec.owner_id === grant.owner_id && grant.issued_by === spec.owner_id, 'E1_GRANT_SCOPE');
  need(grant.spec_digest === digest(spec), 'E1_GRANT_SPEC_DIGEST');
  need(now < spec.deadline && spec.deadline <= grant.expires_at, 'E1_MISSION_DEADLINE');
  need(spec.budget.currency === grant.budget_cap.currency && BigInt(spec.budget.amount_micros) <= BigInt(grant.budget_cap.amount_micros), 'E1_MISSION_BUDGET');
  need(subset(spec.requested_capabilities, grant.allowed_capabilities), 'E1_GRANT_CAPABILITY');
  need(subset(spec.data_classes, grant.allowed_data_classes) && subset(spec.allowed_origins, grant.allowed_origins), 'E1_GRANT_DATA_OR_ORIGIN');
  need(!spec.allowed_origins.some(x => ['INFERRED', 'UNKNOWN'].includes(x)), 'E1_UNTRUSTED_ORIGIN');
  need(spec.max_replans <= grant.max_replans && spec.max_actions <= grant.max_actions, 'E1_GRANT_BOUNDS');
  for (const fact of spec.facts_refs) { need(fact.project_id === spec.project_id && fact.mission_id === spec.mission_id, 'E1_ARTIFACT_SCOPE'); need(spec.data_classes.includes(fact.data_class) && spec.allowed_origins.includes(fact.origin), 'E1_ARTIFACT_CLASS_OR_ORIGIN'); need(fact.created_at <= now, 'E1_ARTIFACT_FUTURE'); }
  return immutable({spec, grant});
}
export function assertNarrowerGrant(previous, next) {
  need(previous.grant_id === next.grant_id && next.grant_version === previous.grant_version + 1 && next.issued_at >= previous.issued_at && next.expires_at <= previous.expires_at, 'E1_GRANT_REVISION');
  for (const key of ['allowed_principals', 'permissions', 'allowed_capabilities', 'allowed_data_classes', 'allowed_origins', 'allowed_effect_classes', 'destinations']) need(subset(next[key], previous[key]), 'E1_GRANT_SELF_ELEVATION');
  need(next.budget_cap.currency === previous.budget_cap.currency && BigInt(next.budget_cap.amount_micros) <= BigInt(previous.budget_cap.amount_micros) && ['max_tasks', 'max_actions', 'max_replans'].every(k => next[k] <= previous[k]), 'E1_GRANT_SELF_ELEVATION');
}
export function validateDomainBinding(spec, domainManifestInput) {
  need(domainManifestInput, 'E1_DOMAIN_MANIFEST_MISSING', 'WAIT');
  const manifest = validateContract('DomainManifest', domainManifestInput);
  need(manifest.project_id === spec.project_id && manifest.manifest_id === spec.domain_manifest.manifest_id && manifest.version === spec.domain_manifest.version && digest(manifest) === spec.domain_manifest.digest, 'E1_DOMAIN_MANIFEST_BINDING');
  need(subset(spec.requested_capabilities, manifest.capabilities), 'E1_DOMAIN_CAPABILITIES');
  return manifest;
}
export function validatePlanRevision(planInput, {spec: specInput, grant: grantInput, capabilities, domainManifest, now}) {
  const plan = validateContract('PlanRevision', planInput), {spec, grant} = validateMissionBinding(specInput, grantInput, now);
  const manifest = validateDomainBinding(spec, domainManifest);
  need(plan.mission_id === spec.mission_id && plan.project_id === spec.project_id && plan.spec_digest === digest(spec) && plan.grant_digest === digest(grant) && plan.grant_version === grant.grant_version, 'E1_PLAN_BINDING');
  need(plan.created_at <= now && plan.created_at >= grant.issued_at && plan.deadline <= spec.deadline && now < plan.deadline, 'E1_PLAN_DEADLINE');
  need(plan.revision <= Math.min(spec.max_replans, grant.max_replans) + 1 && plan.tasks.length <= grant.max_tasks, 'E1_PLAN_BOUNDS');
  const registry = new Map(); for (const raw of capabilities) { const cap = validateCapabilityDescriptor(raw); need(!registry.has(capabilityKey(cap.ref)), 'E1_DUPLICATE_CAPABILITY'); registry.set(capabilityKey(cap.ref), cap); }
  const tasks = Object.create(null); plan.tasks.forEach(task => { tasks[task.task_id] = {dependencies: task.depends_on}; });
  try { validateDag(tasks); } catch (error) { throw new ContractError('E1_' + (error.code ?? error.message)); }
  const byId = new Map(plan.tasks.map(t => [t.task_id, t])), criteria = new Set(spec.criteria.map(x => x.criterion_id)), covered = new Set(), effectIds = new Set();
  let worstBudget = 0n, actions = 0;
  for (const task of plan.tasks) {
    const cap = registry.get(capabilityKey(task.capability)); need(cap, 'E1_CAPABILITY_MISSING', 'WAIT');
    need(cap.state === 'ACTIVE' && now < cap.health_until, 'E1_CAPABILITY_UNAVAILABLE', 'WAIT');
    need(same(task.capability, cap.ref) && subset([task.capability], spec.requested_capabilities) && subset([task.capability], grant.allowed_capabilities), 'E1_CAPABILITY_BINDING');
    validateBoundValue(cap.input_schema, task.input);
    need(task.deadline <= plan.deadline && now < task.deadline && task.timeout_ms <= cap.timeout_ms && task.retry.max_attempts <= cap.max_attempts, 'E1_TASK_BOUNDS');
    need(task.budget.currency === spec.budget.currency && BigInt(task.budget.amount_micros) >= BigInt(cap.min_cost_micros), 'E1_TASK_BUDGET'); worstBudget += BigInt(task.budget.amount_micros) * BigInt(task.retry.max_attempts);
    need(subset(task.data_classes, spec.data_classes) && subset(task.data_classes, grant.allowed_data_classes) && subset(task.data_classes, cap.data_classes), 'E1_TASK_DATA_CLASS');
    need(spec.allowed_origins.includes(task.origin.kind) && grant.allowed_origins.includes(task.origin.kind) && cap.origins.includes(task.origin.kind) && !['UNKNOWN', 'INFERRED'].includes(task.origin.kind), 'E1_TASK_ORIGIN');
    need(task.origin.source_digests.every(hash => spec.facts_refs.some(fact => fact.digest === hash && task.data_classes.includes(fact.data_class) && fact.origin === task.origin.kind)), 'E1_TASK_SOURCE');
    need(task.criterion_ids.every(id => criteria.has(id)), 'E1_TASK_CRITERION'); task.criterion_ids.forEach(id => covered.add(id));
    need(task.qa.rubric_id === manifest.qa_rubric.rubric_id && task.qa.rubric_digest === manifest.qa_rubric.digest && same(task.qa.required_checks, manifest.qa_rubric.checks), 'E1_QA_RUBRIC_BINDING');
    need(task.dependency_bindings.length === task.depends_on.length && new Set(task.dependency_bindings.map(x => x.task_id)).size === task.dependency_bindings.length && task.dependency_bindings.every(binding => task.depends_on.includes(binding.task_id) && same(binding.output_schema, byId.get(binding.task_id).capability.output_schema)), 'E1_DEPENDENCY_SCHEMA');
    need(subset(cap.permissions, grant.permissions), 'E1_CAPABILITY_PERMISSION');
    const effect = task.effect; need(effect.mission_id === spec.mission_id && effect.project_id === spec.project_id && effect.task_id === task.task_id && effect.payload_digest === digest(task.input), 'E1_EFFECT_BINDING');
    need(!effectIds.has(effect.effect_id), 'E1_DUPLICATE_EFFECT'); effectIds.add(effect.effect_id);
    need(effect.effect_class === cap.effect_class && grant.allowed_effect_classes.includes(effect.effect_class), 'E1_EFFECT_SCOPE');
    need(effect.outcome === 'NOT_STARTED', 'E1_RECONCILIATION_REQUIRED', 'WAIT');
    if (effect.effect_class === 'NONE') need(effect.permission === null && effect.destination === null && effect.business_key === null && effect.reconcile_capability === null && effect.max_actions === 0, 'E1_EFFECT_NONE');
    else {
      need(effect.permission !== null && grant.permissions.includes(effect.permission) && cap.permissions.includes(effect.permission) && effect.destination !== null && grant.destinations.includes(effect.destination) && effect.business_key !== null && effect.max_actions === 1, 'E1_EFFECT_PERMISSION');
      const permission = effect.effect_class.startsWith('LOCAL_') ? 'effect.local' : effect.effect_class === 'EXTERNAL_READ' ? 'effect.external_read' : 'effect.external_write'; need(effect.permission === permission, 'E1_EFFECT_PERMISSION');
      if (effect.reconcile_capability) { const reconcile = registry.get(capabilityKey(effect.reconcile_capability)); need(reconcile && same(reconcile.ref, effect.reconcile_capability) && reconcile.state === 'ACTIVE' && now < reconcile.health_until && subset([reconcile.ref], grant.allowed_capabilities) && subset(reconcile.permissions, grant.permissions) && ['NONE', 'LOCAL_READ', 'EXTERNAL_READ'].includes(reconcile.effect_class), 'E1_RECONCILE_CAPABILITY'); }
      if (effect.effect_class === 'EXTERNAL_WRITE') need(cap.supports_reconcile && effect.reconcile_capability !== null && task.retry.max_attempts === 1, 'E1_EXTERNAL_UNKNOWN_POLICY');
      need(!effect.effect_class.startsWith('EXTERNAL_'), 'E1_EXTERNAL_EFFECT_NOT_BOUND', 'WAIT');
    }
    actions += effect.max_actions;
  }
  need(covered.size === criteria.size, 'E1_CRITERIA_COVERAGE');
  need(plan.budget.currency === spec.budget.currency && BigInt(plan.budget.amount_micros) === worstBudget && worstBudget <= BigInt(spec.budget.amount_micros) && worstBudget <= BigInt(grant.budget_cap.amount_micros), 'E1_PLAN_BUDGET');
  need(actions <= spec.max_actions && actions <= grant.max_actions, 'E1_PLAN_ACTIONS');
  const finish = new Map(); const earliestFinish = id => { if (finish.has(id)) return finish.get(id); const task = byId.get(id); const start = Math.max(Date.parse(now), ...task.depends_on.map(earliestFinish)); const result = start + task.timeout_ms * task.retry.max_attempts; need(result <= Date.parse(task.deadline), 'E1_CRITICAL_PATH_DEADLINE'); finish.set(id, result); return result; }; plan.tasks.forEach(t => earliestFinish(t.task_id));
  return immutable({decision: 'VALIDATED', release: RELEASE, plan_digest: digest(plan), spec_digest: digest(spec), grant_digest: digest(grant), registry_digest: capabilityRegistryDigest([...registry.values()]), worst_budget: plan.budget, actions, accepted: false, execution_authorized: false});
}
