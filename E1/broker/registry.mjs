import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {RELEASE, CONTRACT_VERSION, immutable, digest, need, utc, capabilityManifestDigest, validateCapabilityDescriptor, validateMissionBinding, capabilityKey} from '../contracts/index.mjs';
import {INSTRUCTION_SCHEMA, TEXT_SCHEMA, HEAD_DRAFT_SCHEMA, MODEL_POLICY} from './schemas.mjs';

const SOURCE_FILES = ['schemas.mjs', 'registry.mjs', 'head.mjs', 'model.mjs', 'canary.mjs', 'benchmark.mjs', 'index.mjs'];
export function brokerSourcePins() {
  const files = SOURCE_FILES.map(file => ({file: 'E1/broker/' + file, digest: 'sha256:' + createHash('sha256').update(readFileSync(new URL(file, import.meta.url))).digest('hex')}));
  return immutable({files, build_digest: digest(files), node: process.version});
}
const versioned = value => ({contract_version: CONTRACT_VERSION, release: RELEASE, ...value});
const binding = (schema_id, schema) => ({schema_id, version: '1.0.0', digest: digest(schema)});

/** Registry envelope adds deployment evidence without changing A1's frozen descriptor. */
export function createBrokerRegistry({now = new Date().toISOString(), healthUntil = new Date(Date.parse(now) + 3600000).toISOString()} = {}) {
  utc(now); utc(healthUntil); need(now < healthUntil, 'A3_HEALTH_TIME');
  const pins = brokerSourcePins();
  const entries = [
    ['e1.code.parse', 'script', TEXT_SCHEMA, 'e1.text'],
    ['e1.code.review', 'llm', TEXT_SCHEMA, 'e1.text'],
    ['e1.head.plan', 'llm', HEAD_DRAFT_SCHEMA, 'e1.head.draft']
  ].map(([capability_id, executor_kind, output_schema, outputId]) => {
    const descriptor = {ref: versioned({capability_id, version: '1.0.0', manifest_digest: 'sha256:' + '0'.repeat(64), input_schema: binding('e1.instruction', INSTRUCTION_SCHEMA), output_schema: binding(outputId, output_schema)}), executor_kind, permissions: ['artifact.read', 'artifact.write'], data_classes: ['PUBLIC', 'PROJECT'], origins: ['OWNER', 'PROJECT'], effect_class: 'NONE', health_until: healthUntil, state: 'ACTIVE', max_attempts: 1, timeout_ms: executor_kind === 'llm' ? 120000 : 1000, min_cost_micros: '0', supports_reconcile: false, input_schema: INSTRUCTION_SCHEMA, output_schema};
    descriptor.ref.manifest_digest = capabilityManifestDigest(descriptor);
    return {descriptor: validateCapabilityDescriptor(descriptor), registry_version: 'awe.e1.capabilities/1', source_pin: pins.build_digest, build_pin: pins.build_digest, schema_pins: [descriptor.ref.input_schema.digest, descriptor.ref.output_schema.digest], platforms: [process.platform], placement: 'LOCAL_HOST', installed: true, approved_status: 'BOUNDED_CANARY', required_permissions: descriptor.permissions, limits: {max_parallel: 1, max_attempts: 1, timeout_ms: descriptor.timeout_ms, context_tokens: executor_kind === 'llm' ? [4096, 8192] : [], output_tokens: executor_kind === 'llm' ? [512, 2048] : []}, data_labels: ['SYNTHETIC', 'CLEAN_CODE'], cost: {basis: 'API_MICROS', reserve_micros: 0, accepted_result_cost: 'NOT_MEASURED', infrastructure_cost: 'NOT_MEASURED'}, health: {checked_at: now, until: healthUntil, installed_code: true, model_backend: executor_kind === 'llm' ? 'CHECK_BEFORE_EACH_ATTEMPT' : 'NOT_APPLICABLE'}, last_canary: {status: 'NOT_RUN', sample_size: 0}, retry: 'NONE', reconcile: 'HOLD_ON_UNKNOWN', quality_suite: 'e1.code-maintenance.frozen-rubric/1', model_binding: executor_kind === 'llm' ? MODEL_POLICY : null};
  });
  return immutable({version: 'awe.e1.capabilities/1', created_at: now, source: pins, policy: MODEL_POLICY, entries, descriptors: entries.map(entry => entry.descriptor), digest: digest(entries)});
}

export function requireRegistryEntry(registry, capabilityId, now) {
  utc(now); need(registry?.version === 'awe.e1.capabilities/1', 'A3_REGISTRY_REQUIRED');
  const entry = registry.entries.find(x => x.descriptor.ref.capability_id === capabilityId);
  need(entry, 'A3_CAPABILITY_MISSING', 'WAIT'); validateCapabilityDescriptor(entry.descriptor);
  need(entry.installed && entry.descriptor.state === 'ACTIVE' && now < entry.descriptor.health_until && now < entry.health.until, 'A3_CAPABILITY_UNAVAILABLE', 'WAIT');
  need(entry.platforms.includes(process.platform), 'A3_PLATFORM_DENIED');
  need(entry.source_pin === brokerSourcePins().build_digest && entry.build_pin === entry.source_pin, 'A3_SOURCE_PIN_MISMATCH');
  return entry;
}

/** Selection is data only. Dispatch still requires the A2 accounting/claim port. */
export function selectExecutor({registry, task, spec, grant, now = new Date().toISOString(), remaining_micros = 0, purpose = 'BOUNDED_CANARY'}) {
  validateMissionBinding(spec, grant, now);
  need(task && ['deterministic', 'semantic', 'head'].includes(task.kind), 'A3_TASK_KIND');
  need(Number.isSafeInteger(remaining_micros) && remaining_micros >= 0, 'A3_BUDGET_DENIED');
  const wanted = task.capability_id ?? (task.kind === 'deterministic' ? 'e1.code.parse' : task.kind === 'head' ? 'e1.head.plan' : 'e1.code.review');
  const rejected = [], candidates = [];
  for (const item of registry.entries) {
    const cap = item.descriptor;
    let reason;
    try {
      requireRegistryEntry(registry, cap.ref.capability_id, now);
      need(purpose === 'BOUNDED_CANARY' && item.approved_status === 'BOUNDED_CANARY', 'A3_CANARY_ONLY');
      need(spec.requested_capabilities.some(x => digest(x) === digest(cap.ref)) && grant.allowed_capabilities.some(x => digest(x) === digest(cap.ref)), 'A3_CAPABILITY_DENIED');
      need(cap.permissions.every(x => grant.permissions.includes(x)), 'A3_PERMISSION_DENIED');
      need((task.data_classes ?? spec.data_classes).every(x => cap.data_classes.includes(x) && grant.allowed_data_classes.includes(x)), 'A3_PRIVACY_DENIED');
      need(item.data_labels.includes(task.data_label), 'A3_DATA_LABEL_DENIED');
      need(spec.allowed_origins.every(x => cap.origins.includes(x)) && grant.allowed_effect_classes.includes(cap.effect_class), 'A3_ORIGIN_OR_EFFECT_DENIED');
      need(Number(cap.min_cost_micros) <= remaining_micros, 'A3_BUDGET_DENIED');
      need(Date.parse(task.deadline ?? spec.deadline) >= Date.parse(now) + cap.timeout_ms, 'A3_DEADLINE_DENIED');
      need(cap.ref.capability_id === wanted, 'A3_OPERATION_MISMATCH');
      need(task.kind === 'deterministic' ? cap.executor_kind === 'script' : cap.executor_kind === 'llm', 'A3_EXECUTOR_KIND_MISMATCH');
      candidates.push(item);
    } catch (error) { reason = error.code ?? 'A3_SELECTOR_DENIED'; }
    if (reason) rejected.push({capability: capabilityKey(cap.ref), executor_kind: cap.executor_kind, reason});
  }
  if (!candidates.length) return immutable({decision: 'WAIT', reason: 'A3_NO_ALLOWED_ROUTE', rejected, selected: null, automatic_retry: false, accepted: false});
  const selected = candidates[0];
  return immutable({decision: 'SELECTED', reason: task.kind === 'deterministic' ? 'DETERMINISTIC_SCRIPT_FIRST' : 'ONE_BOUNDED_SEMANTIC_MODEL', selected, rejected, worst_reserve_micros: 0, automatic_retry: false, accepted: false});
}
