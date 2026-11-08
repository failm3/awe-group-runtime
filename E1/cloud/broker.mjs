import {performance} from 'node:perf_hooks';
import {digest, immutable, need, utc, validateBoundValue, validateMissionBinding} from '../contracts/index.mjs';
import {isRouterCheapHostTransport} from '../host/router-cheap/transport.mjs';
import {isRouterCheapHostPolicy, getRouterCheapHostPolicySnapshot} from '../host/router-cheap/host-policy.mjs';
import {CLOUD_ENDPOINT, cloudQuote, requireCloudCapability, validateCloudCatalog} from './registry.mjs';
import {ceil, nativeMicros, sourceCost, unsigned} from './pricing.mjs';

const LIVE = 'HOST_BOUND_CLOUD';
const TEST = 'OFFLINE_TEST_DOUBLE';
const SYNTHETIC_CHARGE = 'EXPLICIT_SYNTHETIC_FAKE_PROVIDER_CHARGED_COST';
const logicalRequests = new Set();
const ID = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/;
const HASH = /^sha256:[a-f0-9]{64}$/;
const SAFE_CODES = new Set(('CLOUD_ACCOUNTING_REQUIRED CLOUD_POLICY_REQUIRED CLOUD_POLICY_IDENTITY CLOUD_POLICY_EXPIRED CLOUD_POLICY_SCOPE CLOUD_POLICY_BINDING CLOUD_HARD_CAP_UNKNOWN CLOUD_BUDGET_UNKNOWN CLOUD_BUDGET_DENIED CLOUD_PRIVACY_DENIED CLOUD_INPUT_BOUND CLOUD_INPUT_BOUND_UNKNOWN CLOUD_ATTEMPT_SCOPE CLOUD_ATTEMPT_REUSED CLOUD_ATTEMPT_MEMORY_BOUND CLOUD_ROUTE_DENIED CLOUD_TOKEN_LIMIT CLOUD_REGISTRY_REQUIRED CLOUD_CAPABILITY_MISSING CLOUD_CAPABILITY_DENIED CLOUD_CAPABILITY_ROUTE_DENIED CLOUD_CAPABILITY_BINDING CLOUD_PERMISSION_DENIED CLOUD_DEADLINE_DENIED CLOUD_CATALOG_IDENTITY CLOUD_PRICE_STALE CLOUD_CATALOG_PROVENANCE CLOUD_ROUTES_UNKNOWN CLOUD_ROUTE_IDENTITY CLOUD_LIMITS_UNKNOWN CLOUD_FEATURE_UNKNOWN CLOUD_SOURCE_UNKNOWN CLOUD_PRICE_UNKNOWN CLOUD_PRICE_PROVENANCE CLOUD_NATIVE_AMOUNT_BOUND E1_GRANT_REVOKED E1_GRANT_EXPIRED E1_GRANT_SCOPE E1_GRANT_SPEC_DIGEST E1_MISSION_DEADLINE E1_MISSION_BUDGET E1_GRANT_CAPABILITY E1_GRANT_DATA_OR_ORIGIN E1_UNTRUSTED_ORIGIN E1_GRANT_BOUNDS E1_ARTIFACT_SCOPE E1_ARTIFACT_CLASS_OR_ORIGIN E1_ARTIFACT_FUTURE E1_SCHEMA_TYPE E1_SCHEMA_REQUIRED E1_SCHEMA_EXTRA E1_SCHEMA_STRING E1_SCHEMA_RANGE E1_SCHEMA_CONST E1_SCHEMA_ENUM E1_SCHEMA_ITEM_COUNT').split(' '));
const safeReason = error => SAFE_CODES.has(error?.code) ? error.code : 'CLOUD_PRE_SEND_FAILURE';
const controlled = (decision, reason, more = {}) => immutable({decision, reason, accepted: false, effects: 0, wire_attempts: 0, ...more});
function privacyGuard(value) {
  const text = JSON.stringify(value);
  need(typeof text === 'string' && Buffer.byteLength(text) <= 49152, 'CLOUD_INPUT_BOUND');
  need(!/(?:[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:api[_-]?key|authorization|password|secret|access[_-]?token)\s*["']?\s*[:=]\s*["']?[^\s"']{6,}|\b(?:sk|ghp|github_pat)-[a-z0-9_-]{12,})/i.test(text), 'CLOUD_PRIVACY_DENIED');
}
function validatePolicy(snapshot, {now, spec, grant, catalog, route_id, quote, evidence_level}) {
  const policy = immutable(snapshot); utc(now);
  need(policy.schema === 'awe.e1.router-cheap.host-policy/1' && policy.budget_group_id === 'router.cheap.shared/1' && ID.test(policy.key_binding_id), 'CLOUD_POLICY_IDENTITY');
  utc(policy.issued_at); utc(policy.expires_at);
  need(policy.issued_at <= now && now < policy.expires_at, 'CLOUD_POLICY_EXPIRED');
  need(policy.project_id === spec.project_id && policy.mission_id === spec.mission_id, 'CLOUD_POLICY_SCOPE');
  need(policy.spec_digest === digest(spec) && policy.mission_grant_digest === digest(grant) && policy.catalog_digest === digest(catalog) && Array.isArray(policy.allowed_route_ids) && policy.allowed_route_ids.includes(route_id), 'CLOUD_POLICY_BINDING');
  const cap = policy.hard_cap;
  need(cap && cap.kind === (evidence_level === TEST ? TEST : 'PROVIDER_ACTUAL_CHARGE_HARD_LIMIT') && HASH.test(cap.evidence_digest), 'CLOUD_HARD_CAP_UNKNOWN');
  utc(cap.observed_at); utc(cap.expires_at);
  need(cap.observed_at <= now && now < cap.expires_at && Date.parse(now) - Date.parse(cap.observed_at) <= 300000, 'CLOUD_HARD_CAP_UNKNOWN');
  const hard = unsigned(cap.cap_micros, 'CLOUD_HARD_CAP_UNKNOWN'), total = unsigned(policy.total_cap_micros, 'CLOUD_BUDGET_UNKNOWN'), perAttempt = unsigned(policy.per_attempt_cap_micros, 'CLOUD_BUDGET_UNKNOWN');
  need(hard > 0n && total > 0n && total <= hard && perAttempt > 0n && perAttempt <= total && Number.isSafeInteger(policy.max_attempts) && policy.max_attempts > 0 && policy.max_attempts <= 15, 'CLOUD_BUDGET_DENIED');
  need(spec.budget.currency === 'USD' && grant.budget_cap.currency === 'USD' && BigInt(quote.reserve_micros) <= BigInt(spec.budget.amount_micros) && BigInt(quote.reserve_micros) <= BigInt(grant.budget_cap.amount_micros) && BigInt(quote.reserve_micros) <= perAttempt, 'CLOUD_BUDGET_DENIED');
  nativeMicros(quote.reserve_micros);
  return policy;
}
async function readBoundJson(response) {
  need(response && response.ok === true && response.status === 200 && response.redirected === false && (!response.url || response.url === CLOUD_ENDPOINT), 'CLOUD_HTTP_UNKNOWN');
  need(/^application\/json(?:;|$)/i.test(response.headers?.get('content-type') ?? ''), 'CLOUD_HTTP_UNKNOWN');
  const reader = response.body?.getReader(); need(reader, 'CLOUD_RESPONSE_UNKNOWN');
  let bytes = 0; const chunks = [];
  try {
    while (true) {
      const item = await reader.read(); if (item.done) break;
      bytes += item.value.byteLength; need(bytes <= 131072, 'CLOUD_RESPONSE_BOUND'); chunks.push(Buffer.from(item.value));
    }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  return immutable(JSON.parse(Buffer.concat(chunks).toString('utf8')));
}
function acknowledgedUsage(ack, quote, latency_ms, evidence_level) {
  need(ID.test(ack.id) && ack.model === quote.model_id && ID.test(ack.source_id), 'CLOUD_ACK_IDENTITY_UNKNOWN');
  const source = quote.route_snapshot.sources.find(x => x.source_id === ack.source_id); need(source, 'CLOUD_ACK_IDENTITY_UNKNOWN');
  const input_tokens = ack.usage?.prompt_tokens, output_tokens = ack.usage?.completion_tokens, cached_input_tokens = ack.usage?.prompt_tokens_details?.cached_tokens;
  need([input_tokens, output_tokens, cached_input_tokens].every(x => Number.isSafeInteger(x) && x >= 0) && cached_input_tokens <= input_tokens && input_tokens <= quote.max_input_tokens && output_tokens <= quote.max_output_tokens, 'CLOUD_USAGE_UNKNOWN');
  const charge = ack.actual_charge;
  need(charge?.currency === 'USD' && (charge.evidence_label === 'PROVIDER_AUTHENTICATED_BILLING' || evidence_level === TEST && charge.evidence_label === SYNTHETIC_CHARGE) && HASH.test(charge.evidence_digest), 'CLOUD_CHARGE_UNKNOWN');
  const actual = unsigned(charge.amount_micros, 'CLOUD_CHARGE_UNKNOWN');
  const cost = sourceCost(source, {input_tokens, cached_input_tokens, output_tokens});
  need(actual === cost.rounded_micros && actual <= BigInt(quote.reserve_micros), 'CLOUD_CHARGE_MISMATCH');
  return immutable({provider: 'router.cheap', model: quote.model_id, source_id: source.source_id, provider_request_id: ack.id, input_tokens, cached_input_tokens, output_tokens, latency_ms, wire_attempts: 1, actual_charge_micros: actual.toString(), base_cost_micros: ceil(cost.base).toString(), base_cost: {numerator: cost.base.n.toString(), denominator: cost.base.d.toString()}, source_coefficient: source.coefficient, price_evidence_digest: source.price_evidence_digest, charge_evidence_digest: charge.evidence_digest, charge_evidence_label: evidence_level === TEST ? SYNTHETIC_CHARGE : charge.evidence_label, quote_digest: quote.quote_digest, route_snapshot_digest: quote.route_snapshot_digest});
}

function makeBroker({accounting, registry, clock = () => new Date().toISOString(), timeoutMs = 120000}, binding) {
  need(accounting && ['reserve', 'markSending', 'settle', 'unknown', 'failBeforeSend'].every(key => typeof accounting[key] === 'function'), 'CLOUD_ACCOUNTING_REQUIRED');
  need(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 120000, 'CLOUD_TOKEN_LIMIT');
  const {evidence_level} = binding;
  async function invoke(untrustedRequest) {
    let scope, quote, policy, request_hash, usage, reserveAttempted = false, reserveConfirmed = false, markerAttempted = false, sent = false, settled = false, dedupeKey, dedupeOwned = false;
    try {
      const request = immutable(untrustedRequest);
      const {spec, grant, capability_id, input, data_label, route_id, max_input_tokens, max_output_tokens} = request; scope = request.scope;
      need(scope && ['mission_id', 'task_id', 'logical_request_id', 'attempt_id', 'worker_id'].every(key => typeof scope[key] === 'string' && ID.test(scope[key])) && /^(0|[1-9][0-9]{0,15})$/.test(String(scope.fence)) && BigInt(scope.fence) > 0n && BigInt(scope.fence) <= BigInt(Number.MAX_SAFE_INTEGER) && scope.mission_id === spec.mission_id && grant.allowed_principals.includes(scope.worker_id), 'CLOUD_ATTEMPT_SCOPE');
      // This fixed object prevents untrusted extra scope fields reaching A2.
      scope = immutable(Object.fromEntries(['mission_id', 'task_id', 'logical_request_id', 'attempt_id', 'worker_id', 'fence'].map(key => [key, scope[key]])));
      const catalog = validateCloudCatalog(binding.catalog(), clock());
      quote = cloudQuote({catalog, route_id, max_input_tokens, max_output_tokens, now: clock()});
      const route = quote.route_snapshot;
      const revalidate = () => {
        const now = clock(); validateMissionBinding(spec, grant, now); validateCloudCatalog(binding.catalog(), now);
        need(digest(binding.catalog()) === quote.catalog_digest, 'CLOUD_POLICY_BINDING');
        const cap = requireCloudCapability(registry, capability_id, route, now);
        validateBoundValue(cap.input_schema, input);
        need(spec.requested_capabilities.some(x => digest(x) === digest(cap.ref)) && grant.allowed_capabilities.some(x => digest(x) === digest(cap.ref)), 'CLOUD_CAPABILITY_BINDING');
        need(cap.permissions.every(x => grant.permissions.includes(x)), 'CLOUD_PERMISSION_DENIED');
        need(['SYNTHETIC', 'CLEAN_CODE'].includes(data_label) && spec.data_classes.every(x => ['PUBLIC', 'PROJECT'].includes(x) && cap.data_classes.includes(x) && grant.allowed_data_classes.includes(x)) && spec.allowed_origins.every(x => ['OWNER', 'PROJECT'].includes(x) && cap.origins.includes(x)), 'CLOUD_PRIVACY_DENIED');
        need(Date.parse(now) + timeoutMs <= Date.parse(spec.deadline), 'CLOUD_DEADLINE_DENIED');
        policy = validatePolicy(binding.policy(), {now, spec, grant, catalog, route_id, quote, evidence_level});
        return cap;
      };
      const cap = revalidate(); privacyGuard(input); privacyGuard(spec.goal);
      const body = immutable({model: quote.model_id, messages: [{role: 'user', content: input.instruction}], stream: false, max_tokens: max_output_tokens, temperature: 0, response_format: {type: 'json_schema', json_schema: {name: 'awe_e1_bounded_output', strict: true, schema: cap.output_schema}}});
      // The opaque host verifies the full serialized request and schema, never
      // merely a caller-provided token estimate or a catalogue feature flag.
      need(await binding.verifyInputBound({body, max_input_tokens, model_id: quote.model_id, input_bound_evidence_digest: route.input_bound_evidence_digest}) === true, 'CLOUD_INPUT_BOUND_UNKNOWN');
      revalidate(); request_hash = digest(body);
      dedupeKey = [spec.project_id, scope.mission_id, scope.logical_request_id].join(':');
      need(!logicalRequests.has(dedupeKey), 'CLOUD_ATTEMPT_REUSED'); need(logicalRequests.size < 4096, 'CLOUD_ATTEMPT_MEMORY_BOUND');
      logicalRequests.add(dedupeKey); dedupeOwned = true;
      reserveAttempted = true;
      const reserved = await accounting.reserve({...scope, reserve_micros: nativeMicros(quote.reserve_micros), quota_units: 1, route_id, request_hash, capability_id: cap.ref.capability_id, capability_version: cap.ref.version, cloud: {route_snapshot_digest: quote.route_snapshot_digest, quote_digest: quote.quote_digest, input_tokens_bound: max_input_tokens, cached_input_tokens_bound: max_input_tokens, output_tokens_bound: max_output_tokens, worst_case_micros: quote.reserve_micros, request_charge_cap_micros: quote.reserve_micros}});
      need(reserved?.status === 'RESERVED', 'CLOUD_RESERVATION_DENIED'); reserveConfirmed = true;
      revalidate();
      markerAttempted = true;
      const marked = await accounting.markSending(scope); need(marked?.status === 'SENDING', 'CLOUD_SENDING_DENIED');
      // Expiry/revocation during SENDING is a hold with retained reserve. It
      // never calls failBeforeSend after an ambiguous durable send transition.
      revalidate();
      const controller = new AbortController(), timer = setTimeout(() => controller.abort(), timeoutMs);
      let ack;
      try {
        sent = true; const start = performance.now();
        const aborted = new Promise((resolve, reject) => controller.signal.addEventListener('abort', () => reject(new Error('CLOUD_TIMEOUT')), {once: true}));
        ack = await Promise.race([Promise.resolve(binding.send({url: CLOUD_ENDPOINT, method: 'POST', redirect: 'error', body, request_hash, quote_digest: quote.quote_digest, max_input_tokens, signal: controller.signal})).then(readBoundJson), aborted]);
        usage = acknowledgedUsage(ack, quote, Math.ceil(performance.now() - start), evidence_level);
      } finally { clearTimeout(timer); }
      const settlement = await accounting.settle({...scope, actual_cost_micros: nativeMicros(usage.actual_charge_micros), provider_ref: usage.provider_request_id, usage, cloud: {route_snapshot_digest: quote.route_snapshot_digest, quote_digest: quote.quote_digest, provider_request_id: usage.provider_request_id, source_id: usage.source_id, actual_charged_micros: usage.actual_charge_micros, base_cost_micros: usage.base_cost_micros, source_coefficient: usage.source_coefficient, source_factor_ref: usage.source_id, source_factor_digest: usage.price_evidence_digest, charge_evidence_digest: usage.charge_evidence_digest, charge_evidence_label: usage.charge_evidence_label}});
      need(settlement?.status === 'CONFIRMED', 'CLOUD_SETTLEMENT_FAILED'); settled = true;
      const metrics = {wire_attempts: 1, accounting_status: 'CONFIRMED', usage, request_hash, quote_digest: quote.quote_digest, evidence_level};
      if (ack.choices?.length !== 1 || ack.choices[0]?.finish_reason !== 'stop') return controlled('REPAIR', ack.choices?.[0]?.finish_reason === 'length' ? 'CLOUD_OUTPUT_TRUNCATED' : 'CLOUD_OUTPUT_INCOMPLETE', metrics);
      let output;
      try {
        const content = ack.choices[0]?.message?.content;
        need(typeof content === 'string' && Buffer.byteLength(content) <= 65536, 'CLOUD_OUTPUT_BOUND');
        output = validateBoundValue(cap.output_schema, JSON.parse(content));
      } catch { return controlled('REPAIR', 'CLOUD_MALFORMED_STRUCTURED_OUTPUT', metrics); }
      return controlled('PROPOSED', 'CLOUD_RESPONSE_VALIDATED', {...metrics, output, output_digest: digest(output)});
    } catch (error) {
      if (settled) return controlled('REPAIR', 'CLOUD_OUTPUT_INCOMPLETE', {wire_attempts: 1, accounting_status: 'CONFIRMED', usage, evidence_level});
      if (sent || markerAttempted || reserveAttempted && !reserveConfirmed) {
        let accounting_status = 'UNKNOWN_WRITE_FAILED';
        const reason = sent ? 'CLOUD_POSSIBLE_SEND' : markerAttempted ? 'CLOUD_MARK_SENDING_UNCERTAIN' : 'CLOUD_RESERVATION_UNCERTAIN';
        try { const marked = await accounting.unknown({...scope, reason}); if (['UNKNOWN', 'OUTCOME_UNKNOWN'].includes(marked?.status)) accounting_status = 'UNKNOWN'; } catch {}
        return controlled('HOLD', reason, {wire_attempts: sent ? 1 : 0, accounting_status, usage: usage ?? null, evidence_level});
      }
      if (reserveConfirmed) {
        try {
          const released = await accounting.failBeforeSend({...scope, reason: 'CLOUD_PROVEN_NO_SEND'}); need(released?.status === 'FAILED', 'CLOUD_PRE_SEND_RELEASE_FAILED');
          if (dedupeOwned) logicalRequests.delete(dedupeKey);
          return controlled('BLOCK', safeReason(error), {reservation_released: true, accounting_status: 'FAILED', evidence_level});
        } catch {
          let accounting_status = 'UNKNOWN_WRITE_FAILED';
          try { const marked = await accounting.unknown({...scope, reason: 'CLOUD_PRE_SEND_RELEASE_UNCERTAIN'}); if (['UNKNOWN', 'OUTCOME_UNKNOWN'].includes(marked?.status)) accounting_status = 'UNKNOWN'; } catch {}
          return controlled('HOLD', 'CLOUD_PRE_SEND_RELEASE_UNCERTAIN', {accounting_status, evidence_level});
        }
      }
      return controlled('BLOCK', safeReason(error), {evidence_level});
    }
  }
  return Object.freeze({evidence_level, invoke});
}

/** Only host-created opaque transport and authenticated policy capabilities can
 * cross this boundary. No public raw-fetch injection or activation boolean. */
export function createCloudModelBroker(options) {
  need(options && Object.keys(options).every(key => ['accounting', 'registry', 'clock', 'timeoutMs', 'transport', 'policy'].includes(key)), 'CLOUD_LIVE_CONFIG_DENIED');
  need(isRouterCheapHostTransport(options.transport), 'CLOUD_HOST_TRANSPORT_REQUIRED');
  need(isRouterCheapHostPolicy(options.policy), 'CLOUD_POLICY_REQUIRED');
  const transport = options.transport, policyToken = options.policy;
  need(typeof transport.send === 'function' && typeof transport.verifyInputBound === 'function', 'CLOUD_HOST_TRANSPORT_REQUIRED');
  const send = transport.send.bind(transport), verifyInputBound = transport.verifyInputBound.bind(transport);
  const snapshot = () => getRouterCheapHostPolicySnapshot(policyToken);
  return makeBroker(options, {evidence_level: LIVE, policy: snapshot, catalog: () => snapshot().catalog, send, verifyInputBound});
}

/** Deliberately cannot emit live evidence. This path never mints host tokens. */
export function createOfflineCloudModelBrokerForTests(options, {transport, inputTokenBound, label}) {
  need(label === TEST && typeof transport === 'function' && typeof inputTokenBound === 'function', 'CLOUD_TEST_DOUBLE_LABEL_REQUIRED');
  const {catalog, policy, ...brokerOptions} = options;
  return makeBroker(brokerOptions, {evidence_level: TEST, policy: () => typeof policy === 'function' ? policy() : policy, catalog: () => typeof catalog === 'function' ? catalog() : catalog, send: transport, verifyInputBound: inputTokenBound});
}
