import {performance} from 'node:perf_hooks';
import {digest, immutable, need, validateBoundValue, validateMissionBinding} from '../contracts/index.mjs';
import {MODEL_POLICY, HEAD_DRAFT_SCHEMA} from './schemas.mjs';
import {requireRegistryEntry} from './registry.mjs';
import {materializeHeadDraft, headPrompt} from './head.mjs';

let inferenceInFlight = false;
const cleanId = value => typeof value === 'string' && /^[a-z][a-z0-9_.:-]{0,159}$/.test(value);
const controlled = (decision, reason, more = {}) => immutable({decision, reason, accepted: false, effects: 0, wire_attempts: 0, ...more});
function privacyGuard(text) {
  need(typeof text === 'string' && Buffer.byteLength(text) <= 24576, 'A3_INPUT_BOUND');
  need(!/(?:[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:api[_-]?key|authorization|password|secret|access[_-]?token)\s*[:=]\s*["']?[^\s"']{6,}|\b(?:sk|ghp|github_pat)-[a-z0-9_-]{12,})/i.test(text), 'A3_PRIVACY_DENIED');
}
async function readBoundJson(response) {
  need(response && response.ok === true && !response.redirected, 'A3_BACKEND_HTTP');
  const reader = response.body?.getReader(); need(reader, 'A3_BACKEND_BODY');
  let size = 0; const chunks = [];
  try { while (true) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; need(size <= 131072, 'A3_RESPONSE_BOUND'); chunks.push(Buffer.from(part.value)); } }
  catch (error) { await reader.cancel().catch(() => {}); throw error; }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
function usageFrom(ack, latency_ms) {
  for (const key of ['prompt_eval_count', 'eval_count', 'total_duration', 'eval_duration', 'load_duration', 'prompt_eval_duration']) need(Number.isSafeInteger(ack[key]) && ack[key] >= 0, 'A3_USAGE_MISSING');
  need(ack.model === MODEL_POLICY.model && ack.done === true && ['stop', 'length'].includes(ack.done_reason) && typeof ack.created_at === 'string' && Number.isFinite(Date.parse(ack.created_at)), 'A3_BACKEND_ACK');
  return {input_tokens: ack.prompt_eval_count, output_tokens: ack.eval_count, total_duration_ns: ack.total_duration, eval_duration_ns: ack.eval_duration, load_duration_ns: ack.load_duration, prompt_eval_duration_ns: ack.prompt_eval_duration, latency_ms, model: ack.model, digest: MODEL_POLICY.digest, wire_attempts: 1};
}

function makeBroker({accounting, registry, clock = () => new Date().toISOString(), endpoint = MODEL_POLICY.endpoint, contextTokens = 4096, maxOutputTokens = 1024, timeoutMs = 120000}, transport, evidence_level) {
  need(accounting && ['reserve', 'markSending', 'settle', 'unknown', 'failBeforeSend'].every(method => typeof accounting[method] === 'function'), 'A3_ACCOUNTING_REQUIRED');
  need(endpoint === MODEL_POLICY.endpoint, 'A3_ENDPOINT_DENIED');
  need(MODEL_POLICY.context_tokens.includes(contextTokens) && Number.isInteger(maxOutputTokens) && maxOutputTokens >= 512 && maxOutputTokens <= 2048 && Number.isInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 120000, 'A3_MODEL_LIMITS');
  async function invoke({scope, spec, grant, capability_id, input, data_label = 'SYNTHETIC'}) {
    let sent = false, reserveAttempted = false, reserveConfirmed = false, markerAttempted = false, usage, responseHash, locked = false;
    try {
      const now = clock(); validateMissionBinding(spec, grant, now);
      const entry = requireRegistryEntry(registry, capability_id, now), cap = entry.descriptor;
      need(cap.executor_kind === 'llm' && entry.approved_status === 'BOUNDED_CANARY', 'A3_MODEL_CAPABILITY_DENIED');
      validateBoundValue(cap.input_schema, input);
      need(spec.requested_capabilities.some(x => digest(x) === digest(cap.ref)) && grant.allowed_capabilities.some(x => digest(x) === digest(cap.ref)), 'A3_CAPABILITY_DENIED');
      need(MODEL_POLICY.allowed_data_labels.includes(data_label) && spec.data_classes.every(x => MODEL_POLICY.allowed_data_classes.includes(x) && grant.allowed_data_classes.includes(x)) && spec.allowed_origins.every(x => ['OWNER', 'PROJECT'].includes(x)), 'A3_PRIVACY_DENIED');
      need(cap.permissions.every(x => grant.permissions.includes(x)), 'A3_PERMISSION_DENIED');
      need(scope && ['mission_id', 'task_id', 'logical_request_id', 'attempt_id', 'worker_id'].every(key => cleanId(scope[key])) && scope.mission_id === spec.mission_id && grant.allowed_principals.includes(scope.worker_id) && (Number.isSafeInteger(scope.fence) || typeof scope.fence === 'string'), 'A3_ATTEMPT_SCOPE');
      privacyGuard(input.instruction); privacyGuard(spec.goal);
      need(!inferenceInFlight, 'A3_MODEL_BUSY', 'WAIT'); inferenceInFlight = true; locked = true;
      const controller = new AbortController(), timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const tags = await readBoundJson(await transport(MODEL_POLICY.endpoint + '/api/tags', {method: 'GET', redirect: 'error', signal: controller.signal}));
        const model = tags.models?.find(x => x.name === MODEL_POLICY.model);
        need(model && model.digest === MODEL_POLICY.digest, 'A3_MODEL_PIN_MISMATCH');
        const body = {model: MODEL_POLICY.model, prompt: input.instruction + '\nOUTPUT JSON SCHEMA:\n' + JSON.stringify(cap.output_schema), stream: false, think: false, format: cap.output_schema, keep_alive: '5m', options: {num_ctx: contextTokens, num_predict: maxOutputTokens, temperature: 0, seed: 42}};
        const request_hash = digest(body);
        const accountingScope = {mission_id: scope.mission_id, task_id: scope.task_id, logical_request_id: scope.logical_request_id, attempt_id: scope.attempt_id, worker_id: scope.worker_id, fence: scope.fence};
        reserveAttempted = true;
        const reserved = await accounting.reserve({...accountingScope, reserve_micros: 0, quota_units: 1, route_id: MODEL_POLICY.route_id, request_hash, capability_id: cap.ref.capability_id, capability_version: cap.ref.version});
        need(reserved?.status === 'RESERVED', 'A3_RESERVATION_DENIED');
        reserveConfirmed = true;
        validateMissionBinding(spec, grant, clock()); requireRegistryEntry(registry, capability_id, clock());
        markerAttempted = true;
        const marked = await accounting.markSending(accountingScope); need(marked?.status === 'SENDING', 'A3_SENDING_DENIED');
        const start = performance.now(); sent = true;
        const ack = await readBoundJson(await transport(MODEL_POLICY.endpoint + '/api/generate', {method: 'POST', redirect: 'error', headers: {'content-type': 'application/json'}, body: JSON.stringify(body), signal: controller.signal}));
        usage = usageFrom(ack, Math.ceil(performance.now() - start));
        need(typeof ack.response === 'string', 'A3_RESPONSE_SHAPE'); responseHash = digest({response: ack.response});
        const settlement = await accounting.settle({...accountingScope, actual_cost_micros: 0, usage, provider_ref: 'ollama:' + ack.created_at});
        need(settlement?.status === 'CONFIRMED', 'A3_SETTLEMENT_FAILED');
        if (ack.done_reason === 'length') return controlled('REPAIR', 'A3_OUTPUT_TRUNCATED', {wire_attempts: 1, usage, response_digest: responseHash, request_hash, model: {id: ack.model, digest: model.digest, details: model.details ?? {}}, accounting_status: 'CONFIRMED', evidence_level});
        let output;
        try { output = validateBoundValue(cap.output_schema, JSON.parse(ack.response)); }
        catch { return controlled('REPAIR', 'A3_MALFORMED_STRUCTURED_OUTPUT', {wire_attempts: 1, usage, response_digest: responseHash, accounting_status: 'CONFIRMED', evidence_level}); }
        return controlled('PROPOSED', 'A3_MODEL_RESPONSE_VALIDATED', {wire_attempts: 1, output, output_digest: digest(output), response_digest: responseHash, request_hash, usage, model: {id: ack.model, digest: model.digest, details: model.details ?? {}}, accounting_status: 'CONFIRMED', evidence_level});
      } finally { clearTimeout(timer); }
    } catch (error) {
      if (sent) {
        let accounting_status = 'UNKNOWN_WRITE_FAILED';
        try { await accounting.unknown({...scope, reason: 'A3_POSSIBLE_SEND:' + (error.code ?? (error.name === 'AbortError' ? 'TIMEOUT' : 'TRANSPORT_OR_ACK'))}); accounting_status = 'UNKNOWN'; } catch {}
        return controlled('WAIT', 'A3_OUTCOME_UNKNOWN', {wire_attempts: 1, accounting_status, usage: usage ?? null, evidence_level});
      }
      if (markerAttempted) {
        let accounting_status = 'UNKNOWN_WRITE_FAILED';
        try { await accounting.unknown({...scope, reason: 'A3_MARK_SENDING_UNCERTAIN'}); accounting_status = 'UNKNOWN'; } catch {}
        return controlled('WAIT', 'A3_MARK_SENDING_UNCERTAIN', {accounting_status, wire_attempts: 0, evidence_level});
      }
      if (reserveConfirmed) {
        // No generation fetch or SENDING transition was attempted: release the
        // same durable reservation through A2, never a parallel ledger.
        try {
          const released = await accounting.failBeforeSend({...scope, reason: 'A3_PROVEN_NO_MODEL_SEND'});
          need(released?.status === 'FAILED', 'A3_PRE_SEND_RELEASE_FAILED');
          return controlled(error.disposition === 'WAIT' ? 'WAIT' : 'BLOCK', error.code ?? 'A3_PROVEN_PRE_SEND_FAILURE', {accounting_status: 'FAILED', reservation_released: true, evidence_level});
        } catch {
          let accounting_status = 'UNKNOWN_WRITE_FAILED';
          try { await accounting.unknown({...scope, reason: 'A3_PRE_SEND_RELEASE_UNCERTAIN'}); accounting_status = 'UNKNOWN'; } catch {}
          return controlled('WAIT', 'A3_PRE_SEND_RELEASE_UNCERTAIN', {accounting_status, wire_attempts: 0, evidence_level});
        }
      }
      if (reserveAttempted) {
        let accounting_status = 'UNKNOWN_WRITE_FAILED';
        try { await accounting.unknown({...scope, reason: 'A3_RESERVATION_UNCERTAIN'}); accounting_status = 'UNKNOWN'; } catch {}
        return controlled('WAIT', 'A3_RESERVATION_UNCERTAIN', {accounting_status, wire_attempts: 0, evidence_level});
      }
      const reason = error.code ?? (error.name === 'AbortError' ? 'A3_MODEL_UNAVAILABLE' : 'A3_PRE_SEND_FAILURE');
      return controlled(error.disposition === 'WAIT' || ['A3_MODEL_UNAVAILABLE', 'A3_PRE_SEND_FAILURE'].includes(reason) ? 'WAIT' : 'BLOCK', reason, {evidence_level});
    } finally { if (locked) inferenceInFlight = false; }
  }
  return Object.freeze({policy: MODEL_POLICY, evidence_level, invoke,
    async generateHeadProposal(request) {
      const {scope, spec, grant, source, domainManifest, authority, headContext, plan_id, revision, previous_digest} = request;
      const bridge = {domainManifest, authority, headContext, plan_id, revision, previous_digest};
      // Authenticate before any metadata or inference wire; raw JSON actor fields are not credentials.
      try {
        const probe = {reason: 'Preflight only', tasks: [{task_id: 'preflight', title: 'Preflight', capability_id: 'e1.code.parse', instruction: 'Parse supplied synthetic code.', depends_on: [], criterion_ids: spec.criteria.map(x => x.criterion_id)}]};
        materializeHeadDraft(probe, {spec, grant, capabilities: registry.descriptors, source, ...bridge, now: clock()});
      } catch (error) { return controlled('BLOCK', error.code ?? 'A3_HEAD_AUTHORITY', {evidence_level}); }
      const response = await invoke({scope, spec, grant, capability_id: 'e1.head.plan', input: {instruction: headPrompt({spec, source})}, data_label: request.data_label ?? 'SYNTHETIC'});
      if (response.decision !== 'PROPOSED') return response;
      try {
        const result = materializeHeadDraft(response.output, {spec, grant, capabilities: registry.descriptors, source, ...bridge, now: clock()});
        return immutable({...response, ...result});
      } catch (error) { return immutable({...response, decision: 'REPAIR', reason: error.code ?? 'A3_PLAN_INVALID', output: response.output, accepted: false, effects: 0}); }
    }
  });
}

/** Live public factory has no transport injection, paid routes, retries or alternate endpoint. */
export function createLocalModelBroker(options) {
  need(!Object.hasOwn(options, 'fetchImpl') && !Object.hasOwn(options, 'transport') && !Object.hasOwn(options, 'testMode'), 'A3_TEST_TRANSPORT_DENIED');
  need(Object.keys(options).every(key => ['accounting', 'registry', 'clock', 'endpoint', 'contextTokens', 'maxOutputTokens', 'timeoutMs'].includes(key)), 'A3_LIVE_CONFIG_FIELD_DENIED');
  return makeBroker(options, globalThis.fetch.bind(globalThis), 'LIVE_LOCAL_MODEL');
}
/** Explicit unit-test boundary. Never emits live evidence or accepted=true. */
export function createOfflineModelBrokerForTests(options, {transport, label}) {
  need(label === 'OFFLINE_TEST_DOUBLE' && typeof transport === 'function', 'A3_TEST_DOUBLE_LABEL_REQUIRED');
  return makeBroker(options, transport, 'OFFLINE_TEST_DOUBLE');
}
