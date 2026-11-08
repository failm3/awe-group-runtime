import {digest} from '../../contracts/index.mjs';
import {createMaintenanceMission} from '../../broker/canary.mjs';
import {createOfflineCloudModelBrokerForTests} from '../../cloud/broker.mjs';

export const NOW = '2026-11-08T01:00:00.000Z';
export const LATER = '2026-11-08T01:04:00.000Z';
export const ROUTE = 'router.cheap.chat.gpt-6-sol';
export const HASH = 'sha256:' + 'a'.repeat(64);
const rate = (numerator, denominator = '1') => ({numerator, denominator});
let counter = 0;
export function syntheticCatalog() {
  return {version: 'awe.e1.router-cheap.catalog/1', provider: 'router.cheap', endpoint: 'https://router.cheap/v1/chat/completions', currency: 'USD', observed_at: NOW, expires_at: LATER, official_source: 'https://router.cheap', source_digest: HASH, routes: [{route_id: ROUTE, route_version: '1.0.0', model_id: 'gpt-6-sol', context_tokens: 8192, max_output_tokens: 2048, features: Object.fromEntries(['chat_completions', 'strict_json_schema', 'non_streaming', 'source_identity', 'provider_request_id', 'usage', 'actual_billed_charge', 'bounded_input_tokens'].map(key => [key, 'CONFIRMED'])), input_token_bound: 'HOST_VERIFIED_UPPER_BOUND', input_bound_evidence_digest: HASH, sources: [{source_id: 'synthetic_source', input_micros_per_token: rate('1', '3'), cached_input_micros_per_token: rate('1', '7'), output_micros_per_token: rate('7', '5'), coefficient: rate('5', '3'), price_evidence_digest: HASH}]}]};
}
export function syntheticAck() {
  return {id: 'synthetic_provider_request', model: 'gpt-6-sol', source_id: 'synthetic_source', usage: {prompt_tokens: 12, completion_tokens: 4, prompt_tokens_details: {cached_tokens: 3}}, actual_charge: {currency: 'USD', amount_micros: '16', evidence_label: 'PROVIDER_AUTHENTICATED_BILLING', evidence_digest: HASH}, choices: [{finish_reason: 'stop', message: {content: JSON.stringify({text: 'Synthetic code review.'})}}]};
}
export const jsonResponse = value => new Response(JSON.stringify(value), {status: 200, headers: {'content-type': 'application/json'}});
/** All values here are synthetic and cannot mint either host capability. */
export function cloudFixture({answer = syntheticAck(), overrides = {}, transport, inputTokenBound, timeoutMs, onReserve, onSending} = {}) {
  const suffix = 'cloud_' + (++counter), f = createMaintenanceMission({now: NOW, suffix});
  const spec = structuredClone(f.spec), grant = structuredClone(f.grant), registry = structuredClone(f.registry), catalog = syntheticCatalog();
  spec.budget = {currency: 'USD', amount_micros: '100000'};
  grant.budget_cap = {currency: 'USD', amount_micros: '100000'}; grant.spec_digest = digest(spec);
  registry.entries.forEach(entry => { entry.cloud_routes = [{route_id: ROUTE, route_version: '1.0.0'}]; });
  const policy = {schema: 'awe.e1.router-cheap.host-policy/1', key_binding_id: 'synthetic_key_only', budget_group_id: 'router.cheap.shared/1', project_id: spec.project_id, mission_id: spec.mission_id, spec_digest: digest(spec), mission_grant_digest: digest(grant), catalog_digest: digest(catalog), allowed_route_ids: [ROUTE], issued_at: NOW, expires_at: LATER, total_cap_micros: '100000', per_attempt_cap_micros: '10000', max_attempts: 2, hard_cap: {kind: 'OFFLINE_TEST_DOUBLE', evidence_digest: HASH, observed_at: NOW, expires_at: LATER, cap_micros: '100000'}, catalog};
  const calls = [], wires = [], bounds = []; let now = NOW;
  const accounting = Object.fromEntries(['reserve', 'markSending', 'settle', 'unknown', 'failBeforeSend'].map(method => [method, async request => {
    calls.push({method, request});
    if (method === 'reserve') onReserve?.({policy, registry, setNow: value => { now = value; }});
    if (method === 'markSending') onSending?.({policy, registry, setNow: value => { now = value; }});
    if (overrides[method]) return overrides[method](request);
    return {status: {reserve: 'RESERVED', markSending: 'SENDING', settle: 'CONFIRMED', unknown: 'UNKNOWN', failBeforeSend: 'FAILED'}[method]};
  }]));
  const options = {accounting, registry, catalog, policy, clock: () => now, ...(timeoutMs ? {timeoutMs} : {})};
  const testBinding = {label: 'OFFLINE_TEST_DOUBLE', transport: async request => { wires.push(request); return transport ? transport(request) : jsonResponse(answer); }, inputTokenBound: async request => { bounds.push(request); return inputTokenBound ? inputTokenBound(request) : Buffer.byteLength(JSON.stringify(request.body)) <= request.max_input_tokens; }};
  const broker = createOfflineCloudModelBrokerForTests(options, testBinding);
  const request = {scope: {mission_id: spec.mission_id, task_id: 'head_control', logical_request_id: suffix + '_logical', attempt_id: suffix + '_attempt', worker_id: 'e1_worker', fence: 1}, spec, grant, capability_id: 'e1.code.review', input: {instruction: 'Review synthetic numerical-sort code.'}, data_label: 'SYNTHETIC', route_id: ROUTE, max_input_tokens: 4096, max_output_tokens: 16};
  return {broker, request, options, testBinding, calls, wires, bounds, policy, registry, catalog, spec, grant};
}
