import assert from 'node:assert/strict';
import {MemoryLedger, intentKey} from '../../awe/budget/memory-ledger.mjs';
import {RouteBroker} from '../../awe/providers/route-broker.mjs';
import {createMockAdapter} from '../../awe/providers/mock-adapter.mjs';

export const shape = {required: ['answer'], properties: {answer: 'string'}, additionalProperties: false};
export const success = (patch = {}) => ({status: 'OK', complete: true,
  usage: {uncachedInput: 4, cacheRead: 0, cacheWrite: 0, output: 2, toolCalls: 0},
  output: {text: 'synthetic answer', tools: []}, ...patch});
export const notSent = (status = 'TRANSIENT_NOT_SENT') => ({status, accepted: false, billable: false, emittedBytes: 0});
export function price(patch = {}) {
  return {status: 'SYNTHETIC_QUOTED', currency: 'USD', budgetCurrency: 'RUB', validFrom: 0, validUntil: 8000,
    rates: {uncachedInput: '1000000', cacheRead: '100000', cacheWrite: '2000000', output: '2000000'},
    toolCallMicros: '3', fees: {status: 'SYNTHETIC_PINNED', bps: '0', fixedMicros: '0'},
    fx: {status: 'SYNTHETIC_PINNED', fromCurrency: 'USD', toCurrency: 'RUB', numerator: '1', denominator: '1', validFrom: 0, validUntil: 8000}, ...patch};
}
export function route(id = 'r1', provider = 'router.cheap', patch = {}) {
  const result = {id, provider, mode: 'MOCK_ONLY', physicalDecision: 'DENY', role: provider === 'direct' ? 'DIRECT' : 'SELLER', seller: 'synthetic-' + provider,
    upstreamSeller: provider === 'direct' ? 'synthetic-direct' : 'synthetic-inference-seller', gateway: null, accountId: id === 'r1' ? 'acct1' : 'acct2',
    eligibility: 'SYNTHETIC_ELIGIBLE', upstreamEligibility: 'SYNTHETIC_ELIGIBLE', region: 'fixture-eu', upstreamRegion: 'fixture-eu',
    regionStatus: 'SYNTHETIC_VERIFIED', upstreamRegionStatus: 'SYNTHETIC_VERIFIED', privacyStatus: 'SYNTHETIC_VERIFIED', upstreamPrivacyStatus: 'SYNTHETIC_VERIFIED',
    privacy: 'SYNTHETIC_NO_RETENTION', upstreamPrivacy: 'SYNTHETIC_NO_RETENTION',
    alias: 'synthetic-stable', modelId: 'synthetic-pinned-v1',
    capabilities: {protocol: 'SYNTHETIC_RESPONSES_V1', contextTokens: 1000, outputTokens: 100, tools: true, stream: true, json: true, usage: true, idempotency: true},
    retries: {owner: 'RouteBroker', sdk: 0, gateway: 0, seller: 0}, price: price(), ...patch};
  if (result.role === 'DIRECT' && patch.upstreamSeller === undefined) result.upstreamSeller = result.seller;
  result.price = {...result.price, binding: result.price.binding ?? {provider, accountId: result.accountId, modelId: result.modelId,
    protocol: result.capabilities.protocol, seller: result.seller, upstreamSeller: result.upstreamSeller,
    gateway: result.gateway, role: result.role, contextTokens: 1000, outputTokens: 100}};
  return result;
}
export function request(suffix = 'one', patch = {}) {
  return {scopeId: 'scope', projectId: 'project', taskId: 'task', effectSlot: 'slot-' + suffix,
    operationId: 'op-' + suffix, logicalRequestId: 'logical-' + suffix, correlationId: 'corr-' + suffix,
    kind: 'MAIN', authority: {policyVersion: 'synthetic-v1', epoch: 1}, deadline: 7000, maxAttempts: 2,
    alias: 'synthetic-stable', modelPins: {r1: 'synthetic-pinned-v1', r2: 'synthetic-pinned-v1'},
    allowedRoutes: ['r1'], allowedRegions: ['fixture-eu'], allowedPrivacy: ['SYNTHETIC_NO_RETENTION'],
    protocol: 'SYNTHETIC_RESPONSES_V1', bounds: {uncachedInput: 10, cacheRead: 0, cacheWrite: 0, output: 5, toolCalls: 0},
    features: {tools: false, stream: false, json: false}, toolSchemas: {}, jsonSchema: null, jsonExample: null,
    sdkRetries: 0, runtimeRetries: 0, unknownCostBoundMicros: null, payload: {prompt: 'synthetic fixture'}, ...patch};
}
export function world({routes = [route()], scripts = [[success()]], deferred = false, cap = '10000',
  budgetPatches = {}, slots = ['one', 'two', ...Array.from({length: 32}, (_, i) => String(i))], scopes = null, retry} = {}) {
  const kinds = {global: 'GLOBAL', project: 'PROJECT', parent: 'PARENT', task: 'TASK', day: 'DAY', month: 'MONTH', agent: 'AGENT', model: 'MODEL', account1: 'ACCOUNT', account2: 'ACCOUNT'};
  const budgets = Object.entries(kinds).map(([id, kind]) => ({id, kind, currency: 'RUB', capMicros: cap,
    balanceMicros: cap, committedMicros: '0', attemptLimit: 100, ...budgetPatches[id]}));
  const baseScope = {id: 'scope', projectId: 'project', taskId: 'task', originId: 'origin-workflow', effectSlots: slots.map(s => 'slot-' + s),
    budgetIds: Object.keys(kinds).filter(k => !k.startsWith('account')), accountBudgets: {acct1: 'account1', acct2: 'account2'}, maxAttempts: 2, validUntil: 9000};
  const ledger = new MemoryLedger({budgets, scopes: scopes ?? [baseScope], now: 1000});
  const adapters = {}, controls = {};
  routes.forEach((r, i) => { const mock = createMockAdapter({provider: r.provider, script: scripts[i] ?? [success()], deferred}); adapters[r.id] = mock.adapter; controls[r.id] = mock.control; });
  const broker = new RouteBroker({ledger, routes, adapters, ...(retry ? {retry} : {})});
  return {ledger, broker, controls, routes, adapters, baseScope};
}
export function approve(w, r = request(), patch = {}) {
  const prepared = w.broker.prepare(r);
  assert.equal(prepared.decision, 'ALLOW_SIMULATION_ONLY', JSON.stringify(prepared));
  const approval = {id: 'approval-' + r.operationId, operationId: r.operationId, logicalRequestId: r.logicalRequestId,
    correlationId: r.correlationId, scopeId: r.scopeId, effectSlot: r.effectSlot, planHash: prepared.planHash,
    authority: r.authority, maxMicros: prepared.totalBoundMicros, maxAttempts: r.maxAttempts, expiresAt: 7000,
    allowUnknownCost: false, ...patch};
  w.ledger.approve(approval); return {approval, prepared};
}
export function assertCaps(w) {
  for (const [id, t] of Object.entries(w.ledger.inspect().totals)) {
    assert(BigInt(t.exposureMicros) <= BigInt(t.capMicros), id);
    assert.equal(BigInt(t.spentMicros) + BigInt(t.reservedMicros) + BigInt(t.uncertainMicros), BigInt(t.exposureMicros));
    assert(t.attempts + t.reservedAttempts <= w.ledger.inspect().budgets[id].attemptLimit);
  }
}
export function readback(w, operationId = 'op-one', cost = '8') {
  const op = w.ledger.operation(operationId);
  return {kind: 'INDEPENDENT_SYNTHETIC_READBACK', operationId, planHash: op.planHash, intentKey: intentKey(op.scopeId, op.plan.request.effectSlot),
    authority: w.ledger.authority(), attempts: op.attempts.filter(a => a.status === 'IN_FLIGHT')
      .map(a => ({attemptId: a.id, costMicros: cost, providerRequestId: 'synthetic-readback-' + a.id}))};
}
