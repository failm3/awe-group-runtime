import test from 'node:test';
import assert from 'node:assert/strict';
import {quoteCost, money} from '../../awe/budget/money.mjs';
import {RouteBroker} from '../../awe/providers/route-broker.mjs';
import {providerEvidence} from '../../awe/providers/catalog.mjs';
import {world, request, approve, route, price, success, notSent, shape, assertCaps} from './fixtures.mjs';

for (const provider of ['router.cheap', 'OpenRouter', 'Requesty', 'direct']) test('R01 opaque mocked ' + provider, async () => {
  const w = world({routes: [route('r1', provider, provider === 'direct' ? {role: 'DIRECT', seller: 'synthetic-upstream'} : {})]});
  const r = request(), a = approve(w, r); const result = await w.broker.execute(r, a.approval.id);
  assert.equal(result.status, 'SUCCEEDED'); assert.equal(result.costMicros, '8');
  assert.equal(result.physicalDecision, 'DENY'); assertCaps(w);
});
test('R02 submitted C unknowns are preserved', () => {
  assert.equal(providerEvidence['router.cheap'].tariff, 'UNKNOWN');
  assert.equal(providerEvidence.Requesty.fees, 'MARKUP_VS_TOPUP_UNRESOLVED');
  assert.equal(providerEvidence.OpenRouter.eligibility, 'UNKNOWN');
});
test('R03 arbitrary/real transport and retry owner rejected', () => {
  const w = world();
  assert.throws(() => new RouteBroker({ledger: w.ledger, routes: [route()], adapters: {r1: {invoke: () => { throw Error('NEVER'); }}}}), /MOCK_ADAPTER_REQUIRED/);
  assert.throws(() => new RouteBroker({ledger: w.ledger, routes: [route('r1', 'router.cheap', {physicalDecision: 'ALLOW'})], adapters: w.adapters}), /PHYSICAL_ADAPTER_FORBIDDEN/);
  assert.throws(() => new RouteBroker({ledger: w.ledger, routes: w.routes, adapters: w.adapters, retry: {owner: 'SDK'}}), /RETRY_OWNER_CONFLICT/);
  assert.equal(w.broker.physicalDispatch().decision, 'DENY');
});
const constraints = [
  ['eligibility UNKNOWN', {eligibility: 'UNKNOWN'}, 'ELIGIBILITY_UNKNOWN_OR_DENIED'],
  ['upstream eligibility DENIED', {upstreamEligibility: 'DENIED'}, 'ELIGIBILITY_UNKNOWN_OR_DENIED'],
  ['region', {region: 'other'}, 'REGION_CONSTRAINT'],
  ['upstream region', {upstreamRegion: 'other'}, 'REGION_CONSTRAINT'],
  ['privacy', {privacy: 'UNKNOWN'}, 'PRIVACY_UNKNOWN'],
  ['upstream privacy', {upstreamPrivacy: 'UNKNOWN'}, 'PRIVACY_UNKNOWN'],
  ['model alias substitution', {modelId: 'synthetic-latest'}, 'MODEL_PIN_MISMATCH'],
  ['seller identity', {upstreamSeller: null}, 'SELLER_IDENTITY_UNKNOWN'],
  ['context UNKNOWN', {capabilities: {...route().capabilities, contextTokens: null}}, 'INVALID_INTEGER'],
  ['context too small', {capabilities: {...route().capabilities, contextTokens: 14}}, 'CONTEXT_OR_OUTPUT_LIMIT'],
  ['output too large', {capabilities: {...route().capabilities, outputTokens: 4}}, 'CONTEXT_OR_OUTPUT_LIMIT'],
  ['protocol', {capabilities: {...route().capabilities, protocol: 'CHAT_COMPATIBILITY_ASSUMED'}}, 'PROTOCOL_OR_USAGE_UNSUPPORTED'],
  ['usage UNKNOWN', {capabilities: {...route().capabilities, usage: 'UNKNOWN'}}, 'PROTOCOL_OR_USAGE_UNSUPPORTED'],
  ['SDK retry', {retries: {...route().retries, sdk: 1}}, 'NESTED_RETRY_RISK'],
  ['gateway retry', {retries: {...route().retries, gateway: 1}}, 'NESTED_RETRY_RISK'],
  ['seller retry UNKNOWN', {retries: {...route().retries, seller: null}}, 'NESTED_RETRY_RISK'],
  ['tariff UNKNOWN', {price: price({status: 'UNKNOWN'})}, 'COST_UNKNOWN'],
  ['fees UNKNOWN', {price: price({fees: {status: 'UNKNOWN'}})}, 'FEES_UNKNOWN'],
  ['FX UNKNOWN', {price: price({fx: {status: 'UNKNOWN'}})}, 'FX_UNKNOWN'],
  ['stale quote', {price: price({validUntil: 999})}, 'QUOTE_STALE'],
  ['stale FX', {price: price({fx: {...price().fx, validUntil: 999}})}, 'FX_STALE'],
  ['cache rate UNKNOWN', {price: price({rates: {...price().rates, cacheRead: null}})}, 'COST_UNKNOWN']
];
for (const [name, patch, code] of constraints) test('R04 constraint ' + name, () => {
  const w = world({routes: [route('r1', 'router.cheap', patch)]});
  const result = w.broker.prepare(request()); assert.equal(result.decision, 'DENY'); assert.equal(result.code, code);
  assert.equal(w.controls.r1.calls().length, 0); assertCaps(w);
});
for (const feature of ['tools', 'stream', 'json']) test('R05 explicit ' + feature + ' capability', () => {
  const w = world({routes: [route('r1', 'router.cheap', {capabilities: {...route().capabilities, [feature]: false}})]});
  const r = request();
  r.features[feature] = true;
  if (feature === 'json') { r.jsonSchema = shape; r.jsonExample = {answer: 'fixture'}; }
  assert.equal(w.broker.prepare(r).code, 'CAPABILITY_UNKNOWN_OR_UNSUPPORTED');
});
test('R06 integer fees, disjoint buckets and FX round upward', () => {
  const p = price({fees: {status: 'SYNTHETIC_PINNED', bps: '500', fixedMicros: '2'},
    fx: {...price().fx, numerator: '3', denominator: '2'}});
  assert.equal(quoteCost(p, {uncachedInput: 3, cacheRead: 2, cacheWrite: 1, output: 4, toolCalls: 1}, 1000), '30');
  for (const v of [0, 0.1, '-1', '01', '1e4', 'UNKNOWN', null]) assert.throws(() => money(v), /INVALID_MONEY/);
});
test('R07 bounded UNKNOWN requires separate explicit approval and retains liability', async () => {
  const w = world({routes: [route('r1', 'router.cheap', {price: price({status: 'UNKNOWN'})})]});
  const r = request('one', {unknownCostBoundMicros: '50'}), a = approve(w, r);
  assert.equal(a.prepared.totalBoundMicros, '100'); assert(a.prepared.unknownCost);
  assert.equal((await w.broker.execute(r, a.approval.id)).code, 'UNKNOWN_COST_APPROVAL_REQUIRED');
  assert.equal(w.controls.r1.calls().length, 0); assert.equal(w.ledger.inspect().approvals[a.approval.id].uses, 0);
  const b = approve(w, r, {id: 'bounded-approval', allowUnknownCost: true});
  assert.equal((await w.broker.execute(r, b.approval.id)).status, 'OUTCOME_UNKNOWN');
  assert.equal(w.ledger.inspect().totals.global.uncertainMicros, '100');
  assert.equal(w.ledger.inspect().totals.global.spentMicros, '0'); assertCaps(w);
});
test('R08 bounded money cannot override UNKNOWN eligibility/context or hidden retries', () => {
  for (const patch of [{eligibility: 'UNKNOWN'}, {capabilities: {...route().capabilities, contextTokens: null}}, {retries: {...route().retries, seller: null}}]) {
    const w = world({routes: [route('r1', 'router.cheap', {...patch, price: price({status: 'UNKNOWN'})})]});
    assert.equal(w.broker.prepare(request('one', {unknownCostBoundMicros: '100'})).decision, 'DENY');
  }
});
test('R09 transient proven NOT_SENT uses approved reserve route after bounded backoff', async () => {
  const w = world({routes: [route(), route('r2', 'OpenRouter')], scripts: [[notSent()], [success()]]});
  const r = request('one', {allowedRoutes: ['r1', 'r2']}), a = approve(w, r);
  const first = await w.broker.execute(r, a.approval.id); assert.equal(first.status, 'RETRYABLE');
  assert.equal((await w.broker.execute(r, a.approval.id)).code, 'BACKOFF_PENDING');
  w.ledger.advanceClock(first.retryAt);
  const second = await w.broker.execute(r, a.approval.id); assert.equal(second.status, 'SUCCEEDED'); assert.equal(second.routeId, 'r2');
  const attempts = w.ledger.operation(r.operationId).attempts;
  assert.equal(attempts.length, 2); assert.equal(new Set(attempts.map(x => x.idempotencyKey)).size, 2);
  assert(attempts.every(x => x.logicalRequestId === r.logicalRequestId && x.correlationId === r.correlationId));
  assert.equal(w.ledger.inspect().totals.global.spentMicros, '8'); assertCaps(w);
});
for (const error of ['AUTH_ERROR', 'REGION_ERROR', 'INVALID_REQUEST', 'CONTEXT_ERROR']) test('R10 no failover on ' + error, async () => {
  const w = world({routes: [route(), route('r2', 'Requesty')], scripts: [[notSent(error)], [success()]]});
  const r = request('one', {allowedRoutes: ['r1', 'r2']}), a = approve(w, r);
  assert.equal((await w.broker.execute(r, a.approval.id)).status, 'FAILED');
  assert.equal(w.controls.r2.calls().length, 0); assert.equal(w.ledger.inspect().totals.global.exposureMicros, '0');
});
test('R11 expensive fallback is fully reserved before first invocation', async () => {
  const costly = price({rates: {...price().rates, output: '20000000'}});
  const w = world({cap: '100', routes: [route(), route('r2', 'direct', {price: costly})]});
  const r = request('one', {allowedRoutes: ['r1', 'r2']}), a = approve(w, r);
  assert.equal(a.prepared.totalBoundMicros, '220'); assert.equal((await w.broker.execute(r, a.approval.id)).code, 'CAP_EXCEEDED');
  assert.equal(w.controls.r1.calls().length, 0);
});
test('R12 ineligible fallback is visibly excluded, never invoked', async () => {
  const w = world({routes: [route(), route('r2', 'OpenRouter', {privacy: 'UNKNOWN'})], scripts: [[notSent(), success()], [success()]]});
  const r = request('one', {allowedRoutes: ['r1', 'r2']}), a = approve(w, r);
  assert.deepEqual(a.prepared.plan.rejected, [{routeId: 'r2', code: 'PRIVACY_UNKNOWN'}]);
  const first = await w.broker.execute(r, a.approval.id); w.ledger.advanceClock(first.retryAt);
  assert.equal((await w.broker.execute(r, a.approval.id)).status, 'SUCCEEDED'); assert.equal(w.controls.r2.calls().length, 0);
});
test('R13 BYOK gateway and upstream seller remain separate cost identities', () => {
  const w = world({routes: [route('r1', 'OpenRouter', {role: 'BYOK_GATEWAY', seller: 'synthetic-direct-provider', upstreamSeller: 'synthetic-direct-provider', gateway: 'synthetic-OpenRouter'})]});
  const prepared = w.broker.prepare(request()); assert.equal(prepared.plan.routes[0].gateway, 'synthetic-OpenRouter');
  assert.equal(prepared.plan.routes[0].seller, 'synthetic-direct-provider');
});
test('R14 direct/upstream quotes cannot be transplanted to reseller or BYOK legs', () => {
  const directQuote = route('r2', 'direct', {role: 'DIRECT'}).price;
  const w = world({routes: [route('r1', 'router.cheap', {price: directQuote})]});
  assert.equal(w.broker.prepare(request()).code, 'QUOTE_ROUTE_BINDING');
});
test('R15 FX pair and long-context price tier must match exact request', () => {
  const w = world({routes: [route('r1', 'router.cheap', {price: price({fx: {...price().fx, fromCurrency: 'EUR'}})})]});
  assert.equal(w.broker.prepare(request()).code, 'FX_PAIR_MISMATCH');
  const p = route().price; p.binding.contextTokens = 14;
  assert.equal(world({routes: [route('r1', 'router.cheap', {price: p})]}).broker.prepare(request()).code, 'QUOTE_CONTEXT_TIER');
});
test('R16 requested UNKNOWN privacy/region labels cannot authorize fallback', () => {
  for (const field of ['region', 'upstreamRegion', 'privacy', 'upstreamPrivacy']) {
    const w = world({routes: [route('r1', 'router.cheap', {[field]: 'UNKNOWN'})]});
    const r = request('one', {allowedRegions: ['fixture-eu', 'UNKNOWN'], allowedPrivacy: ['SYNTHETIC_NO_RETENTION', 'UNKNOWN']});
    assert.equal(w.broker.prepare(r).decision, 'DENY');
  }
});
test('R17 missing FX/quote validity is UNKNOWN, never an unbounded valid quote', () => {
  for (const patch of [{validUntil: null}, {fx: {...price().fx, validUntil: null}}])
    assert.equal(world({routes: [route('r1', 'router.cheap', {price: price(patch)})]}).broker.prepare(request()).code, 'INVALID_INTEGER');
});
