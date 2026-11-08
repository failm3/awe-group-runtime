import {canonicalize, digest} from '../../contracts/canonical.mjs';
import {money, integer, usage, quoteCost, requireThat} from '../budget/money.mjs';
import {hashPlan} from '../budget/memory-ledger.mjs';
import {mockProvider, invokeMock} from './mock-adapter.mjs';
import {validateShape, validateResponse} from './validation.mjs';

const copy = v => JSON.parse(canonicalize(v));
const eligibleError = new Set(['COST_UNKNOWN', 'FEES_UNKNOWN', 'FX_UNKNOWN']);
const codeOf = error => typeof error?.code === 'string' ? error.code : 'INVALID_INPUT_OR_RESPONSE';

// The only execution surface is an opaque local mock. Physical egress is always DENY.
export class RouteBroker {
  #ledger; #routes; #adapters; #breakers = new Map(); #retry;
  constructor({ledger, routes, adapters, retry = {owner: 'RouteBroker', baseDelay: 10, jitter: 3, breakerThreshold: 2, cooldown: 100}}) {
    this.#ledger = ledger; this.#routes = copy(routes); this.#adapters = new Map(); this.#retry = copy(retry);
    requireThat(retry.owner === 'RouteBroker', 'RETRY_OWNER_CONFLICT');
    for (const key of ['baseDelay', 'jitter', 'breakerThreshold', 'cooldown']) integer(retry[key], 1000000);
    requireThat(retry.baseDelay > 0 && retry.breakerThreshold > 0 && retry.cooldown > 0, 'RETRY_CONFIGURATION');
    requireThat(new Set(routes.map(r => r.id)).size === routes.length, 'DUPLICATE_ROUTE');
    for (const route of this.#routes) {
      const adapter = adapters[route.id];
      requireThat(mockProvider(adapter) === route.provider, 'MOCK_PROVIDER_MISMATCH');
      requireThat(route.mode === 'MOCK_ONLY' && route.physicalDecision === 'DENY', 'PHYSICAL_ADAPTER_FORBIDDEN');
      this.#adapters.set(route.id, adapter);
    }
  }
  #route(request, route) {
    const now = this.#ledger.now(), c = route.capabilities;
    requireThat(route.eligibility === 'SYNTHETIC_ELIGIBLE' && route.upstreamEligibility === 'SYNTHETIC_ELIGIBLE', 'ELIGIBILITY_UNKNOWN_OR_DENIED');
    const known = v => typeof v === 'string' && v.length > 0 && !['UNKNOWN', 'DENIED', 'NOT_RUN'].includes(v);
    requireThat(route.regionStatus === 'SYNTHETIC_VERIFIED' && route.upstreamRegionStatus === 'SYNTHETIC_VERIFIED'
      && known(route.region) && known(route.upstreamRegion), 'REGION_UNKNOWN');
    requireThat(route.privacyStatus === 'SYNTHETIC_VERIFIED' && route.upstreamPrivacyStatus === 'SYNTHETIC_VERIFIED'
      && known(route.privacy) && known(route.upstreamPrivacy), 'PRIVACY_UNKNOWN');
    requireThat(request.allowedRegions.includes(route.region) && request.allowedRegions.includes(route.upstreamRegion), 'REGION_CONSTRAINT');
    requireThat(request.allowedPrivacy.includes(route.privacy) && request.allowedPrivacy.includes(route.upstreamPrivacy), 'PRIVACY_CONSTRAINT');
    const syntheticSeller = v => typeof v === 'string' && v.startsWith('synthetic-') && v.length > 10;
    requireThat(syntheticSeller(route.seller) && syntheticSeller(route.upstreamSeller)
      && (route.gateway === null || syntheticSeller(route.gateway)) && ['SELLER', 'BYOK_GATEWAY', 'DIRECT'].includes(route.role), 'SELLER_IDENTITY_UNKNOWN');
    requireThat(route.role !== 'BYOK_GATEWAY' || route.gateway !== null, 'GATEWAY_IDENTITY_UNKNOWN');
    requireThat(route.role !== 'DIRECT' || route.gateway === null && route.seller === route.upstreamSeller, 'DIRECT_SELLER_MISMATCH');
    requireThat(route.alias === request.alias && route.modelId === request.modelPins[route.id], 'MODEL_PIN_MISMATCH');
    requireThat(c && c.protocol === request.protocol && c.usage === true && c.idempotency === true, 'PROTOCOL_OR_USAGE_UNSUPPORTED');
    integer(c.contextTokens); integer(c.outputTokens);
    const input = request.bounds.uncachedInput + request.bounds.cacheRead + request.bounds.cacheWrite;
    requireThat(Number.isSafeInteger(input) && input + request.bounds.output <= c.contextTokens
      && request.bounds.output <= c.outputTokens, 'CONTEXT_OR_OUTPUT_LIMIT');
    for (const feature of ['tools', 'stream', 'json']) requireThat(typeof c[feature] === 'boolean'
      && (!request.features[feature] || c[feature]), 'CAPABILITY_UNKNOWN_OR_UNSUPPORTED');
    requireThat(route.retries?.sdk === 0 && route.retries.gateway === 0 && route.retries.seller === 0
      && route.retries.owner === 'RouteBroker', 'NESTED_RETRY_RISK');
    let boundMicros, costMode = 'QUOTED', unknownReason = null, validUntil = null;
    try {
      requireThat(route.price.budgetCurrency === 'RUB', 'CURRENCY_MISMATCH');
      if (route.price.status === 'SYNTHETIC_QUOTED') {
        const binding = route.price.binding;
        requireThat(binding && binding.provider === route.provider && binding.accountId === route.accountId
          && binding.modelId === route.modelId && binding.protocol === request.protocol
          && binding.seller === route.seller && binding.upstreamSeller === route.upstreamSeller
          && binding.gateway === route.gateway && binding.role === route.role, 'QUOTE_ROUTE_BINDING');
        integer(binding.contextTokens); integer(binding.outputTokens);
        requireThat(input + request.bounds.output <= binding.contextTokens && request.bounds.output <= binding.outputTokens, 'QUOTE_CONTEXT_TIER');
      }
      boundMicros = quoteCost(route.price, request.bounds, now);
      validUntil = Math.min(route.price.validUntil, route.price.fx.validUntil);
    } catch (error) {
      if (!eligibleError.has(error.code)) throw error;
      requireThat(request.unknownCostBoundMicros !== null, error.code);
      money(request.unknownCostBoundMicros); requireThat(money(request.unknownCostBoundMicros) > 0n, 'FINITE_POSITIVE_BOUND_REQUIRED');
      boundMicros = request.unknownCostBoundMicros; costMode = 'BOUNDED_UNKNOWN'; unknownReason = error.code;
    }
    requireThat(money(boundMicros) > 0n, 'FINITE_POSITIVE_BOUND_REQUIRED');
    return {...route, boundMicros, costMode, unknownReason, validUntil};
  }
  prepare(raw) {
    try {
      const request = copy(raw); usage(request.bounds);
      requireThat(request.kind && ['MAIN', 'CHILD', 'QA', 'COMPACTION', 'FALLBACK', 'REPAIR'].includes(request.kind), 'KIND_UNKNOWN');
      requireThat(request.sdkRetries === 0 && request.runtimeRetries === 0, 'NESTED_RETRY_RISK');
      requireThat(Array.isArray(request.allowedRoutes) && request.allowedRoutes.length > 0
        && new Set(request.allowedRoutes).size === request.allowedRoutes.length, 'ROUTES_INVALID');
      requireThat(Array.isArray(request.allowedRegions) && Array.isArray(request.allowedPrivacy), 'CONSTRAINTS_REQUIRED');
      requireThat(Object.keys(request.features).sort().join() === 'json,stream,tools'
        && Object.values(request.features).every(v => typeof v === 'boolean'), 'FEATURES_INVALID');
      requireThat(request.features.tools || request.bounds.toolCalls === 0, 'TOOL_BOUND_WITHOUT_CAPABILITY');
      requireThat(request.toolSchemas && typeof request.toolSchemas === 'object' && !Array.isArray(request.toolSchemas), 'TOOL_SCHEMAS_REQUIRED');
      if (request.features.json) validateShape(request.jsonExample, request.jsonSchema);
      for (const tool of Object.values(request.toolSchemas)) validateShape(tool.example, tool.schema);
      // Pin entire payload/constraints and every approved alternative; no silent model substitution.
      const scope = this.#ledger.scope(request.scopeId);
      requireThat(request.authority && canonicalize(request.authority) === canonicalize(this.#ledger.authority()), 'POLICY_STALE');
      integer(request.maxAttempts, scope.maxAttempts); requireThat(request.maxAttempts > 0, 'ATTEMPT_LIMIT');
      const accepted = [], rejected = [];
      for (const routeId of request.allowedRoutes) {
        const route = this.#routes.find(r => r.id === routeId);
        if (!route) { rejected.push({routeId, code: 'ROUTE_UNKNOWN'}); continue; }
        try { accepted.push(this.#route(request, route)); } catch (error) { rejected.push({routeId, code: codeOf(error)}); }
      }
      requireThat(accepted.length > 0, rejected[0]?.code ?? 'NO_ELIGIBLE_ROUTE');
      // A rejected route is explicitly visible, never sent. Eligible routes retain requested priority.
      const plan = {version: 'D06_E0_LOCAL_V1', request, authority: request.authority, currency: 'RUB',
        maxAttempts: request.maxAttempts, routes: accepted, rejected, retry: this.#retry};
      const totalBoundMicros = String(accepted.reduce((n, r) => money(r.boundMicros) > n ? money(r.boundMicros) : n, 0n) * BigInt(plan.maxAttempts));
      return {decision: 'ALLOW_SIMULATION_ONLY', physicalDecision: 'DENY', plan, planHash: hashPlan(plan), totalBoundMicros,
        unknownCost: accepted.some(r => r.costMode === 'BOUNDED_UNKNOWN')};
    } catch (error) { return {decision: 'DENY', physicalDecision: 'DENY', code: codeOf(error)}; }
  }
  #select(op) {
    const routes = [...op.plan.routes], previous = op.attempts.at(-1)?.routeId;
    if (previous && routes.length > 1) routes.sort((a, b) => Number(a.id === previous) - Number(b.id === previous));
    return routes.find(route => (this.#breakers.get(route.id)?.until ?? 0) <= this.#ledger.now());
  }
  #trip(routeId) {
    const old = this.#breakers.get(routeId) ?? {failures: 0, until: 0}, failures = old.failures + 1;
    this.#breakers.set(routeId, {failures, until: failures >= this.#retry.breakerThreshold ? this.#ledger.now() + this.#retry.cooldown : 0});
  }
  #unknown(operationId, reason) {
    try { this.#ledger.quarantine(operationId, reason); } catch { /* admitted IN_FLIGHT reserve remains held if ledger unavailable */ }
    return {status: 'OUTCOME_UNKNOWN', code: reason, physicalDecision: 'DENY', retainedLiability: true, reconciliationRequired: true};
  }
  async execute(raw, approvalId) {
    const prepared = this.prepare(raw);
    if (prepared.decision === 'DENY') return {status: 'DENY', ...prepared};
    let admitted;
    try { admitted = this.#ledger.admit(prepared.plan, approvalId); }
    catch (error) {
      if (error.code === 'COMMIT_OUTCOME_UNKNOWN') return this.#unknown(raw.operationId, error.code);
      return {status: 'DENY', physicalDecision: 'DENY', code: codeOf(error)};
    }
    const op = admitted.operation;
    if (['SUCCEEDED', 'FAILED', 'CANCELLED', 'RECONCILED'].includes(op.status)) return {status: op.status, replay: true, physicalDecision: 'DENY'};
    if (op.status === 'QUARANTINED') return this.#unknown(op.id, 'SCOPE_QUARANTINED');
    if (op.status === 'IN_FLIGHT') return {status: 'IN_PROGRESS', physicalDecision: 'DENY'};
    const route = this.#select(op);
    if (!route) return {status: 'DENY', code: 'CIRCUIT_OPEN', physicalDecision: 'DENY', reservationRetained: true};
    let attempt;
    try { attempt = this.#ledger.begin(op.id, route.id); }
    catch (error) {
      if (error.code === 'COMMIT_OUTCOME_UNKNOWN') return this.#unknown(op.id, error.code);
      return {status: 'DENY', physicalDecision: 'DENY', code: codeOf(error), reservationRetained: true};
    }
    // No await or worker callback between atomic admission and invoking the sealed mock.
    const input = {attemptId: attempt.id, idempotencyKey: attempt.idempotencyKey, modelId: route.modelId,
      logicalRequestId: op.logicalRequestId, correlationId: op.correlationId, payloadHash: digest(op.plan.request.payload),
      protocol: op.plan.request.protocol, physicalDecision: 'DENY'};
    let response;
    try {
      response = await invokeMock(this.#adapters.get(route.id), input);
      canonicalize(response);
      for (const key of ['attemptId', 'idempotencyKey', 'modelId', 'logicalRequestId', 'correlationId'])
        requireThat(response[key] === input[key], 'RESPONSE_ID_OR_MODEL_MISMATCH');
      if (response.status === 'OK') {
        // Request stores tool documentation separately; pass only actual bounded schemas.
        const validatedRequest = {...op.plan.request, toolSchemas: Object.fromEntries(Object.entries(op.plan.request.toolSchemas).map(([k, v]) => [k, v.schema]))};
        const tokens = validateResponse(response, validatedRequest, route, attempt);
        if (route.costMode === 'BOUNDED_UNKNOWN') return this.#unknown(op.id, 'COST_UNKNOWN_REQUIRES_READBACK');
        // Settlement uses the admission-time quote, even after its dispatch TTL elapsed.
        const cost = quoteCost(route.price, tokens, attempt.begunAt);
        const result = this.#ledger.settle(op.id, attempt.id, cost, response.providerRequestId, tokens);
        this.#breakers.delete(route.id);
        return {...result, physicalDecision: 'DENY', costMicros: cost, routeId: route.id, modelId: route.modelId,
          attemptId: attempt.id, usage: tokens, output: response.output, simulated: true};
      }
      const provedNotSent = response.accepted === false && response.billable === false && response.emittedBytes === 0
        && !response.output && !response.stream;
      if (['TRANSIENT_NOT_SENT', 'AUTH_ERROR', 'REGION_ERROR', 'INVALID_REQUEST', 'CONTEXT_ERROR'].includes(response.status) && provedNotSent) {
        const transient = response.status === 'TRANSIENT_NOT_SENT';
        if (transient) this.#trip(route.id);
        const jitter = parseInt(digest({attempt: attempt.id}).slice(-4), 16) % (this.#retry.jitter + 1);
        const ready = this.#ledger.now() + this.#retry.baseDelay * 2 ** (attempt.number - 1) + jitter;
        const retryAt = transient && attempt.number < op.maxAttempts && ready < op.deadline ? ready : null;
        return {...this.#ledger.notSent(op.id, attempt.id, {retryAt, reason: response.status}), physicalDecision: 'DENY', routeId: route.id};
      }
      this.#trip(route.id);
      return this.#unknown(op.id, ['TIMEOUT', 'PARTIAL_STREAM', 'LOST_RESPONSE', 'SPLIT_COMMIT'].includes(response.status) ? response.status : 'UNPROVEN_FAILURE');
    } catch (error) { return this.#unknown(op.id, codeOf(error)); }
  }
  physicalDispatch() { return {decision: 'DENY', code: 'E0_PHYSICAL_EGRESS_DISABLED'}; }
}
