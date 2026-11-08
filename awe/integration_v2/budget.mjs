import {digest, need, copy} from './ports.mjs';

// D05 reservations are construction tickets, NOT money or attempts. D06 is the sole monetary/attempt writer.
// One host instance/root; a new instance is never a recovery authority.
export function createBudgetBridge({ledger, broker, rootId, scopeId, readContext, readOwner, requestTemplate, maxBuilds = 8}) {
  const tickets = new Map(), proposals = new WeakMap();
  let active = null, builds = 0, stopped = false, operationId = null;
  const terminal = new Set(['SUCCEEDED','FAILED','CANCELLED','RECONCILED']);
  const gate = () => {
    const s = ledger.inspect();
    const origin = ledger.scope(scopeId).originId;
    return stopped || s.recoveryRequired || s.quarantinedOrigins[origin] ? 'STOPPED' : operationId ? 'EXECUTING' : 'OPEN';
  };
  function ticket(ref) {
    const t = tickets.get(ref); need(t && ref === active && !stopped, 'RESERVATION_INVALID'); return t;
  }
  const contextOpen = () => gate() === 'OPEN' || (gate() === 'EXECUTING' && ['RETRYABLE','SUCCEEDED'].includes(ledger.operation(operationId)?.status));
  const contextLedger = Object.freeze({
    reserve(input) {
      const s = readContext();
      if (gate() !== 'OPEN' || ++builds > maxBuilds) return {decision: 'DENY', code: 'RETRY_EXHAUSTED'};
      need(input.root_budget_id === rootId && input.project_id === s.project_id && input.task_id === s.task_id
        && input.now < input.deadline && input.deadline === s.deadline && Number.isSafeInteger(input.units) && input.units > 0, 'BUDGET_EXHAUSTED');
      const ref = digest({format: 'INT02_NON_MONETARY_BUILD_TICKET', rootId, serial: builds, input});
      tickets.set(ref, {rootId, input: copy(input), binding: null}); active = ref;
      return {decision: 'RESERVED', ref};
    },
    check(root, ref) { return root === rootId && ref === active && tickets.has(ref) && contextOpen() ? 'RESERVED' : 'DENY'; },
    ready(root) { return root === rootId && contextOpen() ? 'OPEN' : 'STOPPED'; },
    repair() { return {decision: 'DENY', code: 'RETRY_EXHAUSTED'}; },
    consumeRetry() { return 'DENY'; },
    stop() { stopped = true; }
  });
  function prepare(record, binding) {
    need(gate() === 'OPEN', 'ROOT_STOPPED');
    const t = ticket(record.manifest.reservation_ref), s = readContext();
    need(record.decision === 'READY_OFFLINE' && record.physical_decision === 'DENY'
      && digest(record.payload) === record.manifest.payload_hash && record.request_hash === record.manifest.payload_hash
      && digest(binding.profile) === record.manifest.profile_hash, 'CONTEXT_BINDING');
    need(t.input.project_id === s.project_id && t.input.task_id === s.task_id && t.input.root_budget_id === rootId, 'SCOPE_MISMATCH');
    // The protocol translation is explicit and reviewed in a host-only full-profile + route fingerprint.
    need(binding.context_protocol === 'awe-synthetic-chat-v1' && binding.broker_protocol === 'SYNTHETIC_RESPONSES_V1'
      && binding.profile_hash === record.manifest.profile_hash && binding.route_fingerprint === digest(binding.route)
      && binding.profile.model_revision === binding.route.modelId && binding.profile.provider === binding.route.provider
      && binding.profile.region === binding.route.region && binding.route.capabilities.contextTokens >= binding.profile.caps.window
      && binding.route.capabilities.outputTokens >= binding.profile.caps.output && binding.route.capabilities.tools === binding.profile.tools,
      'MODEL_BINDING');
    const template = copy(requestTemplate), r = copy(record), bounds = {
      uncachedInput: r.manifest.counted.upper_bound, cacheRead: 0, cacheWrite: 0,
      output: r.manifest.budget.generation_reserve, toolCalls: template.bounds.toolCalls
    };
    const request = {...template, scopeId, projectId: s.project_id, taskId: s.task_id, bounds,
      payload: {format: 'INT02_D05_TO_D06_V1', context_ref: r.ref, profile_hash: r.manifest.profile_hash,
        payload_hash: r.request_hash, context: r.payload}, protocol: binding.broker_protocol,
      modelPins: {[binding.route.id]: binding.route.modelId}, allowedRoutes: [binding.route.id],
      allowedRegions: [binding.route.region], authority: ledger.authority()};
    const prepared = broker.prepare(request);
    need(prepared.decision === 'ALLOW_SIMULATION_ONLY' && !prepared.unknownCost
      && prepared.plan.routes.length === 1 && digest(binding.route) === digest((({boundMicros,costMode,unknownReason,validUntil,...route})=>route)(prepared.plan.routes[0])),
      prepared.code ?? 'MODEL_BINDING');
    const handle = Object.freeze({});
    const data = {request, prepared, ref: r.manifest.reservation_ref, context_ref: r.ref, consumed: false, approved: false};
    proposals.set(handle, data); t.binding = r.request_hash;
    return {handle, plan_hash: prepared.planHash, bound_micros: prepared.totalBoundMicros, currency: 'RUB', physical_decision: 'DENY'};
  }
  function approve(owner, handle) {
    need(readOwner(owner) === true, 'OWNER_REQUIRED');
    const p = proposals.get(handle); need(p && !p.consumed && !p.approved && p.ref === active && gate() === 'OPEN', 'PROPOSAL_INVALID');
    const r = p.request;
    ledger.approve({id: 'apr_' + r.operationId, operationId: r.operationId, logicalRequestId: r.logicalRequestId,
      correlationId: r.correlationId, scopeId, effectSlot: r.effectSlot, planHash: p.prepared.planHash,
      authority: r.authority, maxMicros: p.prepared.totalBoundMicros, maxAttempts: r.maxAttempts,
      expiresAt: r.deadline, allowUnknownCost: false}); p.approved = true;
  }
  async function execute(handle, finalBarrier) {
    const p = proposals.get(handle);
    need(p && p.approved && !p.consumed && p.ref === active && gate() === 'OPEN', 'PROPOSAL_INVALID');
    need(finalBarrier() === true, 'FINAL_BARRIER_DENIED'); // synchronous trusted host, no physical dispatcher
    p.consumed = true; operationId = p.request.operationId;
    const result = await broker.execute(p.request, 'apr_' + operationId);
    if (result.status !== 'SUCCEEDED' && result.status !== 'RETRYABLE') stopped = true;
    return copy(result);
  }
  async function retry(handle, finalBarrier) {
    const p = proposals.get(handle), op = operationId && ledger.operation(operationId);
    need(!stopped && p?.consumed && p.request.operationId === operationId && op?.status === 'RETRYABLE', 'RETRY_OWNER_REQUIRED');
    need(finalBarrier() === true, 'FINAL_BARRIER_DENIED');
    const result = await broker.execute(p.request, 'apr_' + operationId);
    if (!['SUCCEEDED','RETRYABLE','DENY'].includes(result.status)) stopped = true;
    return copy(result);
  }
  return Object.freeze({contextLedger, prepare, approve, execute, retry,
    cancel() { stopped = true; if (operationId) ledger.cancel(operationId); },
    stop(reason) { stopped = true; if (operationId && !terminal.has(ledger.operation(operationId)?.status)) ledger.quarantine(operationId, reason); },
    inspect: () => ({rootId, builds, active_ticket: active, operation_id: operationId, gate: gate(),
      unit_semantics: 'NON_MONETARY_CONSTRUCTION_TICKET', monetary_owner: 'D06_MemoryLedger', retry_owner: 'D06_RouteBroker'})
  });
}
