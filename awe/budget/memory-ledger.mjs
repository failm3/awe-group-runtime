import {digest, canonicalize} from '../../contracts/canonical.mjs';
import {money, integer, usage, BUCKETS, quoteCost, requireThat, fail} from './money.mjs';

const clone = value => structuredClone(value);
const TERMINAL = new Set(['SUCCEEDED', 'FAILED', 'CANCELLED', 'RECONCILED']);
const id = value => requireThat(typeof value === 'string' && /^[a-zA-Z0-9_.:-]{1,128}$/.test(value)
  && !['__proto__', 'constructor', 'prototype'].includes(value), 'INVALID_ID');
const same = (a, b) => canonicalize(a) === canonicalize(b);
export const intentKey = (scopeId, effectSlot) => digest({scopeId, effectSlot});
export const hashPlan = plan => digest(plan);

// TRUSTED SYNTHETIC HOST ONLY. A deterministic single-process transaction model.
// No database, file writer, D-02/D-03 writer, physical dispatch or durability claim.
export class MemoryLedger {
  #state; #fault = null; #available = true;
  constructor({budgets = [], scopes = [], authority = {policyVersion: 'synthetic-v1', epoch: 1}, now = 0, checkpoint = null} = {}) {
    integer(now); integer(authority.epoch); id(authority.policyVersion);
    if (checkpoint) {
      requireThat(checkpoint.digest === digest(checkpoint.state), 'CHECKPOINT_CHECKSUM');
      this.#state = clone(checkpoint.state);
      this.#state.recoveryRequired = true;
      this.#state.authority = clone(authority); this.#state.now = now;
      for (const approval of Object.values(this.#state.approvals)) approval.revoked = true;
      for (const op of Object.values(this.#state.operations)) if (!TERMINAL.has(op.status)) this.#uncertain(this.#state, op, 'MOCK_RESTORE');
    } else {
      this.#state = {version: 1, revision: 0, now, authority: clone(authority), recoveryRequired: false,
        budgets: {}, scopes: {}, approvals: {}, operations: {}, intents: {}, logicalIds: {}, correlations: {}, receipts: {}, quarantinedOrigins: {}, journal: []};
      for (const b of budgets) {
        id(b.id); requireThat(!Object.hasOwn(this.#state.budgets, b.id), 'DUPLICATE_BUDGET');
        money(b.capMicros); money(b.balanceMicros, {signed: true}); money(b.committedMicros ?? '0');
        integer(b.attemptLimit); requireThat(b.currency === 'RUB', 'BUDGET_CURRENCY_UNSUPPORTED');
        this.#state.budgets[b.id] = {...clone(b), committedMicros: b.committedMicros ?? '0'};
      }
      for (const scope of scopes) {
        id(scope.id); id(scope.projectId); id(scope.taskId); id(scope.originId);
        requireThat(!Object.values(this.#state.scopes).some(s => s.projectId === scope.projectId && s.taskId === scope.taskId), 'TASK_SCOPE_ALIAS_FORBIDDEN');
        requireThat(!Object.hasOwn(this.#state.scopes, scope.id) && scope.budgetIds.length > 0 && scope.effectSlots.length > 0, 'SCOPE_INVALID');
        integer(scope.validUntil); integer(scope.maxAttempts, 2); requireThat(scope.maxAttempts > 0, 'ATTEMPT_LIMIT');
        requireThat(new Set(scope.budgetIds).size === scope.budgetIds.length && new Set(scope.effectSlots).size === scope.effectSlots.length, 'SCOPE_DUPLICATES');
        for (const slot of scope.effectSlots) id(slot);
        for (const budgetId of [...scope.budgetIds, ...Object.values(scope.accountBudgets)]) requireThat(Object.hasOwn(this.#state.budgets, budgetId), 'BUDGET_UNKNOWN');
        // Host fixes origin/ancestors/day/month/agent/model subpools; worker cannot omit them.
        const kinds = scope.budgetIds.map(k => this.#state.budgets[k].kind);
        for (const kind of ['GLOBAL', 'PROJECT', 'TASK', 'DAY', 'MONTH']) requireThat(kinds.includes(kind), 'REQUIRED_BUDGET_DIMENSION');
        for (const budgetId of Object.values(scope.accountBudgets)) requireThat(this.#state.budgets[budgetId].kind === 'ACCOUNT'
          && !scope.budgetIds.includes(budgetId), 'ACCOUNT_BUDGET_INVALID');
        this.#state.scopes[scope.id] = clone(scope);
      }
    }
    this.#invariants(this.#state);
  }
  now() { return this.#state.now; }
  authority() { return clone(this.#state.authority); }
  scope(scopeId) { const s = this.#state.scopes[scopeId]; requireThat(s, 'SCOPE_UNKNOWN'); return clone(s); }
  inspect() { return {...clone(this.#state), totals: this.#totals(this.#state)}; }
  operation(operationId) { return clone(this.#state.operations[operationId] ?? null); }
  checkpoint() { const state = clone(this.#state); return {state, digest: digest(state), durability: 'MEMORY_ONLY_NOT_POWER_LOSS_SAFE'}; }
  setAvailable(value) { requireThat(typeof value === 'boolean', 'INVALID_AVAILABILITY'); this.#available = value; }
  injectFault(stage) { requireThat(['BEFORE_COMMIT', 'AFTER_COMMIT_ACK_LOST'].includes(stage), 'FAULT_UNKNOWN'); this.#fault = stage; }
  advanceClock(now) { integer(now); requireThat(now >= this.#state.now, 'CLOCK_ROLLBACK'); this.#state.now = now; }

  #totals(state) {
    const totals = {};
    for (const budget of Object.values(state.budgets)) {
      let spent = money(budget.committedMicros), reserved = 0n, uncertain = 0n, attempts = 0, reservedAttempts = 0;
      for (const op of Object.values(state.operations)) {
        if (!Object.hasOwn(op.allocations, budget.id)) continue;
        const allocation = op.allocations[budget.id];
        spent += money(allocation.spentMicros);
        if (!TERMINAL.has(op.status)) {
          const remaining = money(allocation.envelopeMicros) - money(allocation.spentMicros);
          if (op.status === 'QUARANTINED') uncertain += remaining; else reserved += remaining;
          reservedAttempts += op.maxAttempts - op.attempts.length;
        }
        attempts += op.attempts.filter(a => a.budgetIds.includes(budget.id)).length;
      }
      totals[budget.id] = {spentMicros: String(spent), reservedMicros: String(reserved), uncertainMicros: String(uncertain),
        exposureMicros: String(spent + reserved + uncertain), attempts, reservedAttempts,
        capMicros: budget.capMicros, balanceMicros: budget.balanceMicros,
        balanceAtRisk: money(budget.balanceMicros, {signed: true}) < reserved + uncertain};
    }
    return totals;
  }
  #invariants(state) {
    const totals = this.#totals(state);
    for (const total of Object.values(totals)) {
      requireThat(money(total.exposureMicros) <= money(total.capMicros), 'CAP_INVARIANT');
    }
    for (const [key, total] of Object.entries(totals)) requireThat(total.attempts + total.reservedAttempts <= state.budgets[key].attemptLimit, 'ATTEMPT_INVARIANT');
    for (const op of Object.values(state.operations)) for (const allocation of Object.values(op.allocations))
      requireThat(money(allocation.spentMicros) <= money(allocation.envelopeMicros), 'ALLOCATION_INVARIANT');
  }
  #uncertain(state, op, reason) {
    op.status = 'QUARANTINED'; op.reason = reason;
    state.quarantinedOrigins[state.scopes[op.scopeId].originId] = true;
  }
  #transaction(event, reducer) {
    requireThat(this.#available, 'LEDGER_UNAVAILABLE');
    const fault = this.#fault; this.#fault = null;
    if (fault === 'BEFORE_COMMIT') fail('COMMIT_NOT_APPLIED');
    const next = clone(this.#state);
    const result = reducer(next);
    next.revision++;
    next.journal.push({revision: next.revision, event, at: next.now});
    if (fault === 'AFTER_COMMIT_ACK_LOST') {
      for (const op of Object.values(next.operations)) if (!TERMINAL.has(op.status)
        || JSON.stringify(op) !== JSON.stringify(this.#state.operations[op.id])) this.#uncertain(next, op, 'COMMIT_ACK_LOST');
      next.recoveryRequired = true;
    }
    this.#invariants(next);
    this.#state = next; // sole linearization point; no await or callback in reducer
    if (fault === 'AFTER_COMMIT_ACK_LOST') fail('COMMIT_OUTCOME_UNKNOWN');
    return clone(result);
  }
  #current(state, op) {
    requireThat(!state.recoveryRequired, 'RECOVERY_REQUIRED');
    requireThat(!state.quarantinedOrigins[state.scopes[op.scopeId].originId], 'SCOPE_QUARANTINED');
    const scope = state.scopes[op.scopeId], approval = state.approvals[op.approvalId];
    requireThat(same(state.authority, op.authority), 'POLICY_STALE');
    requireThat(approval && !approval.revoked && state.now < approval.expiresAt, 'APPROVAL_STALE');
    requireThat(state.now < op.deadline && state.now < scope.validUntil, 'DEADLINE_EXPIRED');
    for (const [budgetId, total] of Object.entries(this.#totals(state))) if (Object.hasOwn(op.allocations, budgetId))
      requireThat(!total.balanceAtRisk, 'BALANCE_CHANGED');
  }
  approve(approval) {
    return this.#transaction('APPROVAL_REGISTERED', state => {
      id(approval.id); id(approval.operationId); id(approval.logicalRequestId); id(approval.correlationId);
      requireThat(!Object.hasOwn(state.approvals, approval.id), 'APPROVAL_IMMUTABLE');
      requireThat(same(approval.authority, state.authority), 'POLICY_STALE');
      integer(approval.expiresAt); integer(approval.maxAttempts, 2); money(approval.maxMicros);
      requireThat(approval.expiresAt > state.now && approval.maxAttempts > 0 && typeof approval.allowUnknownCost === 'boolean', 'APPROVAL_INVALID');
      const scope = state.scopes[approval.scopeId];
      requireThat(scope && scope.effectSlots.includes(approval.effectSlot), 'INTENT_NOT_REGISTERED');
      requireThat(/^sha256:[a-f0-9]{64}$/.test(approval.planHash), 'PLAN_HASH_INVALID');
      state.approvals[approval.id] = {...clone(approval), uses: 0, revoked: false};
      return {status: 'APPROVED_SYNTHETIC_ONLY'};
    });
  }
  admit(plan, approvalId) {
    return this.#transaction('ADMISSION', state => {
      const key = intentKey(plan.request.scopeId, plan.request.effectSlot);
      const existingId = state.intents[key];
      if (existingId) {
        const existing = state.operations[existingId];
        requireThat(existing.id === plan.request.operationId && existing.logicalRequestId === plan.request.logicalRequestId
          && existing.correlationId === plan.request.correlationId && existing.planHash === hashPlan(plan)
          && existing.approvalId === approvalId, 'INTENT_ID_REUSE_BLOCKED');
        return {status: 'REPLAY', operation: existing};
      }
      requireThat(!state.recoveryRequired, 'RECOVERY_REQUIRED');
      const request = plan.request, scope = state.scopes[request.scopeId];
      requireThat(scope && scope.effectSlots.includes(request.effectSlot), 'INTENT_NOT_REGISTERED');
      requireThat(!state.quarantinedOrigins[scope.originId], 'SCOPE_QUARANTINED');
      requireThat(request.projectId === scope.projectId && request.taskId === scope.taskId, 'SCOPE_MISMATCH');
      for (const value of [request.operationId, request.logicalRequestId, request.correlationId]) id(value);
      requireThat(!Object.hasOwn(state.operations, request.operationId) && !Object.hasOwn(state.logicalIds, request.logicalRequestId)
        && !Object.hasOwn(state.correlations, request.correlationId), 'ID_ALREADY_BOUND');
      requireThat(same(plan.authority, state.authority), 'POLICY_STALE');
      integer(request.deadline); requireThat(request.deadline > state.now && request.deadline <= scope.validUntil, 'DEADLINE_EXPIRED');
      integer(plan.maxAttempts, scope.maxAttempts); requireThat(plan.maxAttempts > 0, 'ATTEMPT_LIMIT');
      const approval = state.approvals[approvalId];
      requireThat(approval && !approval.revoked && approval.uses === 0 && state.now < approval.expiresAt, 'APPROVAL_STALE');
      requireThat(approval.planHash === hashPlan(plan) && approval.operationId === request.operationId
        && approval.logicalRequestId === request.logicalRequestId && approval.correlationId === request.correlationId
        && approval.scopeId === request.scopeId && approval.effectSlot === request.effectSlot
        && same(approval.authority, plan.authority), 'APPROVAL_BINDING');
      requireThat(plan.maxAttempts <= approval.maxAttempts, 'APPROVAL_ATTEMPTS');
      requireThat(plan.routes.length > 0 && new Set(plan.routes.map(r => r.id)).size === plan.routes.length, 'ROUTES_INVALID');
      let max = 0n; const accountMax = {};
      for (const route of plan.routes) {
        requireThat(Object.hasOwn(scope.accountBudgets, route.accountId), 'ACCOUNT_UNBOUND');
        const bound = money(route.boundMicros); requireThat(bound > 0n, 'FINITE_POSITIVE_BOUND_REQUIRED');
        if (route.costMode === 'BOUNDED_UNKNOWN') requireThat(approval.allowUnknownCost, 'UNKNOWN_COST_APPROVAL_REQUIRED');
        else requireThat(route.costMode === 'QUOTED', 'COST_MODE_UNKNOWN');
        max = bound > max ? bound : max;
        const budgetId = scope.accountBudgets[route.accountId];
        accountMax[budgetId] = bound > (accountMax[budgetId] ?? 0n) ? bound : accountMax[budgetId];
      }
      const total = max * BigInt(plan.maxAttempts);
      requireThat(total <= money(approval.maxMicros), 'APPROVAL_COST_BOUND');
      const allocations = {};
      for (const budgetId of scope.budgetIds) allocations[budgetId] = {envelopeMicros: String(total), spentMicros: '0'};
      for (const [budgetId, bound] of Object.entries(accountMax)) allocations[budgetId] = {envelopeMicros: String(bound * BigInt(plan.maxAttempts)), spentMicros: '0'};
      const totals = this.#totals(state);
      for (const [budgetId, allocation] of Object.entries(allocations)) {
        const b = state.budgets[budgetId], t = totals[budgetId], bound = money(allocation.envelopeMicros);
        requireThat(b.currency === plan.currency, 'CURRENCY_MISMATCH');
        requireThat(money(t.exposureMicros) + bound <= money(b.capMicros), 'CAP_EXCEEDED');
        requireThat(money(t.reservedMicros) + money(t.uncertainMicros) + bound <= money(b.balanceMicros, {signed: true}), 'INSUFFICIENT_BALANCE');
        requireThat(t.attempts + t.reservedAttempts + plan.maxAttempts <= b.attemptLimit, 'ANCESTOR_ATTEMPT_LIMIT');
      }
      const op = {id: request.operationId, scopeId: request.scopeId, intentKey: key, logicalRequestId: request.logicalRequestId,
        correlationId: request.correlationId, planHash: hashPlan(plan), plan: clone(plan), approvalId,
        authority: clone(plan.authority), deadline: request.deadline, maxAttempts: plan.maxAttempts,
        status: 'ADMITTED', attempts: [], allocations, reason: null, retryAt: null};
      state.operations[op.id] = op; state.intents[key] = op.id;
      state.logicalIds[op.logicalRequestId] = op.id; state.correlations[op.correlationId] = op.id;
      approval.uses++;
      return {status: 'ADMITTED', operation: op};
    });
  }
  begin(operationId, routeId) {
    return this.#transaction('ATTEMPT_BEGUN', state => {
      const op = state.operations[operationId]; requireThat(op, 'OPERATION_UNKNOWN'); this.#current(state, op);
      requireThat(['ADMITTED', 'RETRYABLE'].includes(op.status), 'ATTEMPT_NOT_READY');
      requireThat(op.retryAt === null || state.now >= op.retryAt, 'BACKOFF_PENDING');
      requireThat(op.attempts.length < op.maxAttempts, 'ATTEMPT_LIMIT');
      const route = op.plan.routes.find(r => r.id === routeId); requireThat(route, 'ROUTE_UNAPPROVED');
      requireThat(route.validUntil === null || state.now < route.validUntil, 'QUOTE_STALE');
      const scope = state.scopes[op.scopeId], number = op.attempts.length + 1;
      const attempt = {id: op.id + ':attempt:' + number, number, routeId, provider: route.provider, accountId: route.accountId,
        idempotencyKey: digest({intentKey: op.intentKey, number}), correlationId: op.correlationId,
        logicalRequestId: op.logicalRequestId, boundMicros: route.boundMicros,
        budgetIds: [...scope.budgetIds, scope.accountBudgets[route.accountId]], status: 'IN_FLIGHT',
        settledMicros: null, providerRequestId: null, usage: null, costSource: null,
        begunAt: state.now, quoteHash: digest(route.price), simulated: true, physicalDecision: 'DENY'};
      op.attempts.push(attempt); op.status = 'IN_FLIGHT'; return attempt;
    });
  }
  #attempt(state, operationId, attemptId) {
    const op = state.operations[operationId], attempt = op?.attempts.find(a => a.id === attemptId);
    requireThat(op && attempt, 'ATTEMPT_UNKNOWN'); return {op, attempt};
  }
  #charge(state, op, attempt, cost, providerRequestId) {
    money(cost); requireThat(money(cost) <= money(attempt.boundMicros), 'PROVIDER_BOUND_BREACH');
    id(providerRequestId);
    const receiptKey = attempt.provider + ':' + providerRequestId;
    requireThat(!Object.hasOwn(state.receipts, receiptKey) || state.receipts[receiptKey] === attempt.id, 'RECEIPT_ALREADY_BOUND');
    for (const budgetId of attempt.budgetIds) {
      const allocation = op.allocations[budgetId]; allocation.spentMicros = String(money(allocation.spentMicros) + money(cost));
      state.budgets[budgetId].balanceMicros = String(money(state.budgets[budgetId].balanceMicros, {signed: true}) - money(cost));
    }
    attempt.settledMicros = cost; attempt.providerRequestId = providerRequestId; attempt.status = 'SETTLED';
    state.receipts[receiptKey] = attempt.id;
  }
  settle(operationId, attemptId, cost, providerRequestId, tokens = null) {
    return this.#transaction('SETTLED', state => {
      const {op, attempt} = this.#attempt(state, operationId, attemptId);
      if (attempt.status === 'SETTLED') {
        requireThat(attempt.settledMicros === cost && attempt.providerRequestId === providerRequestId
          && (tokens === null || same(tokens, attempt.usage)), 'RECEIPT_CONFLICT');
        return {status: op.status, replay: true};
      }
      requireThat(op.status === 'IN_FLIGHT' && attempt.status === 'IN_FLIGHT', 'RECONCILIATION_REQUIRED');
      usage(tokens);
      for (const key of [...BUCKETS, 'toolCalls']) requireThat(tokens[key] <= op.plan.request.bounds[key], 'USAGE_EXCEEDS_BOUND');
      const route = op.plan.routes.find(r => r.id === attempt.routeId);
      requireThat(route.costMode === 'QUOTED' && cost === quoteCost(route.price, tokens, attempt.begunAt), 'COST_RECEIPT_MISMATCH');
      this.#charge(state, op, attempt, cost, providerRequestId);
      attempt.usage = clone(tokens); attempt.costSource = 'PINNED_SYNTHETIC_USAGE';
      op.status = 'SUCCEEDED'; return {status: op.status};
    });
  }
  notSent(operationId, attemptId, {retryAt = null, reason}) {
    return this.#transaction('PROVEN_NOT_SENT', state => {
      const {op, attempt} = this.#attempt(state, operationId, attemptId);
      requireThat(op.status === 'IN_FLIGHT' && attempt.status === 'IN_FLIGHT', 'RECONCILIATION_REQUIRED');
      attempt.status = 'NOT_SENT'; attempt.settledMicros = '0'; attempt.proof = 'SYNTHETIC_NO_ACCEPTANCE_NO_CHARGE_NO_OUTPUT';
      op.reason = reason;
      if (retryAt !== null && op.attempts.length < op.maxAttempts) {
        integer(retryAt); requireThat(retryAt >= state.now && retryAt < op.deadline, 'RETRY_DEADLINE');
        op.status = 'RETRYABLE'; op.retryAt = retryAt;
      } else op.status = 'FAILED';
      return {status: op.status, retryAt: op.retryAt};
    });
  }
  quarantine(operationId, reason = 'OUTCOME_UNKNOWN') {
    return this.#transaction('QUARANTINED', state => {
      const op = state.operations[operationId]; requireThat(op, 'OPERATION_UNKNOWN');
      if (!TERMINAL.has(op.status)) this.#uncertain(state, op, reason);
      return {status: op.status, retainedLiability: !TERMINAL.has(op.status)};
    });
  }
  cancel(operationId) {
    return this.#transaction('CANCELLED', state => {
      const op = state.operations[operationId]; requireThat(op, 'OPERATION_UNKNOWN');
      if (op.status === 'IN_FLIGHT' || op.status === 'QUARANTINED') this.#uncertain(state, op, 'CANCEL_AFTER_ADMISSION');
      else if (!TERMINAL.has(op.status)) op.status = 'CANCELLED';
      return {status: op.status};
    });
  }
  revoke(approvalId) {
    return this.#transaction('APPROVAL_REVOKED', state => {
      const approval = state.approvals[approvalId]; requireThat(approval, 'APPROVAL_UNKNOWN'); approval.revoked = true;
      for (const op of Object.values(state.operations)) if (op.approvalId === approvalId && !TERMINAL.has(op.status)) {
        if (op.status === 'IN_FLIGHT' || op.status === 'QUARANTINED') this.#uncertain(state, op, 'REVOKED_IN_FLIGHT');
        else op.status = 'CANCELLED';
      }
      return {status: 'REVOKED'};
    });
  }
  changeAuthority(authority) {
    return this.#transaction('AUTHORITY_CHANGED', state => {
      id(authority.policyVersion); integer(authority.epoch);
      requireThat(authority.epoch > state.authority.epoch, 'EPOCH_NOT_MONOTONIC'); state.authority = clone(authority);
      for (const op of Object.values(state.operations)) if (!TERMINAL.has(op.status)) {
        if (op.status === 'IN_FLIGHT' || op.status === 'QUARANTINED') this.#uncertain(state, op, 'AUTHORITY_CHANGED_IN_FLIGHT');
        else op.status = 'CANCELLED';
      }
      return {status: 'AUTHORITY_CHANGED'};
    });
  }
  updateBalance(budgetId, balanceMicros) {
    return this.#transaction('BALANCE_OBSERVED', state => {
      money(balanceMicros, {signed: true}); requireThat(Object.hasOwn(state.budgets, budgetId), 'BUDGET_UNKNOWN');
      state.budgets[budgetId].balanceMicros = balanceMicros; return {status: 'UPDATED'};
    });
  }
  reconcile(operationId, evidence) {
    return this.#transaction('RECONCILED', state => {
      const op = state.operations[operationId]; requireThat(op?.status === 'QUARANTINED', 'NOT_QUARANTINED');
      requireThat(evidence?.kind === 'INDEPENDENT_SYNTHETIC_READBACK' && evidence.operationId === op.id
        && evidence.planHash === op.planHash && evidence.intentKey === op.intentKey
        && same(evidence.authority, state.authority) && Array.isArray(evidence.attempts), 'RECONCILIATION_EVIDENCE');
      const unresolved = op.attempts.filter(a => a.status === 'IN_FLIGHT');
      requireThat(evidence.attempts.length === unresolved.length && new Set(evidence.attempts.map(e => e.attemptId)).size === unresolved.length, 'RECONCILIATION_INCOMPLETE');
      for (const attempt of unresolved) {
        const receipt = evidence.attempts.find(e => e.attemptId === attempt.id);
        requireThat(receipt, 'RECONCILIATION_INCOMPLETE');
        this.#charge(state, op, attempt, receipt.costMicros, receipt.providerRequestId);
        attempt.costSource = 'INDEPENDENT_SYNTHETIC_READBACK_USAGE_UNKNOWN';
      }
      op.status = 'RECONCILED'; op.reason = 'INDEPENDENT_SYNTHETIC_READBACK';
      const originId = state.scopes[op.scopeId].originId;
      if (!Object.values(state.operations).some(o => state.scopes[o.scopeId].originId === originId && o.status === 'QUARANTINED')) delete state.quarantinedOrigins[originId];
      return {status: op.status, historicalIntentStillBound: true};
    });
  }
  finishMockRecovery() {
    return this.#transaction('MOCK_RECOVERY_FINISHED', state => {
      requireThat(!Object.values(state.operations).some(o => !TERMINAL.has(o.status)), 'UNRESOLVED_OPERATIONS');
      state.recoveryRequired = false; return {status: 'MEMORY_ONLY_RECOVERED'};
    });
  }
}
