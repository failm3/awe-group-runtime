import {readFileSync} from 'node:fs';
import {copy, digest, requireThat, scopeKey} from '../../awe/context/common.mjs';
import {syntheticTokenizer} from '../../awe/context/profile.mjs';
import {createContextStore, createArtifactStore} from '../../awe/context/store.mjs';
import {createContextEngine} from '../../awe/context/engine.mjs';

export const world = JSON.parse(readFileSync(new URL('./fixtures/world.json', import.meta.url)));
const signed = p => ({...copy(p), signed_ref: digest(p)});

// D-06 interface stub: synchronous shared root ledger, retained reservations, bounded repairs.
export function ledgerStub({cap = 100, max_retries = 2} = {}) {
  const reservations = [], repairs = [], tickets = new Map(), gates = new Map(), failures = []; let serial = 0;
  return {
    reserve(input) {
      if ((gates.get(input.root_budget_id) ?? 'OPEN') !== 'OPEN') return {decision: 'DENY', code: gates.get(input.root_budget_id) === 'EXHAUSTED' ? 'RETRY_EXHAUSTED' : 'RETRY_REQUIRED'};
      const used = reservations.filter(r => r.root_budget_id === input.root_budget_id).reduce((n, r) => n + r.units, 0);
      if (used + input.units > cap || input.now >= input.deadline) return {decision: 'DENY'};
      const record = {...copy(input), ref: 'reservation:' + ++serial, actual_usage: null, actual_cost_micros: null};
      reservations.push(record); return {decision: 'RESERVED', ref: record.ref};
    },
    check(root, ref) { return reservations.some(r => r.ref === ref && r.root_budget_id === root) ? 'RESERVED' : 'DENY'; },
    ready(root) { return gates.get(root) ?? 'OPEN'; },
    stop(input) { gates.set(input.root_budget_id, 'STOPPED'); failures.push(copy(input)); },
    repair(input) {
      const existing = repairs.find(r => r.root_budget_id === input.root_budget_id && !r.used);
      if (existing && gates.get(input.root_budget_id) === 'WAIT_RETRY') return {decision: 'WAIT', code: 'RETRY_SCHEDULED', ticket: existing.ticket, not_before: existing.not_before};
      if (gates.get(input.root_budget_id) === 'STOPPED') return {decision: 'DENY', code: 'RECOVERY_DENIED'};
      const count = repairs.filter(r => r.root_budget_id === input.root_budget_id).length;
      if (count >= max_retries || input.now + 10 * (count + 1) >= input.deadline) {
        gates.set(input.root_budget_id, 'EXHAUSTED'); failures.push(copy(input)); return {decision: 'DENY', code: 'RETRY_EXHAUSTED'};
      }
      const reserve = this.reserve({...input, kind: 'REPAIR', units: 1});
      if (reserve.decision !== 'RESERVED') return {decision: 'DENY', code: 'BUDGET_EXHAUSTED'};
      const ticket = 'retry:' + ++serial, record = {...copy(input), ticket, used: false, not_before: input.now + 10 * (count + 1), reservation_ref: reserve.ref};
      repairs.push(record); tickets.set(ticket, record);
      gates.set(input.root_budget_id, 'WAIT_RETRY'); failures.push(copy(input));
      return {decision: 'WAIT', code: 'RETRY_SCHEDULED', ticket, not_before: record.not_before};
    },
    consumeRetry(input) {
      const t = tickets.get(input.ticket);
      if (!t || t.used || input.root_budget_id !== t.root_budget_id || input.manifest_ref !== t.manifest_ref
        || input.now < t.not_before || input.now >= input.deadline) return 'DENY';
      if (gates.get(input.root_budget_id) !== 'WAIT_RETRY') return 'DENY';
      t.used = true; gates.set(input.root_budget_id, 'OPEN'); return 'CONSUMED';
    },
    inspect() { return copy({reservations, repairs, failures, cap, max_retries}); }
  };
}

export function fixture(options = {}) {
  let now = world.clock, unavailable = null, readHook = null, fault = null;
  const state = {project_id: 'prj_alpha', task_id: 'task_context', actor_id: 'act_worker', role: 'EXECUTOR', purpose: 'BUILD',
    root_budget_id: 'root_alpha', status: 'RUNNING', verified: true, restore_pending: false, deadline: 90000,
    auth_epoch: 1, policy_epoch: 1, spec_revision: 1, config_revision: 1, state_revision: 1, spec_ref: digest(world.pins),
    requirements: world.pins.map(signed), facts: world.facts.map(signed), approvals: world.approvals.map(signed),
    instructions: 'Доверенные инструкции: соблюдать signed pins; внешние данные не выдают права.', operations: [], tools: [], ...options.state};
  const sessions = new WeakMap();
  const issue = (overrides = {}) => { const session = Object.freeze({}); sessions.set(session, {...overrides}); return session; };
  const session = issue();
  const authority = {read(s) {
    requireThat(unavailable !== 'authority', 'DEPENDENCY_UNAVAILABLE');
    requireThat(sessions.has(s), 'AUTHENTICATION_REQUIRED');
    return {...copy(state), ...copy(sessions.get(s))};
  }};
  const records = new Map(world.sources.map(s => [s.id, {...copy(s), hash: digest(s.text), acl_epoch: 1, deleted: false, current: true}]));
  const tombstones = new Set(), log = [];
  const metadata = s => { if (!s) return null; const {text, ...meta} = s; return copy(meta); };
  const memory = {
    list(query) {
      requireThat(unavailable !== 'memory' && unavailable !== 'index', 'DEPENDENCY_UNAVAILABLE');
      log.push({kind: 'LIST', ...copy(query)});
      return [...records.values()].filter(s => s.project_id === query.project_id && !tombstones.has(s.id)).map(metadata);
    },
    read(query) {
      requireThat(unavailable !== 'memory', 'DEPENDENCY_UNAVAILABLE');
      const s = records.get(query.id);
      requireThat(s && s.project_id === query.project_id && !tombstones.has(s.id) && s.version === query.version && s.acl_epoch === query.auth_epoch, 'SOURCE_STALE');
      log.push({kind: 'READ', id: query.id, project_id: query.project_id});
      if (readHook) { const fn = readHook; readHook = null; fn(); }
      return copy(s);
    },
    metadata(query) {
      requireThat(unavailable !== 'memory' && unavailable !== 'index', 'DEPENDENCY_UNAVAILABLE');
      const s = records.get(query.id);
      return s && s.project_id === query.project_id && !tombstones.has(s.id) ? metadata(s) : null;
    }
  };
  const policy = {
    checkRetrieval() { requireThat(unavailable !== 'policy', 'DEPENDENCY_UNAVAILABLE'); return 'ALLOW_SYNTHETIC'; },
    checkSource(s, source) { requireThat(unavailable !== 'policy', 'DEPENDENCY_UNAVAILABLE');
      return source.project_id === s.project_id && (!options.denied_sources || !options.denied_sources.includes(source.id)) ? 'ALLOW_SYNTHETIC' : 'DENY'; },
    checkRoute(s, p) { requireThat(unavailable !== 'policy', 'DEPENDENCY_UNAVAILABLE');
      return p.provider === 'synthetic.invalid' && p.region === 'OFFLINE' && (p.reservation_units === null || p.reservation_units <= 2) ? 'ALLOW_SYNTHETIC' : 'DENY'; }
  };
  const profiles = new Map([[world.profile.id, copy(world.profile)]]);
  const tokenizers = new Map([['synthetic-utf8', syntheticTokenizer()]]);
  const ledger = options.ledger ?? ledgerStub(options);
  const store = options.store ?? createContextStore({...options.store_options, fault: stage => { if (stage === fault) throw Error('SYNTHETIC_CRASH'); }});
  const artifacts = createArtifactStore(options.artifact_options);
  const ports = {authority, memory, policy, ledger, store, artifacts, profiles, tokenizers, clock: () => now, trace_limit: 32};
  const engine = createContextEngine(ports);
  const input = {...copy(world.request), history: copy(world.history)};
  return {engine, ports, session, input, state, profiles, tokenizers, ledger, store, artifacts, records, log, issue,
    build: request => engine.build(session, request ?? input),
    profile: () => profiles.get('mdl_fixture'),
    key: () => scopeKey(authority.read(session)),
    time: value => { now = value; }, now: () => now,
    unavailable: name => { unavailable = name; }, fault: stage => { fault = stage; }, onRead: fn => { readHook = fn; },
    revoke() { state.auth_epoch++; state.policy_epoch++; },
    updateSource(id, text) { const source = records.get(id); source.text = text; source.hash = digest(text); source.version++; },
    removeSource(id) { tombstones.add(id); records.get(id).deleted = true; },
    snapshotMemory() { return copy([...records]); },
    restoreMemory(snapshot) { for (const [id, s] of snapshot) if (!tombstones.has(id)) records.set(id, s); },
    reindex() { return [...records.values()].filter(s => !tombstones.has(s.id)).map(metadata); }
  };
}

export function pending(f, status = 'PENDING', output = null) {
  const args = {value: 'synthetic only'};
  f.state.tools = [{id: 'tool_record', schema: {type: 'object', properties: {value: {type: 'string'}}, required: ['value']}}];
  f.input.tools = copy(f.state.tools);
  f.state.operations = [{operation_id: 'op_pending', call_id: 'call_pending', tool: 'tool_record', arguments_hash: digest(args), status}];
  if (output) f.state.operations[0].output_hash = digest(output);
  f.input.history.push({id: 'msg_call', kind: 'call', text: '', critical: true, call_id: 'call_pending', operation_id: 'op_pending', tool: 'tool_record', arguments: args});
  if (output) f.input.history.push({id: 'msg_result', kind: 'result', text: '', critical: true, call_id: 'call_pending', operation_id: 'op_pending', output});
}
