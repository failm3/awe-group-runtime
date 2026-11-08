import {copy, digest, bytesHash, requireThat, integer, scopeKey, authorityHash, failure, safeFailure} from './common.mjs';
import {checkProfile, countRequest, budgetDecision} from './profile.mjs';
import {validateHistory, compactHistory} from './protocol.mjs';

const forbiddenExaminer = new Set(['LOCAL_QA', 'WORKER_CHAT', 'WORKER_CACHE', 'PRIVATE_TRACE', 'HIDDEN_TEST']);
const requestKeys = ['request_id', 'profile_id', 'route', 'history', 'source_ids', 'tools', 'attachments', 'reserves', 'planned_next_tool_turn'];

// Ports are synchronous, trusted host capabilities; no vendor client or physical executor is accepted.
export function createContextEngine({authority, memory, policy, ledger, store, artifacts, profiles, tokenizers, clock, trace_limit = 64}) {
  requireThat(integer(trace_limit) && trace_limit > 0, 'STORE_LIMIT_INVALID');
  const trace = [];
  function audit(key, kind, details) {
    trace.push({scope: key, kind, ...details, actual_usage: null, actual_cost_micros: null});
    if (trace.length > trace_limit) trace.shift();
  }
  function current(session) {
    const state = copy(authority.read(session));
    requireThat(state.status === 'RUNNING' && state.verified === true && state.restore_pending === false
      && clock() < state.deadline, 'PERMISSION_REVOKED');
    for (const k of ['project_id', 'task_id', 'actor_id', 'role', 'purpose', 'root_budget_id'])
      requireThat(typeof state[k] === 'string' && state[k].length > 0, 'AUTHORITY_INVALID');
    for (const k of ['auth_epoch', 'policy_epoch', 'spec_revision', 'config_revision', 'state_revision'])
      requireThat(integer(state[k]), 'AUTHORITY_INVALID');
    requireThat(Array.isArray(state.requirements) && state.requirements.length > 0
      && Array.isArray(state.facts) && Array.isArray(state.approvals) && Array.isArray(state.operations)
      && typeof state.instructions === 'string', 'AUTHORITY_INVALID');
    const ids = new Set();
    for (const r of [...state.requirements, ...state.facts, ...state.approvals]) {
      requireThat(typeof r.id === 'string' && !ids.has(r.id) && integer(r.version) && typeof r.text === 'string'
        && r.signed_ref === digest({id: r.id, version: r.version, text: r.text, kind: r.kind}), 'SIGNED_PIN_INVALID');
      ids.add(r.id);
    }
    return state;
  }
  function model(state, input) {
    const profile = copy(profiles.get(input.profile_id) ?? null);
    const adapter = profile ? tokenizers.get(profile.tokenizer?.id) : null;
    const hash = checkProfile(profile, input.route, adapter, clock());
    requireThat(policy.checkRoute(state, profile) === 'ALLOW_SYNTHETIC', 'ROUTE_DENIED');
    requireThat(integer(profile.reservation_units) && profile.reservation_units > 0, 'PRICE_UNKNOWN');
    return {profile, adapter, hash};
  }
  function checkSource(state, metadata) {
    requireThat(metadata && metadata.project_id === state.project_id && !metadata.deleted
      && metadata.acl_epoch === state.auth_epoch && metadata.current === true, 'SOURCE_STALE');
    requireThat(!(state.role === 'EXAMINER' && forbiddenExaminer.has(metadata.classification))
      && (state.role !== 'EXAMINER' || ['SPEC', 'ARTIFACT', 'SHARED'].includes(metadata.classification))
      && policy.checkSource(state, metadata) === 'ALLOW_SYNTHETIC', 'SOURCE_DENIED');
  }
  function retrieve(state, input) {
    requireThat(Array.isArray(input.source_ids) && input.source_ids.length <= 128
      && new Set(input.source_ids).size === input.source_ids.length, 'REQUEST_INVALID');
    // Namespace and role/purpose filtering precede ranking or body reads, including explicit IDs.
    requireThat(policy.checkRetrieval(state) === 'ALLOW_SYNTHETIC', 'SOURCE_DENIED');
    const listed = memory.list({project_id: state.project_id, role: state.role, purpose: state.purpose, auth_epoch: state.auth_epoch});
    requireThat(Array.isArray(listed), 'DEPENDENCY_UNAVAILABLE');
    const metadata = input.source_ids.map(id => {
      const m = listed.find(m => m.id === id);
      requireThat(m, 'SOURCE_UNAVAILABLE'); checkSource(state, m); return m;
    });
    const ranked = [...metadata].sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0) || a.id.localeCompare(b.id, 'en'));
    return ranked.map(meta => {
      const source = copy(memory.read({project_id: state.project_id, id: meta.id, version: meta.version, auth_epoch: state.auth_epoch}));
      requireThat(typeof source.text === 'string' && source.hash === digest(source.text)
        && source.hash === meta.hash && source.version === meta.version && source.id === meta.id, 'SOURCE_CORRUPT');
      // Recheck revocation/current version after the read as well as immediately before activation.
      checkSource(state, memory.metadata({project_id: state.project_id, id: meta.id}));
      return {id: meta.id, version: meta.version, hash: meta.hash, acl_epoch: meta.acl_epoch,
        classification: meta.classification, trust: 'UNTRUSTED_SOURCE', text: source.text};
    });
  }
  function sourceCheck(state, selected) {
    for (const source of selected) {
      const meta = memory.metadata({project_id: state.project_id, id: source.id}); checkSource(state, meta);
      requireThat(source.hash === meta.hash && source.version === meta.version, 'SOURCE_STALE');
    }
  }
  function artifactCheck(state, history) {
    for (const message of history.filter(m => m.kind === 'result' && m.output.artifact_ref)) {
      requireThat(artifacts, 'ARTIFACT_UNAVAILABLE');
      const data = artifacts.get({project_id: state.project_id, task_id: state.task_id, auth_epoch: state.auth_epoch}, message.output.artifact_ref);
      requireThat(data.length === message.output.bytes && bytesHash(data) === message.output.hash, 'ARTIFACT_UNAVAILABLE');
    }
  }
  function activeRecord(session, ref) {
    const state = current(session), key = scopeKey(state), pointer = store.current(key);
    requireThat(pointer && pointer.ref === ref, 'MANIFEST_INVALID');
    const record = pointer.value;
    requireThat(digest(record) === ref && record.manifest && record.manifest.payload_hash === digest(record.payload)
      && record.manifest.authority_hash === authorityHash(state) && record.manifest.scope_key === key
      && clock() < record.manifest.expires_at, 'PERMISSION_REVOKED');
    const destination = model(state, record.input);
    requireThat(record.manifest.profile_hash === destination.hash, 'PROFILE_UNKNOWN');
    sourceCheck(state, record.manifest.selected_sources);
    validateHistory(record.input.history, state.operations, record.input.tools); artifactCheck(state, record.input.history);
    requireThat(ledger.check(state.root_budget_id, record.manifest.reservation_ref) === 'RESERVED', 'RESERVATION_INVALID');
    return {state, key, record, ...destination};
  }
  function perform(session, rawInput, {kind = 'BUILD', previous_ref = null, omissions = [], compaction = null, derived_lineage = null, compaction_input = null} = {}) {
    let reservation_ref = null, auditKey = null;
    try {
      const state = current(session), key = scopeKey(state), stateHash = authorityHash(state), input = copy(rawInput);
      auditKey = key;
      requireThat(input && Object.keys(input).length === requestKeys.length && Object.keys(input).every(k => requestKeys.includes(k))
        && typeof input.request_id === 'string' && typeof input.planned_next_tool_turn === 'boolean', 'REQUEST_INVALID');
      // A blind run accepts signed authority and allowlisted source refs, never worker narrative/cache uploads.
      if (state.role === 'EXAMINER') requireThat(Array.isArray(input.history) && input.history.length === 0
        && Array.isArray(input.attachments) && input.attachments.length === 0, 'BLIND_INPUT_DENIED');
      const {profile, adapter, hash: profileHash} = model(state, input);
      const reservation = ledger.reserve({root_budget_id: state.root_budget_id, project_id: state.project_id,
        task_id: state.task_id, kind, units: profile.reservation_units, now: clock(), deadline: state.deadline});
      requireThat(reservation.decision === 'RESERVED', ['RETRY_REQUIRED', 'RETRY_EXHAUSTED'].includes(reservation.code) ? reservation.code : 'BUDGET_EXHAUSTED'); reservation_ref = reservation.ref;
      requireThat(Array.isArray(input.tools) && digest(input.tools) === digest(state.tools), 'TOOL_SCHEMA_UNAPPROVED');
      requireThat(profile.tools || (input.tools.length === 0 && !input.history.some(m => ['call', 'result'].includes(m.kind))), 'MODEL_SWITCH_UNSUPPORTED');
      const history = validateHistory(input.history, state.operations, input.tools); artifactCheck(state, history);
      requireThat(input.reserves && (input.planned_next_tool_turn || input.reserves.next_tool === 0), 'TOOL_RESERVE_INVALID');
      requireThat(Array.isArray(input.attachments) && input.attachments.length <= 8 && input.attachments.every(a =>
        a && a.kind === 'SYNTHETIC_INLINE' && typeof a.data_base64 === 'string'
        && Buffer.from(a.data_base64, 'base64').toString('base64') === a.data_base64
        && a.bytes === Buffer.from(a.data_base64, 'base64').length), 'ATTACHMENT_UNSUPPORTED');
      const sources = retrieve(state, input);
      const payload = {protocol: profile.protocol, model: {profile_hash: profileHash, deployment: profile.deployment, revision: profile.model_revision},
        request_id: input.request_id, instructions: {text: state.instructions, trust: 'AUTHORITY'},
        requirements: state.requirements, facts: state.facts, approvals: state.approvals,
        pending_operations: state.operations.filter(o => o.status !== 'COMPLETE'), tools: input.tools,
        history: history.map(record => ({trust: 'UNTRUSTED_HISTORY', record})), sources,
        attachments: input.attachments.map(a => ({trust: 'UNTRUSTED_USER', ...a})),
        generation: {output: input.reserves.output, reasoning: input.reserves.reasoning}};
      const counted = countRequest(payload, adapter), budget = budgetDecision(profile, counted, input.reserves, reservation_ref);
      if (budget.decision !== 'ALLOW_OFFLINE') {
        let code = budget.code;
        if (code === 'CONTEXT_TOO_LARGE') {
          const pins = {...payload, history: payload.history.filter(m => m.record.critical || ['call', 'result'].includes(m.record.kind)), sources: [], attachments: []};
          if (budgetDecision(profile, countRequest(pins, adapter), input.reserves, reservation_ref).decision !== 'ALLOW_OFFLINE') code = 'PIN_SET_TOO_LARGE';
        }
        audit(key, kind, {code, payload_hash: counted.payload_hash, reservation_ref, authority_hash: stateHash});
        return failure(code, budget.decision === 'WAIT' ? 'WAIT' : 'DENY', {budget, reservation_ref});
      }
      const currentPointer = store.current(key), expectedRef = currentPointer?.ref ?? null;
      if (previous_ref !== null) requireThat(expectedRef === previous_ref, 'CONTEXT_CONFLICT');
      sourceCheck(state, sources);
      requireThat(authorityHash(current(session)) === stateHash, 'PERMISSION_REVOKED');
      requireThat(model(state, input).hash === profileHash, 'PROFILE_UNKNOWN');
      const manifest = {schema_version: '0.1.0-d05', scope_key: key, authority_hash: stateHash,
        authority_refs: {project_id: state.project_id, task_id: state.task_id, spec_ref: state.spec_ref,
          spec_revision: state.spec_revision, state_revision: state.state_revision, config_revision: state.config_revision,
          auth_epoch: state.auth_epoch, policy_epoch: state.policy_epoch},
        profile_hash: profileHash, profile_id: profile.id, payload_hash: digest(payload),
        selected_sources: sources.map(({text, ...reference}) => reference),
        mandatory_coverage: [...state.requirements, ...state.facts, ...state.approvals].map(r => ({id: r.id, version: r.version, signed_ref: r.signed_ref})),
        pinned: ['instructions', 'requirements', 'facts', 'approvals', 'pending_operations', 'tools', 'critical_history', 'tool_pairs'],
        omitted: omissions, previous_ref, counted, budget, reservation_ref, expires_at: Math.min(profile.expires_at, state.deadline),
        operations: copy(state.operations), lineage: compaction ? {input_ref: previous_ref, input_request_hash: compaction.input_request_hash ?? null,
          method: 'EXTRACTIVE_IDENTITY_V1', source_lineage: compaction.lineage} : derived_lineage};
      let receipt = null;
      if (compaction) receipt = {schema_version: '0.1.0-d05', input_ref: previous_ref, input_payload_hash: compaction.input_payload_hash,
        input_build_request_hash: compaction.input_request_hash ?? null,
        output_payload_hash: manifest.payload_hash, lineage: compaction.lineage, preserved_mandatory_ids: manifest.mandatory_coverage,
        preserved_operations: manifest.operations, omissions, invariant_diff: [], validator: 'EXACT_RECORD_AND_SIGNED_PINS_V1',
        verdict: 'VALID', rollback_ref: previous_ref ?? compaction.input_request_hash, reservation_ref, actual_usage: null, actual_cost_micros: null};
      const value = {manifest, payload, input, compaction_receipt: receipt, compaction_input};
      const ref = store.commit(key, expectedRef, value);
      audit(key, kind, {code: 'READY_OFFLINE', manifest_ref: ref, payload_hash: manifest.payload_hash, reservation_ref, authority_hash: stateHash});
      return {decision: 'READY_OFFLINE', code: 'READY_OFFLINE', physical_decision: 'DENY', ref,
        request_hash: manifest.payload_hash, manifest: copy(manifest), payload: copy(payload), compaction_receipt: receipt,
        actual_usage: null, actual_cost_micros: null};
    } catch (error) {
      const result = {...safeFailure(error), reservation_ref};
      if (auditKey) {
        let hash = null; try { hash = authorityHash(current(session)); } catch { /* no authority means no trace disclosure */ }
        audit(auditKey, kind, {code: result.code, reservation_ref, authority_hash: hash});
      }
      return result;
    }
  }
  return Object.freeze({
    build(session, input) { return perform(session, input); },
    preflight(session, ref) {
      try {
        const {record, profile, adapter, state} = activeRecord(session, ref);
        requireThat(ledger.ready(state.root_budget_id) === 'OPEN', 'RETRY_REQUIRED');
        if (state.operations.some(o => o.status === 'OUTCOME_UNKNOWN')) return failure('OUTCOME_UNKNOWN', 'WAIT', {ref});
        const counted = countRequest(record.payload, adapter), budget = budgetDecision(profile, counted, record.input.reserves, record.manifest.reservation_ref);
        requireThat(budget.decision === 'ALLOW_OFFLINE' && digest(record.manifest.counted) === digest(counted), 'CONTEXT_TOO_LARGE');
        sourceCheck(state, record.manifest.selected_sources);
        requireThat(authorityHash(current(session)) === record.manifest.authority_hash
          && model(state, record.input).hash === record.manifest.profile_hash, 'PERMISSION_REVOKED');
        return {decision: 'READY_OFFLINE', code: 'READY_OFFLINE', ref, request_hash: counted.payload_hash, budget, physical_decision: 'DENY'};
      } catch (error) { return safeFailure(error); }
    },
    compact(session, ref, proposed = null) {
      try {
        const {record} = activeRecord(session, ref);
        const candidate = proposed === null ? record.input.history.filter(m => m.critical || ['call', 'result'].includes(m.kind)) : copy(proposed);
        const compacted = compactHistory(record.input.history, candidate);
        const priorOmissions = record.manifest.omitted;
        const omissions = [...priorOmissions, ...compacted.omissions.map(o => ({...o, recoverable_from: ref}))];
        return perform(session, {...record.input, history: compacted.history}, {kind: 'COMPACTION', previous_ref: ref, omissions,
          compaction: {input_payload_hash: record.manifest.payload_hash,
            lineage: [{ref, payload_hash: record.manifest.payload_hash}, ...(record.compaction_receipt?.lineage ?? [])].slice(0, 16)}});
      } catch (error) { return safeFailure(error); }
    },
    compactInput(session, rawInput, proposed = null) {
      try {
        const state = current(session), input = copy(rawInput);
        validateHistory(input.history, state.operations, input.tools); artifactCheck(state, input.history);
        const candidate = proposed === null ? input.history.filter(m => m.critical || ['call', 'result'].includes(m.kind)) : copy(proposed);
        const compacted = compactHistory(input.history, candidate), inputHash = digest(input);
        return perform(session, {...input, history: compacted.history}, {kind: 'COMPACTION', compaction_input: input,
          omissions: compacted.omissions.map(o => ({...o, recoverable_from: inputHash})),
          compaction: {input_payload_hash: null, input_request_hash: inputHash, lineage: [{input_request_hash: inputHash}]}});
      } catch (error) { return safeFailure(error); }
    },
    switchModel(session, ref, profile_id, route) {
      try {
        const {record} = activeRecord(session, ref);
        return perform(session, {...record.input, profile_id, route: copy(route)}, {kind: 'MODEL_SWITCH', previous_ref: ref,
          omissions: record.manifest.omitted, derived_lineage: record.manifest.lineage});
      } catch (error) { return safeFailure(error); }
    },
    recover(session, ref, {failure_code = null, retry_ticket = null} = {}) {
      try {
        const {state, key, record} = activeRecord(session, ref);
        if (state.operations.some(o => o.status === 'OUTCOME_UNKNOWN')) return failure('OUTCOME_UNKNOWN', 'WAIT', {ref});
        if (failure_code !== null) {
          if (!['429', 'PROVIDER_OVERFLOW', 'ESTIMATOR_MISS', 'MODEL_OUTAGE'].includes(failure_code)) {
            ledger.stop({root_budget_id: state.root_budget_id, failure_code, manifest_ref: ref});
            return failure(failure_code === 'OUTCOME_UNKNOWN' ? 'OUTCOME_UNKNOWN' : 'RECOVERY_DENIED', 'WAIT', {ref});
          }
          const repair = ledger.repair({root_budget_id: state.root_budget_id, manifest_ref: ref, failure_code, now: clock(), deadline: state.deadline});
          audit(key, 'REPAIR', {code: repair.code, ref, original_failure: failure_code, retry_ticket: repair.ticket ?? null, authority_hash: authorityHash(state)});
          return failure(repair.code, repair.decision, {ref, retry_ticket: repair.ticket ?? null, not_before: repair.not_before ?? null});
        }
        if (retry_ticket !== null) requireThat(ledger.consumeRetry({root_budget_id: state.root_budget_id, manifest_ref: ref,
          ticket: retry_ticket, now: clock(), deadline: state.deadline}) === 'CONSUMED', 'RETRY_NOT_READY');
        else requireThat(ledger.ready(state.root_budget_id) === 'OPEN', 'RETRY_REQUIRED');
        return perform(session, record.input, {kind: retry_ticket ? 'RETRY_BUILD' : 'RECOVERY', previous_ref: ref,
          omissions: record.manifest.omitted, derived_lineage: record.manifest.lineage});
      } catch (error) { return safeFailure(error); }
    },
    reconnect(session) {
      try {
        const state = current(session), key = scopeKey(state), pointer = store.current(key);
        const events = trace.filter(e => e.scope === key && e.authority_hash === authorityHash(state));
        let result = pointer ? this.preflight(session, pointer.ref) : failure('NO_ACTIVE_CONTEXT', 'WAIT');
        const last = events.at(-1);
        if (last && last.code !== 'READY_OFFLINE') result = failure(last.code, last.code === 'RETRY_SCHEDULED' ? 'WAIT' : 'DENY', {active_ref: pointer?.ref ?? null});
        return {...result, message_ru: result.decision === 'READY_OFFLINE' ? 'Синтетический контекст проверен; выполнение требует отдельного допуска.' : result.message_ru,
          next_action_ru: result.next_action_ru ?? 'Проверьте профиль и подключение runtime перед реальным запуском.',
          evidence: events, actual_usage: null, actual_cost_micros: null};
      } catch (error) { return safeFailure(error); }
    },
    requestPhysicalEffect() { return failure('OFFLINE_ONLY'); }
  });
}
