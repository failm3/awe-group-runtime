import {digest, need, copy} from './ports.mjs';

export function runtimePins(record, binding, authority) {
  need(record.decision === 'READY_OFFLINE' && record.physical_decision === 'DENY'
    && digest(record.payload) === record.request_hash && record.manifest.profile_hash === digest(binding.profile), 'CONTEXT_BINDING');
  return {config_hash: digest({format: 'INT02_CONFIG_V1', config_revision: authority.config_revision,
    profile: binding.profile, route: binding.route, profile_hash: record.manifest.profile_hash,
    capability_revision: binding.capability_revision, protocol_translation: [binding.context_protocol,binding.broker_protocol]}),
    manifest_hash: digest({format: 'INT02_CONTEXT_MANIFEST_V1', ref: record.ref, manifest: record.manifest,
      payload_hash: record.request_hash, epochs: {auth: authority.auth_epoch, policy: authority.policy_epoch,
        owner: authority.owner_epoch, stop: authority.stop_epoch}})};
}
// Host-created closure: workers receive only run/cancel and cannot substitute identity, context, pins or approval handles.
export function createBoundExecution({engine, session, record, binding, readContext, budget, proposal, pins, validateInputs}) {
  const frozen = copy(record), reviewedBinding = copy(binding), reviewedPins = copy(pins);
  let started = false;
  function barrier() {
    const state = readContext();
    need(state && !state.then && state.status === 'RUNNING' && state.verified && !state.restore_pending, 'PERMISSION_REVOKED');
    need(digest(runtimePins(frozen, reviewedBinding, state)) === digest(reviewedPins)
      && digest(state) === frozen.manifest.authority_hash, 'GRANT_PIN_STALE');
    const checked = engine.preflight(session, frozen.ref);
    need(checked.decision === 'READY_OFFLINE' && checked.request_hash === frozen.request_hash
      && digest(checked.budget) === digest(frozen.manifest.budget), 'CONTEXT_PREFLIGHT_DENIED');
    need(typeof validateInputs === 'function' && validateInputs() === true, 'ARTIFACT_PREFLIGHT_DENIED');
    need(digest(readContext()) === digest(state), 'FINAL_AUTHORITY_CHANGED');
    return true;
  }
  function afterReply(result) {
    if (result.status !== 'SUCCEEDED') return result;
    try { barrier(); return result; }
    catch {
      budget.stop('POST_MODEL_PREFLIGHT');
      return {status: 'DENY', code: 'POST_MODEL_PREFLIGHT', physicalDecision: 'DENY',
        settled_cost_micros: result.costMicros, output: null, simulated: true};
    }
  }
  return Object.freeze({
    async run() {
      need(!started, 'ALREADY_STARTED'); barrier(); started = true;
      const result = await budget.execute(proposal.handle, () => barrier());
      return afterReply(result);
    },
    async retry() {
      need(started, 'RETRY_PREFLIGHT_REQUIRED');
      const result = await budget.retry(proposal.handle, () => barrier());
      return afterReply(result);
    },
    preflight() { return barrier(); },
    cancel() { budget.cancel(); },
    requestPhysicalEffect() { return {decision: 'DENY', code: 'E0_PHYSICAL_EGRESS_DISABLED'}; }
  });
}

// An append-only synthetic causal journal; it is neither a durable log nor a QA backend.
export function createReceiptChain() {
  const rows = []; let blocked = false;
  const sequence = ['CONTEXT_PREFLIGHT','SYNTHETIC_CHILD','D06_SETTLED','INT01_CANARY','D03_RECEIPT','D07_ARTIFACT'];
  return Object.freeze({
    append(kind, evidence) {
      need(!blocked && (kind === 'OUTCOME_UNKNOWN' || kind === sequence[rows.length]), 'CHAIN_BLOCKED');
      const body = {sequence: rows.length, kind, previous: rows.at(-1)?.hash ?? null, evidence: copy(evidence)};
      const row = {...body, hash: digest(body)}; rows.push(row);
      if (kind === 'OUTCOME_UNKNOWN') blocked = true;
      return copy(row);
    },
    quarantine(reason) { if (!blocked) this.append('OUTCOME_UNKNOWN', {reason, replay_allowed: false}); },
    inspect() { return {rows: copy(rows), quarantined: blocked}; },
    completion() { return {work: blocked ? 'OUTCOME_UNKNOWN' : rows.at(-1)?.kind === 'D07_ARTIFACT' ? 'WORK_COMPLETED' : 'INCOMPLETE', independent_qa: 'NOT_RUN',
      accepted: false, published: false, authoritative_complete: false, physical_decision: 'DENY'}; }
  });
}
