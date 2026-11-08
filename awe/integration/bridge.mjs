import {digest} from '../../contracts/canonical.mjs';
import {createOfflineSecurity, SIMULATION_POLICY} from '../policy/security.mjs';
import {copy, freeze, parseIntent} from '../policy/json.mjs';

const ensure = (ok, code) => { if (!ok) throw new Error(code); };
const same = (a, b) => digest(a) === digest(b);
export const effectReviewHash = (operation, executorId, inputSchemaHash) => digest({
  profile: 'E0_EFFECT_SCOPE_REVIEW_V1', scope: operation.scope, spec: operation.spec, epochs: operation.epochs,
  action: operation.action, resource: operation.resource, binding: operation.binding,
  effect_class: operation.effect_class, executor_id: executorId, input_schema_hash: inputSchemaHash});
const deny = error => freeze({decision: 'DENY', physical_decision: 'DENY',
  reason: /^[A-Z0-9_]+$/.test(error.code ?? error.message) ? (error.code ?? error.message) : 'BOUNDARY_DENIED'});
const dto = (contract, actor, scope, snapshot, now, extra) => ({schema_version: '1.0.0', contract,
  request_id: 'req_integration', correlation_id: 'corr_integration', causation_id: null,
  actor, scope, epochs: snapshot.project.epochs, spec: snapshot.task.spec, created_at: now,
  expected_revision: snapshot.task.revision, ...extra});

/** Trusted host factory, E0 only. Neither this configuration nor control is a worker API.
 * StateService sessions remain synthetic. No executor, transport or callback is accepted.
 * D02 consumption and D03 commit are NOT one transaction; ambiguity quarantines the bridge.
 */
export async function createE0Bridge({state, storage, supervisor, reader, scope, principals, resources,
  tool, executorId, clock, quotaMicros = '100', policyId = SIMULATION_POLICY}) {
  scope = freeze(copy(scope)); tool = freeze(copy(tool));
  const rootProject = await state.getProject(reader, scope.project_id);
  const rootTask = await state.getTask(reader, scope);
  await state.getTask(supervisor, scope); // check D03 session provenance independently
  const priorOperations = await storage.read(db => {
    const project = db.projects[scope.project_id], task = project?.tasks[scope.task_id];
    ensure(task && same(task, rootTask) && same(project.epochs, rootProject.epochs), 'HANDSHAKE_SNAPSHOT_MISMATCH');
    return Object.values(project.operations).filter(op => op.scope.task_id === scope.task_id).map(op => op.scope.operation_id);
  });
  ensure(rootTask.control_operation_id === scope.operation_id && rootTask.state === 'RUNNING'
    && !rootTask.restore_pending && !rootTask.cancel_requested && !rootTask.acceptance_stale, 'HANDSHAKE_STATE_DENIED');
  ensure(supervisor.role === 'SUPERVISOR' && reader.role === 'STATE_SERVICE', 'HANDSHAKE_ROLE_DENIED');
  const subject = principals.find(p => p.actor.identity_id === executorId);
  ensure(subject?.actor.role === 'EXECUTOR', 'EXECUTOR_REQUIRED');
  // Load actual state into D02 once; retain its approval/quota/replay ledgers for this instance.
  const security = createOfflineSecurity({mode: 'SYNTHETIC_ONLY', principals: copy(principals),
    projects: [{project_id: scope.project_id, epochs: rootProject.epochs, policy_id: policyId,
      tasks: [{task_id: scope.task_id, revision: rootTask.revision, state: rootTask.state,
        spec: rootTask.spec, quota_micros: quotaMicros}]}], resources: copy(resources)}, {clock});
  const supervisorAuth = opScope => security.worker.authenticate(
    security.control.issueSession(supervisor.identity_id), opScope);
  const records = new WeakMap(), ownerUses = new Set();
  let mirrorRevision = rootTask.revision, poisoned = false, tail = Promise.resolve();
  const serial = action => {
    const run = tail.then(action); tail = run.catch(() => {}); return run;
  };
  const checkScope = opScope => ensure(opScope.project_id === scope.project_id
    && opScope.task_id === scope.task_id && opScope.operation_id !== scope.operation_id, 'SCOPE_DENIED');
  async function load(opScope) {
    checkScope(opScope);
    ensure(!priorOperations.includes(opScope.operation_id), 'PRE_HANDSHAKE_OPERATION_BLOCKED');
    const project = await state.getProject(reader, scope.project_id);
    const task = await state.getTask(reader, opScope);
    const operation = await state.getOperation(reader, opScope);
    ensure(!poisoned, 'BRIDGE_QUARANTINED');
    ensure(same(project.epochs, rootProject.epochs) && same(task.spec, rootTask.spec), 'HANDSHAKE_VERSION_MISMATCH');
    ensure(project.status === 'READY' && task.state === 'RUNNING' && !task.restore_pending
      && !task.cancel_requested && !task.acceptance_stale, 'EFFECT_STATE_DENIED');
    ensure(task.lease?.holder === supervisor.identity_id && task.lease.expires_at > clock()
      && task.fence === task.lease.fence && task.lease_epoch === task.lease.lease_epoch, 'STALE_LEASE_OR_FENCE');
    ensure(operation.status === 'INTENT' && operation.attempts === 0, 'REPLAY_OR_RECONCILIATION_REQUIRED');
    ensure(same(operation.scope, opScope) && same(operation.spec, task.spec)
      && same(operation.epochs, project.epochs), 'OPERATION_VERSION_MISMATCH');
    return {project, task, operation};
  }
  function boundaryOf(s, opScope) {
    const op = s.operation;
    return {schema_version: 'd03-pep-proposal-1', boundary: 'effect.dispatch', actor: supervisor,
      scope: opScope, spec: s.task.spec, epochs: s.project.epochs, expected_revision: s.task.revision,
      lease_epoch: s.task.lease_epoch, fence: s.task.fence, action: op.action, resource: op.resource,
      payload_hash: op.binding.payload_hash, tool_id: op.binding.tool_id, tool_digest: op.binding.tool_digest,
      approval_ref: op.approval_ref, operation_status: op.status, mode: 'E0'};
  }
  // Synchronous final barrier is deliberately E0-specific. A future asynchronous store
  // needs a durable admission protocol, not await(read)-then-send.
  function barrier(record) {
    ensure(!poisoned, 'BRIDGE_QUARANTINED');
    const current = storage.read(db => {
      const p = db.projects[scope.project_id], t = p?.tasks[scope.task_id], op = p?.operations[record.intent.scope.operation_id];
      return !!p && p.status === 'READY' && p.revision === record.snapshot.project.revision
        && p.config_revision === record.snapshot.project.config_revision
        && same(p.epochs, record.snapshot.project.epochs) && !!t && same(t, record.snapshot.task)
        && !!op && same(op, record.snapshot.operation);
    });
    if (current && typeof current.then === 'function') {
      current.catch(() => {}); throw new Error('ASYNC_FINAL_BARRIER_BLOCKED');
    }
    ensure(current === true, 'CURRENT_STATE_MISMATCH');
    const physical = state.requestEffect(supervisor, record.intent.scope, record.snapshot.task.lease);
    if (physical && typeof physical.then === 'function') {
      physical.catch(() => {});
      throw new Error('ASYNC_FINAL_BARRIER_BLOCKED');
    }
    ensure(physical.decision === 'DENY', 'PHYSICAL_DENY_REQUIRED');
    ensure(same(physical.boundary, boundaryOf(record.snapshot, record.intent.scope)), 'CURRENT_STATE_MISMATCH');
    return physical;
  }
  function get(handle, text) {
    const record = records.get(handle);
    ensure(record, 'ADMISSION_UNTRUSTED');
    ensure(!record.dispatched, 'ADMISSION_USED');
    const intent = parseIntent(text);
    ensure(same(intent, record.intent), 'INTENT_BINDING_MISMATCH');
    ensure(record.approved, 'OWNER_APPROVAL_REQUIRED');
    return record;
  }
  const control = Object.freeze({
    issueSession: id => security.control.issueSession(id),
    // Prepare only a D03-recorded intent with pinned tool/resource/payload and fresh state.
    prepare(opScope, payload) {
      opScope = copy(opScope); payload = copy(payload);
      return serial(async () => {
        const snapshot = await load(opScope), op = snapshot.operation;
        ensure(op.action === tool.action && op.resource === tool.resource && op.effect_class === tool.effect_class
          && op.binding.tool_id === tool.id && op.binding.tool_digest === tool.digest
          && op.binding.payload_hash === digest(payload), 'TOOL_OR_PAYLOAD_MISMATCH');
        ensure(snapshot.task.revision >= mirrorRevision, 'STATE_ROLLBACK');
        if (snapshot.task.revision > mirrorRevision) {
          security.control.setTaskState(opScope, 'RUNNING', snapshot.task.revision);
          mirrorRevision = snapshot.task.revision;
        }
        const suffix = digest(opScope).slice(7, 31), auth = supervisorAuth(opScope);
        const toolId = tool.id; // D02 registry IDs are immutable; one prepared operation per tool ID.
        const capability = dto('tool-capability', auth.actor, opScope, snapshot, clock(), {
          tool_id: toolId, tool_version: '1.0.0', tool_digest: tool.digest,
          input_schema_hash: tool.input_schema_hash, output_schema_hash: tool.output_schema_hash,
          effect_class: tool.effect_class, timeout_ms: 1000, max_output_bytes: 16384,
          network_scope: 'NONE', credential_handle: null, retry_eligible: false});
        security.control.registerTool(auth, capability, {actions: [tool.action], resources: [tool.resource],
          roles: ['EXECUTOR'], cost_micros: tool.cost_micros});
        const grant = dto('run-grant', auth.actor, opScope, snapshot, clock(), {
          run_id: 'run_' + suffix, parent_run_id: null, capabilities: [toolId],
          deadline: snapshot.task.lease.expires_at, budget_ref: digest({quotaMicros}),
          config_hash: digest({config_revision: snapshot.task.config_revision}),
          manifest_hash: digest({profile: 'E0_CANARY', tool}), depth: 0, max_children: 0, max_physical_attempts: 1});
        security.control.registerGrant(auth, grant, executorId);
        const quoteId = ['charge', 'inference'].includes(tool.action) ? 'price_' + suffix : null;
        if (quoteId) security.control.registerQuote(auth, {...copy(tool.quote), price_profile_id: quoteId},
          {scope: opScope, tool_id: toolId});
        const intent = {scope: opScope, actor: subject.actor, action: tool.action, resource: tool.resource,
          payload, payload_hash: digest(payload), epochs: snapshot.project.epochs, spec: snapshot.task.spec,
          expected_revision: snapshot.task.revision, tool_id: toolId, tool_digest: tool.digest,
          input_schema_hash: tool.input_schema_hash, run_id: grant.run_id, approval_id: 'appr_' + suffix,
          quote_id: quoteId, reservation_micros: tool.cost_micros};
        const handle = Object.freeze({});
        const record = {snapshot: copy(snapshot), intent: copy(intent), approved: false, dispatched: false};
        barrier(record); records.set(handle, record);
        return Object.freeze({handle, intent: freeze(copy(intent))});
      });
    },
    approve(ownerSession, handle, ownerActionId) {
      return serial(async () => {
        const record = records.get(handle); ensure(record && !record.approved, 'ADMISSION_UNTRUSTED');
        const auth = security.worker.authenticate(ownerSession, record.intent.scope);
        ensure(auth.actor.role === 'OWNER', 'OWNER_REQUIRED');
        const actions = await state.getOwnerActions(reader, scope.project_id);
        const action = actions.find(a => a.dto.owner_action_id === ownerActionId), a = action?.dto;
        ensure(a && a.status === 'VERIFIED' && action.uses === 1 && !ownerUses.has(ownerActionId)
          && a.expires_at > clock() && a.revoked_at === null && a.max_uses === 1
          && same(a.scope, scope) && same(a.spec, record.intent.spec) && same(a.epochs, record.intent.epochs)
          && a.action === 'scope-review' && a.resource === record.intent.resource
          && a.payload_hash === effectReviewHash(record.snapshot.operation, executorId, tool.input_schema_hash)
          && record.snapshot.operation.approval_ref === ownerActionId,
        'OWNER_ACTION_BINDING_MISMATCH');
        barrier(record);
        const approval = dto('approval', auth.actor, record.intent.scope, record.snapshot, clock(), {
          approval_id: record.intent.approval_id, action: record.intent.action, resource: a.resource,
          payload_hash: record.intent.payload_hash, approver: auth.actor, expires_at: a.expires_at,
          max_uses: 1, uses: 0, revoked_at: null, policy_revision: record.intent.epochs.policy});
        security.control.registerApproval(auth, approval, executorId);
        ownerUses.add(ownerActionId); record.approved = true;
        return {mode: 'E0_ONLY', approval_id: approval.approval_id};
      });
    },
    revokeIdentity: id => security.control.revokeIdentity(id),
    revokeApproval: id => security.control.revokeApproval(id),
    revokeGrant: id => security.control.revokeGrant(id),
    revokeTool: id => security.control.revokeTool(id),
    revokeQuote: id => security.control.revokeQuote(id),
    setPolicy: id => security.control.setPolicy(scope.project_id, id),
    async advanceEpoch(key) {
      security.control.advanceEpoch(scope.project_id, key); // deny first, then propagate
      try {
        const p = await state.getProject(reader, scope.project_id), epochs = copy(rootProject.epochs);
        epochs[key]++;
        return await state.syncEpochs(reader, scope.project_id, p.revision, epochs);
      } catch (error) { poisoned = true; throw error; }
    },
    inspect: () => ({...security.control.inspect(), quarantined: poisoned,
      ledger_owner: 'D02_PROCESS_LOCAL_ONLY', actual_external_dispatches: 0})
  });
  const worker = Object.freeze({
    authenticate: (session, opScope) => security.worker.authenticate(session, opScope),
    async preflight(session, text) {
      try {
        const intent = parseIntent(text), snapshot = await load(intent.scope), op = snapshot.operation;
        ensure(intent.action === op.action && intent.resource === op.resource
          && intent.payload_hash === op.binding.payload_hash && digest(intent.payload) === intent.payload_hash
          && intent.tool_id === op.binding.tool_id && intent.tool_digest === op.binding.tool_digest
          && intent.expected_revision === snapshot.task.revision && same(intent.spec, snapshot.task.spec)
          && same(intent.epochs, snapshot.project.epochs), 'INTENT_BINDING_MISMATCH');
        if (snapshot.task.revision > mirrorRevision) {
          security.control.setTaskState(intent.scope, 'RUNNING', snapshot.task.revision);
          mirrorRevision = snapshot.task.revision;
        }
        const context = security.worker.authenticate(session, intent.scope);
        barrier({intent, snapshot});
        // The intent is deliberately unarmed: no capability/grant/owner approval yet.
        // PDP still reviews actual authority; it cannot consume or mint an admission.
        return freeze({...security.worker.pdp(context, text), physical_decision: 'DENY', phase: 'UNARMED_PREFLIGHT'});
      } catch (error) { return deny(error); }
    },
    async review(context, handle, text) {
      try { const record = get(handle, text); await load(record.intent.scope); barrier(record);
        return freeze({...security.worker.pdp(context, text), physical_decision: 'DENY'});
      } catch (error) { return deny(error); }
    },
    dispatchCanary(context, handle, text) {
      // Parse/copy before awaiting; caller cannot mutate the authorized body during a queue wait.
      let record;
      try { record = get(handle, text); } catch (error) { return Promise.resolve(deny(error)); }
      return serial(async () => {
        let recorded = false;
        try {
          ensure(!record.dispatched, 'ADMISSION_USED'); await load(record.intent.scope);
          barrier(record); // no await/user callback between current check and D02 consume
          const result = security.worker.execute(context, text);
          if (result.decision !== 'RECORDED_SIMULATION') return freeze({...result, physical_decision: 'DENY'});
          recorded = true; record.dispatched = true;
          const dispatch = await state.simulateDispatch(supervisor, record.intent.scope,
            record.snapshot.task.revision, record.snapshot.task.lease);
          return freeze({decision: 'CANARY_RECORDED', physical_decision: 'DENY', mode: 'E0_ONLY',
            d02_receipt: result, d03_dispatch: dispatch});
        } catch (error) {
          if (recorded) { poisoned = true;
            return freeze({decision: 'OUTCOME_UNKNOWN', physical_decision: 'DENY',
              reason: 'D02_D03_COMMIT_AMBIGUOUS', retained_consumption: true, reconciliation_required: true});
          }
          return deny(error);
        }
      });
    },
    requestPhysicalEffect: () => freeze({decision: 'DENY', reason: 'E0_PHYSICAL_EFFECTS_DISABLED'}),
    directDispatch: (ticket, text) => security.worker.directDispatch(ticket, text)
  });
  return Object.freeze({control, worker});
}
