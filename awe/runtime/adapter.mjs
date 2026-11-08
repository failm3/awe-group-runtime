import {digest} from '../../contracts/canonical.mjs';
import {validate, createValidationContext} from '../../contracts/validate.mjs';
import {parseIntent, copy, freeze} from '../policy/json.mjs';
import {ensure, same, denied, createToolRegistry, summarizeSyntheticPayload} from '../tools/registry.mjs';
import {createFakeHermesTransport, isSyntheticTransport, RUNTIME_INTERFACE} from './fake-hermes.mjs';

const registries = new WeakMap();
/** Host-owned in-memory registry survives adapter replacement within this process only. */
export function createRunRegistry() {
  const token = Object.freeze({});
  registries.set(token, {runs: new Map(), operations: new Map()}); return token;
}
const active = new Set(['CREATED', 'RUNNING', 'CANCEL_REQUESTED', 'UNKNOWN']);
const view = r => freeze(copy({grant: r.grant, executor_id: r.executorId, status: r.status,
  reason: r.reason, owner_epoch: r.ownerEpoch, reserved_children: r.children.length,
  delegated_attempts: r.allocated, dispatch_requests: r.used, work_output: r.output,
  independent_qa: 'NOT_RUN', authoritative_task_completion: false}));

/** Trusted E0 host assembly; controls, sessions and bridge handles must never be exposed to workers.
 * D04 is a local protocol layer, NOT an OS sandbox, durable store, issuer or physical admission gate.
 */
export function createRuntimeAdapter({state, reader, supervisor, bridge, clock, configHash, manifestHash,
  registry = createRunRegistry(), transport = createFakeHermesTransport()}) {
  ensure(registries.has(registry), 'REGISTRY_UNTRUSTED');
  ensure(isSyntheticTransport(transport), 'SYNTHETIC_TRANSPORT_REQUIRED');
  const {runs, operations} = registries.get(registry), handles = new Map(), tools = createToolRegistry();
  let tail = Promise.resolve();
  const serial = action => { const next = tail.then(action); tail = next.catch(() => {}); return next; };
  const run = id => { ensure(runs.has(id), 'RUN_NOT_REGISTERED'); return runs.get(id); };
  const unknown = (r, reason) => { if (active.has(r.status)) { r.status = 'UNKNOWN'; r.reason = reason; } };
  const snapshot = r => ({project: state.getProject(reader, r.grant.scope.project_id), task: state.getTask(reader, r.grant.scope)});
  function current(r) {
    const s = snapshot(r), g = r.grant;
    ensure(s.project.status === 'READY' && s.task.state === 'RUNNING' && !s.task.cancel_requested
      && !s.task.restore_pending && !s.task.acceptance_stale, 'RUNTIME_STATE_DENIED');
    ensure(same(s.project.epochs, g.epochs) && same(s.task.spec, g.spec), 'GRANT_VERSION_STALE');
    ensure(s.task.config_revision === r.configRevision && configHash === g.config_hash && manifestHash === g.manifest_hash, 'GRANT_PIN_STALE');
    ensure(clock() < g.deadline && s.task.lease?.expires_at > clock() && s.task.lease.holder === supervisor.identity_id
      && s.task.fence === r.fence && s.task.lease_epoch === r.leaseEpoch, 'GRANT_LEASE_EXPIRED');
    return s;
  }
  function lineage(r) {
    current(r);
    if (r.grant.parent_run_id) {
      const parent = run(r.grant.parent_run_id); current(parent);
      ensure(parent.status === 'RUNNING', 'PARENT_NOT_RUNNING');
    }
  }
  function authenticate(session, r, scope = r.grant.scope) {
    const auth = bridge.worker.authenticate(session, scope);
    ensure(auth.actor.identity_id === r.executorId && auth.actor.role === 'EXECUTOR', 'RUN_ACTOR_DENIED');
    return auth;
  }
  const attempt = async action => { try { return await action(); } catch (e) { return denied(e); } };
  const control = Object.freeze({
    registerTool: text => tools.register(text),
    registerGrant(text, executorId) {
      const grant = parseIntent(text), s = {project: state.getProject(reader, grant.scope?.project_id), task: state.getTask(reader, grant.scope)};
      ensure(!runs.has(grant.run_id), 'RUN_ALREADY_REGISTERED');
      const parent = grant.parent_run_id === null ? null : run(grant.parent_run_id);
      const ctx = createValidationContext({now: clock(), authenticated_identity_id: supervisor.identity_id,
        principals: {[supervisor.identity_id]: {role: 'SUPERVISOR', projects: [grant.scope.project_id]}},
        project_id: grant.scope.project_id, task_id: grant.scope.task_id, operation: {id: grant.scope.operation_id},
        epochs: s.project.epochs, spec: s.task.spec, revision: s.task.revision, parent_grant: parent?.grant ?? null});
      const validated = validate('run-grant', grant, ctx);
      ensure(validated.ok, 'RUN_GRANT_INVALID');
      ensure(grant.scope.operation_id === s.task.control_operation_id, 'GRANT_CONTROL_SCOPE_REQUIRED');
      ensure(typeof executorId === 'string' && /^act_[a-z0-9][a-z0-9_-]{0,63}$(?![\s\S])/.test(executorId), 'EXECUTOR_INVALID');
      ensure(grant.actor.identity_id === supervisor.identity_id && grant.deadline <= s.task.lease?.expires_at, 'GRANT_LEASE_EXPIRED');
      ensure(grant.capabilities.every(id => tools.get(id)), 'TOOL_NOT_REGISTERED');
      if (parent) {
        lineage(parent); ensure(parent.status === 'RUNNING', 'PARENT_NOT_RUNNING');
        ensure(parent.grant.depth === 0 && same(parent.grant.scope, grant.scope)
          && same(parent.grant.epochs, grant.epochs) && same(parent.grant.spec, grant.spec)
          && parent.grant.config_hash === grant.config_hash && parent.grant.manifest_hash === grant.manifest_hash, 'CHILD_SCOPE_WIDENED');
        ensure(parent.children.length < parent.grant.max_children, 'CHILD_LIMIT');
        ensure(parent.used + parent.allocated + grant.max_physical_attempts <= parent.grant.max_physical_attempts, 'TREE_ATTEMPT_LIMIT');
      }
      const r = {grant: freeze(copy(grant)), executorId, status: 'CREATED', reason: null, children: [],
        allocated: 0, used: 0, output: null, ownerEpoch: s.project.epochs.owner,
        configRevision: s.task.config_revision, fence: s.task.fence, leaseEpoch: s.task.lease_epoch};
      current(r);
      runs.set(grant.run_id, r);
      if (parent) { parent.children.push(grant.run_id); parent.allocated += grant.max_physical_attempts; }
      return view(r);
    },
    registerAdmission(runId, prepared) {
      const r = run(runId); lineage(r); ensure(r.status === 'RUNNING', 'RUN_NOT_RUNNING');
      const i = copy(prepared.intent), t = tools.get(i.tool_id);
      ensure(r.grant.capabilities.includes(t.id), 'CAPABILITY_DENIED');
      ensure(i.scope.project_id === r.grant.scope.project_id && i.scope.task_id === r.grant.scope.task_id
        && i.scope.operation_id !== r.grant.scope.operation_id && i.actor.identity_id === r.executorId, 'TOOL_SCOPE_DENIED');
      ensure(i.action === t.action && i.resource === t.resource && i.tool_digest === t.digest
        && i.input_schema_hash === t.input_schema_hash && digest(i.payload) === i.payload_hash, 'TOOL_BINDING_DENIED');
      const key = digest(i.scope);
      ensure(!operations.has(key), 'OPERATION_ALREADY_REGISTERED');
      operations.set(key, {runId, intent: freeze(i), handle: prepared.handle, status: 'REGISTERED', receipt: null, output: null});
      return i.scope.operation_id;
    },
    reconcile(runId) {
      const r = run(runId), s = snapshot(r);
      if (active.has(r.status)) {
        if (s.project.epochs.owner !== r.ownerEpoch) unknown(r, 'OWNER_EPOCH_CHANGED');
        else if (!handles.has(runId)) unknown(r, 'HELPER_HANDLE_LOST');
        else {
          try { lineage(r); transport.reconcile(handles.get(runId)); }
          catch { unknown(r, 'RECONCILIATION_REQUIRED'); }
        }
      }
      return view(r); // UNKNOWN retains reservation. No launch/replay or automatic slot release.
    },
    inspect: () => freeze(copy({interface: RUNTIME_INTERFACE, runs: [...runs.values()].map(view),
      operations: [...operations.values()].map(o => ({run_id: o.runId, operation_id: o.intent.scope.operation_id,
        bridge_run_id: o.intent.run_id, status: o.status, receipt: o.receipt, output: o.output})),
      physical_dispatches: 0, transport: transport.inspect(), persistence: 'PROCESS_LOCAL_ONLY'}))
  });
  function operation(r, id) {
    const op = operations.get(digest({...r.grant.scope, operation_id: id}));
    ensure(op?.runId === r.grant.run_id, 'OPERATION_SCOPE_DENIED'); return op;
  }
  async function cancel(r) {
    if (!active.has(r.status)) return view(r);
    if (r.status === 'UNKNOWN') return view(r);
    r.status = 'CANCEL_REQUESTED';
    for (const id of r.children) await cancel(run(id));
    try {
      ensure(handles.has(r.grant.run_id), 'HELPER_HANDLE_LOST');
      const result = transport.interrupt(handles.get(r.grant.run_id));
      ensure(result.status === 'CANCELLED', 'CANCEL_NOT_ACKNOWLEDGED');
      ensure(!r.children.some(id => active.has(run(id).status))
        && ![...operations.values()].some(o => o.runId === r.grant.run_id && ['DISPATCHED', 'OUTCOME_UNKNOWN'].includes(o.status)), 'CANCEL_RECONCILIATION_REQUIRED');
      r.status = 'CANCELLED'; r.reason = null;
    } catch (e) { unknown(r, e.message); }
    return view(r);
  }
  const worker = Object.freeze({
    launch: (session, id) => serial(() => attempt(() => {
      const r = run(id); authenticate(session, r); lineage(r); ensure(r.status === 'CREATED', 'RUN_ALREADY_LAUNCHED');
      r.status = 'RUNNING';
      try { handles.set(id, transport.launch(r.grant)); } catch (e) { unknown(r, e.message); }
      return view(r);
    })),
    status: (session, id) => attempt(() => { const r = run(id); authenticate(session, r); return view(r); }),
    reconcile: (session, id, ownerEpoch) => serial(() => attempt(() => {
      const r = run(id); authenticate(session, r);
      ensure(ownerEpoch === snapshot(r).project.epochs.owner, 'OWNER_EPOCH_STALE');
      return control.reconcile(id);
    })),
    interrupt: (session, id) => serial(() => attempt(() => { const r = run(id); authenticate(session, r); return cancel(r); })),
    executeTool: (session, id, operationId) => serial(() => attempt(async () => {
      const r = run(id); authenticate(session, r); lineage(r); ensure(r.status === 'RUNNING', 'RUN_NOT_RUNNING');
      ensure(handles.has(id) && transport.status(handles.get(id)).status === 'RUNNING', 'HELPER_HANDLE_LOST');
      const op = operation(r, operationId); ensure(op.status === 'REGISTERED', 'OPERATION_ALREADY_ATTEMPTED');
      const t = tools.get(op.intent.tool_id);
      ensure(r.grant.capabilities.includes(t.id) && r.used + r.allocated < r.grant.max_physical_attempts, 'TREE_ATTEMPT_LIMIT');
      const auth = authenticate(session, r, op.intent.scope), text = JSON.stringify(op.intent);
      const reviewed = await bridge.worker.review(auth, op.handle, text);
      ensure(reviewed.decision === 'ALLOW_SIMULATION' && reviewed.physical_decision === 'DENY', 'PEP_DENIED');
      lineage(r); // no await or worker callback between this check and entering the INT-01 barrier
      op.status = 'OUTCOME_UNKNOWN'; r.used++;
      let result;
      try { result = await bridge.worker.dispatchCanary(auth, op.handle, text); }
      catch { unknown(r, 'BRIDGE_CALLBACK_LOST'); return {decision: 'OUTCOME_UNKNOWN', physical_decision: 'DENY'}; }
      if (result.decision === 'CANARY_RECORDED') {
        op.status = 'DISPATCHED'; op.output = summarizeSyntheticPayload(op.intent.payload);
      } else if (result.decision === 'DENY') { op.status = 'DENIED'; }
      else unknown(r, 'D02_D03_RECONCILIATION_REQUIRED');
      return freeze(copy({...result, runtime_run_id: id, operation_id: operationId}));
    })),
    collectToolReceipt: (session, id, operationId) => serial(() => attempt(async () => {
      const r = run(id); authenticate(session, r); lineage(r); ensure(r.status === 'RUNNING', 'RUN_NOT_RUNNING');
      const op = operation(r, operationId); ensure(op.status === 'DISPATCHED', 'RECEIPT_NOT_READY');
      const s = current(r), i = op.intent;
      const receipt = {schema_version: '1.0.0', contract: 'tool-receipt', request_id: 'req_runtime',
        correlation_id: i.scope.operation_id.replace(/^op_/, 'corr_'), causation_id: null, actor: reader, scope: i.scope,
        epochs: s.project.epochs, spec: s.task.spec, created_at: clock(), expected_revision: s.task.revision,
        receipt_id: i.scope.operation_id.replace(/^op_/, 'rcpt_'), tool_id: i.tool_id, tool_digest: i.tool_digest,
        payload_hash: i.payload_hash, effect_class: tools.get(i.tool_id).effect_class, outcome: 'CONFIRMED',
        output: null, full_output_bytes: 0, truncated: false, retry_allowed: false,
        external_receipt: digest({profile: 'D04_SYNTHETIC_READBACK_V1', scope: i.scope, output: op.output})};
      // Only the fixed synthetic producer constructs receipts. Worker text is never accepted as one.
      try { await state.recordToolReceipt(reader, receipt); }
      catch (e) { op.status = 'OUTCOME_UNKNOWN'; unknown(r, 'RECEIPT_COMMIT_UNKNOWN'); throw e; }
      op.receipt = freeze(copy(receipt)); op.status = 'CONFIRMED'; return freeze({mode: 'SYNTHETIC_ONLY', receipt: op.receipt, output: op.output});
    })),
    complete: (session, id) => serial(() => attempt(() => {
      const r = run(id); authenticate(session, r); lineage(r); ensure(r.status === 'RUNNING', 'RUN_NOT_RUNNING');
      ensure(!r.children.some(child => run(child).status !== 'WORK_COMPLETED'), 'CHILD_WORK_INCOMPLETE');
      const own = [...operations.values()].filter(o => o.runId === id);
      ensure(own.every(o => o.status === 'CONFIRMED'), 'TOOL_WORK_INCOMPLETE');
      const output = {tools: own.map(o => o.output), children: r.children.map(child => run(child).output)};
      transport.complete(handles.get(id), output); r.output = output; r.status = 'WORK_COMPLETED'; return view(r);
    })),
    requestPhysicalEffect: () => denied(new Error('PHYSICAL_DISPATCH_DISABLED'))
  });
  return Object.freeze({control, worker});
}
