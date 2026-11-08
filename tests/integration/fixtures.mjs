import {digest} from '../../contracts/canonical.mjs';
import {createE0Bridge, effectReviewHash} from '../../awe/integration/bridge.mjs';
import {MemoryStorage} from '../../awe/state/memory-storage.mjs';
import {harness, scope, dto, evidence} from '../state/harness.mjs';

export {scope};
export async function fixture({action = 'publish', quota = '100', quoteStatus = 'QUOTED',
  policyId, subjectsConflict = false, verified = true, beforeWait = false} = {}) {
  let available = true, fault = null;
  const memory = new MemoryStorage({fault: stage => { if (stage === fault) throw new Error('CANARY_COMMIT_FAULT'); }});
  const storage = {read: query => { if (!available) throw new Error('STORE_UNAVAILABLE'); return memory.read(query); },
    transaction: reducer => { if (!available) throw new Error('STORE_UNAVAILABLE'); return memory.transaction(reducer); },
    snapshot: () => memory.snapshot()};
  const h = harness({storage, serviceOptions: {pep: () => ({decision: 'ALLOW'})}});
  await h.running();
  const taskScope = scope(), opScope = {...taskScope, operation_id: 'op_integrated'};
  const payload = {recipient: 'synthetic-memory-only', content: 'E0 canary'};
  const tool = {id: 'tool_integrated', action, resource: 'canary:work', digest: digest({tool: 'memory-recorder-v1'}),
    input_schema_hash: digest({schema: 'input'}), output_schema_hash: digest({schema: 'output'}),
    effect_class: action === 'read' ? 'READ_ONLY' : 'NON_IDEMPOTENT', cost_micros: '10',
    quote: {schema_version: '1.0.0', contract: 'provider-price', price_profile_id: 'price_fixture', status: quoteStatus,
      seller: 'synthetic.invalid', model: 'synthetic', currency: quoteStatus === 'QUOTED' ? 'USD' : null,
      input_micros_per_million: quoteStatus === 'QUOTED' ? '1' : null,
      output_micros_per_million: quoteStatus === 'QUOTED' ? '2' : null,
      quote_ref: quoteStatus === 'QUOTED' ? digest({quote: 'canary'}) : null,
      checked_at: quoteStatus === 'QUOTED' ? h.now() : null,
      expires_at: quoteStatus === 'QUOTED' ? '2026-11-05T12:01:00.000Z' : null,
      reason: quoteStatus === 'QUOTED' ? null : 'Synthetic unavailable quote'}};
  const principals = ['OWNER', 'SUPERVISOR', 'EXECUTOR', 'STATE_SERVICE', 'EXAMINER', 'AUDITOR'].map(role => ({
    actor: {identity_id: {OWNER: 'act_owner', SUPERVISOR: 'act_supervisor', EXECUTOR: 'act_worker',
      STATE_SERVICE: 'act_state', EXAMINER: 'act_examiner', AUDITOR: 'act_auditor'}[role], role},
    subject: subjectsConflict && role === 'EXAMINER' ? 'synthetic-EXECUTOR' : 'synthetic-' + role,
    tasks: [{project_id: taskScope.project_id, task_id: taskScope.task_id}]}));
  const resources = [{id: 'canary:work', project_id: taskScope.project_id, task_id: taskScope.task_id,
    classification: 'WORK', roles: ['EXECUTOR'], value: {canary: 'PUBLIC_CANARY'}},
  {id: 'canary:trace', project_id: taskScope.project_id, task_id: taskScope.task_id,
    classification: 'TRACE', roles: ['OWNER', 'SUPERVISOR', 'EXECUTOR', 'EXAMINER', 'AUDITOR'],
    value: {raw: 'RAW_TRACE_CANARY', hidden: 'HIDDEN_CANARY'}}];
  const bridgeOptions = {state: h.service, storage, supervisor: h.supervisor, reader: h.state, scope: taskScope,
    principals, resources, tool, executorId: 'act_worker', clock: h.now, quotaMicros: quota, policyId};
  const bridge = await createE0Bridge(bridgeOptions);
  const input = {scope: opScope, payload, tool_id: tool.id, tool_digest: tool.digest, action, resource: tool.resource,
    effect_class: tool.effect_class, approval_ref: 'oa_integrated'};
  let task = h.service.getTask(h.owner, taskScope);
  await h.service.intent(h.supervisor, input, task.revision, task.lease, 'integrated-intent');
  task = h.service.getTask(h.owner, taskScope);
  const preflight = await bridge.worker.preflight(bridge.control.issueSession('act_worker'), JSON.stringify({
    scope: opScope, actor: {identity_id: 'act_worker', role: 'EXECUTOR'}, action, resource: tool.resource,
    payload, payload_hash: digest(payload), epochs: rootEpochs(h), spec: task.spec,
    expected_revision: task.revision, tool_id: tool.id, tool_digest: tool.digest,
    input_schema_hash: tool.input_schema_hash, run_id: 'run_unarmed', approval_id: 'appr_unarmed',
    quote_id: null, reservation_micros: tool.cost_micros}));
  const ownerAction = async status => {
    const task = h.service.getTask(h.owner, taskScope), project = h.service.getProject(h.state, taskScope.project_id);
    const actor = ['VERIFYING', 'VERIFIED'].includes(status) ? h.state : h.owner;
    const operations = Object.values(JSON.parse(storage.snapshot()).data.projects[taskScope.project_id].operations);
    const reviewHash = effectReviewHash(h.service.getOperation(h.state, opScope), 'act_worker', tool.input_schema_hash);
    const binding = {mode: 'E0', scope: taskScope, spec: task.spec, epochs: project.epochs,
      revision: task.revision, fence: task.fence, config_revision: task.config_revision,
      operations_hash: digest(operations), kind: 'OWNER_ACTION', owner_action_id: 'oa_integrated', payload_hash: reviewHash};
    return h.service.storeOwnerAction(actor, dto('owner-action', actor, taskScope, task.spec, project.epochs,
      task.revision, h.now(), {request_id: h.next('req_owner'), owner_action_id: 'oa_integrated', status,
        action: 'scope-review', resource: tool.resource, payload_hash: reviewHash, expires_at: '2026-11-05T12:05:00.000Z',
        max_uses: 1, uses: 0, revoked_at: status === 'REVOKED' ? h.now() : null,
        verification_receipt: status === 'VERIFIED' ? evidence(binding).owner_verification : null}));
  };
  await ownerAction('OPEN');
  const verify = async () => { for (const status of ['SUBMITTED', 'VERIFYING', 'VERIFIED']) await ownerAction(status); };
  if (beforeWait && verified) await verify();
  const subscription = await h.subscribe(taskScope, h.service.cursor(h.supervisor, taskScope.project_id), 'owner-action.updated', 'oa_integrated');
  if (!beforeWait && verified) await verify();
  if (verified) await h.wake(subscription);
  const ownerSession = bridge.control.issueSession('act_owner'), executorSession = bridge.control.issueSession('act_worker');
  const f = {h, bridge, bridgeOptions, preflight, opScope, taskScope, payload, input, tool, ownerAction, subscription, ownerSession, executorSession,
    outage: value => { available = value; }, fault: value => { fault = value; },
    inspect: bridge.control.inspect, operation: () => h.service.getOperation(h.state, opScope),
    task: () => h.service.getTask(h.state, taskScope)};
  if (verified) {
    const prepared = await bridge.control.prepare(opScope, payload);
    f.handle = prepared.handle; f.intent = prepared.intent; f.text = JSON.stringify(f.intent);
    f.auth = bridge.worker.authenticate(executorSession, opScope);
    await bridge.control.approve(ownerSession, f.handle, 'oa_integrated');
  }
  f.dispatch = (text = f.text, context = f.auth, handle = f.handle) => bridge.worker.dispatchCanary(context, handle, text);
  f.review = () => bridge.worker.review(f.auth, f.handle, f.text);
  return f;
}
const rootEpochs = h => h.service.getProject(h.state, 'prj_alpha').epochs;

export async function completeCanary(f, unknown = true) {
  const {h, opScope, taskScope} = f;
  const dispatch = await f.dispatch();
  if (dispatch.decision !== 'CANARY_RECORDED') throw new Error(JSON.stringify(dispatch));
  await h.service.recordToolReceipt(h.state, h.receipt(opScope, unknown ? 'OUTCOME_UNKNOWN' : 'CONFIRMED'));
  const retained = f.operation().retained_reservation;
  if (unknown) {
    await h.reconcile(opScope, 'APPLIED'); const task = f.task();
    await h.service.resume(h.supervisor, taskScope, task.revision, task.lease);
  }
  await h.go('QA_PENDING'); await h.go('PERSISTING');
  const task = f.task(), checkpoint = await h.service.checkpoint(h.supervisor, taskScope, task.revision, task.lease);
  await h.go('COMPLETE');
  return {dispatch, retained, checkpoint, task: f.task()};
}
