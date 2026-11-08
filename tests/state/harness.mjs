import {digest} from '../../contracts/canonical.mjs';
import {MemoryStorage} from '../../awe/state/memory-storage.mjs';
import {StateService} from '../../awe/state/service.mjs';

export const guards = ['quota', 'local_qa', 'examiner_qa', 'auditor_qa', 'integration_qa',
  'persisted', 'independent_readback', 'resume_verified', 'qa02', 'owner_verification'];
export const evidence = binding => Object.fromEntries(guards.map(guard => [guard, digest({guard, binding})]));
export const scope = (project = 'prj_alpha', task = 'task_one', operation = 'op_control_one') => ({project_id: project, task_id: task, operation_id: operation});
export const dto = (contract, actor, taskScope, spec, epochs, revision, now, extra = {}) => ({
  schema_version: '1.0.0', contract, request_id: 'req_fixture', correlation_id: 'corr_fixture',
  causation_id: null, actor, scope: taskScope, epochs, spec, created_at: now, expected_revision: revision, ...extra
});

export function harness(options = {}) {
  let now = '2026-11-05T12:00:00.000Z';
  let counter = 0;
  const storage = options.storage ?? new MemoryStorage(options.storageOptions);
  const principals = {
    act_owner: {role: 'OWNER', projects: ['prj_alpha', 'prj_beta']},
    act_supervisor: {role: 'SUPERVISOR', projects: ['prj_alpha', 'prj_beta']},
    act_other_supervisor: {role: 'SUPERVISOR', projects: ['prj_alpha']},
    act_state: {role: 'STATE_SERVICE', projects: ['prj_alpha', 'prj_beta']},
    act_broker: {role: 'ROUTE_BROKER', projects: ['prj_alpha']},
    act_worker: {role: 'EXECUTOR', projects: ['prj_alpha']},
    act_foreign: {role: 'SUPERVISOR', projects: ['prj_beta']}
  };
  const receipts = new Map();
  const service = new StateService({storage, principals, clock: () => now,
    evidence: options.evidence ?? evidence,
    verifyEvent: event => receipts.get(event.event_id) ?? false,
    verifyReconciliation: (binding, resolution) => resolution.receipt === digest({profile: 'CANARY_READBACK', binding}),
    ...options.serviceOptions});
  const owner = service.session('act_owner'), supervisor = service.session('act_supervisor'), state = service.session('act_state');
  const h = {storage, service, owner, supervisor, state, receipts,
    now: () => now, tick: ms => { now = new Date(Date.parse(now) + ms).toISOString(); },
    next: prefix => `${prefix}_${++counter}`};
  h.project = async (projectId = 'prj_alpha', ready = true) => {
    const input = {project_id: projectId, name: 'Canary project', config_owner: 'act_owner', config: {template: 'offline-canary-v1'}};
    let p = await service.createProject(owner, input, 'project');
    if (ready) {
      const binding = {mode: 'E0', kind: 'QA02', project_id: projectId, config_owner: p.config_owner,
        config_revision: 1, config_hash: digest(input.config), epochs: p.epochs};
      p = await service.provision(owner, projectId, p.revision, evidence(binding).qa02);
    }
    return p;
  };
  h.spec = async (projectId = 'prj_alpha', content = {requirements: ['canary'], acceptance: ['offline']}, previous = null) => {
    const p = service.getProject(owner, projectId);
    const spec = {spec_id: 'spec_canary', revision: previous ? previous.revision + 1 : 1, content_hash: digest(content)};
    await service.storeSpec(owner, dto('spec-revision', owner, scope(projectId), spec, p.epochs, p.revision, now,
      {status: 'APPROVED', requirements: ['reqmt_canary'], norms: ['constitution:0.1-draft:C-01'], supersedes: previous}), content);
    return spec;
  };
  h.task = async (taskScope = scope(), dependencies = [], spec = null) => {
    spec ??= await h.spec(taskScope.project_id);
    return service.createTask(supervisor, {scope: taskScope, name: 'Synthetic task', dependencies, spec}, taskScope.task_id);
  };
  h.lease = async (taskScope = scope(), actor = supervisor, ttl = 10000) =>
    service.acquireLease(actor, taskScope, service.getTask(actor, taskScope).revision, ttl);
  h.transitionDto = (to, taskScope = scope(), actor = supervisor, extra = {}) => {
    const {task, epochs, guards: refs} = service.getTransitionContext(actor, taskScope);
    return dto('state-transition', actor, taskScope, task.spec, epochs, task.revision, now, {
      event_id: h.next('evt_transition'), from_state: task.state, to_state: to,
      lease_epoch: task.lease_epoch, fence: task.fence, resume_state: task.resume_state,
      reason: 'Synthetic acceptance fixture', guard_refs: [...new Set(Object.values(refs))], owner_action_id: null, subscription_id: null, ...extra
    });
  };
  h.go = (to, taskScope = scope(), extra = {}) => service.transition(supervisor, h.transitionDto(to, taskScope, supervisor, extra));
  h.running = async (taskScope = scope()) => {
    await h.project(taskScope.project_id); const spec = await h.spec(taskScope.project_id);
    await h.task(taskScope, [], spec); await h.lease(taskScope);
    await h.go('READY', taskScope); return h.go('RUNNING', taskScope);
  };
  h.intent = async (taskScope = scope(), effectClass = 'NON_IDEMPOTENT', payload = {canary: 1}) => {
    const opScope = {...taskScope, operation_id: h.next('op_effect')};
    const task = service.getTask(supervisor, taskScope);
    const input = {scope: opScope, payload, tool_id: 'tool_canary', tool_digest: digest({version: 1}),
      action: 'canary.apply', resource: 'canary-only', effect_class: effectClass, approval_ref: null};
    const op = await service.intent(supervisor, input, task.revision, task.lease, h.next('intent'));
    return {input, op, scope: opScope};
  };
  h.dispatch = opScope => {
    const task = service.getTask(supervisor, opScope);
    return service.simulateDispatch(supervisor, opScope, task.revision, task.lease);
  };
  h.receipt = (opScope, outcome = 'CONFIRMED', extra = {}) => {
    const task = service.getTask(state, opScope), op = service.getOperation(state, opScope), p = service.getProject(state, opScope.project_id);
    return dto('tool-receipt', state, opScope, task.spec, p.epochs, task.revision, now, {
      receipt_id: h.next('rcpt_canary'), ...op.binding, effect_class: op.effect_class, outcome,
      output: null, full_output_bytes: 0, truncated: false, retry_allowed: false,
      external_receipt: outcome === 'CONFIRMED' ? digest({canary_receipt: opScope}) : null, ...extra
    });
  };
  h.reconcile = (opScope, outcome) => {
    const task = service.getTask(state, opScope), op = service.getOperation(state, opScope), p = service.getProject(state, opScope.project_id);
    const binding = {scope: opScope, spec: task.spec, epochs: p.epochs, revision: task.revision, payload_hash: op.binding.payload_hash, outcome};
    return service.reconcile(state, opScope, task.revision, {outcome, receipt: digest({profile: 'CANARY_READBACK', binding})});
  };
  h.action = async (status = 'OPEN', taskScope = scope(), actionId = 'oa_canary') => {
    const task = service.getTask(owner, taskScope), p = service.getProject(owner, taskScope.project_id);
    const actor = ['VERIFYING', 'VERIFIED'].includes(status) ? state : owner;
    const binding = {mode: 'E0', scope: {...taskScope, operation_id: task.control_operation_id}, spec: task.spec,
      epochs: p.epochs, revision: task.revision, fence: task.fence, config_revision: p.config_revision,
      operations_hash: digest([]), kind: 'OWNER_ACTION', owner_action_id: actionId, payload_hash: digest({owner: 'canary'})};
    const action = dto('owner-action', actor, taskScope, task.spec, p.epochs, task.revision, now, {
      request_id: h.next('req_action'), owner_action_id: actionId, status, action: 'scope-review',
      resource: 'canary-only', payload_hash: binding.payload_hash, expires_at: '2026-11-05T12:05:00.000Z',
      max_uses: 1, uses: 0, revoked_at: status === 'REVOKED' ? now : null,
      verification_receipt: status === 'VERIFIED' ? evidence(binding).owner_verification : null
    });
    return service.storeOwnerAction(actor, action);
  };
  h.verifyAction = async taskScope => { for (const status of ['SUBMITTED', 'VERIFYING', 'VERIFIED']) await h.action(status, taskScope); };
  h.subscribe = (taskScope = scope(), cursor = service.cursor(supervisor, taskScope.project_id), type = 'owner-action.updated', ownerActionId = 'oa_canary') => {
    const task = service.getTask(supervisor, taskScope), p = service.getProject(supervisor, taskScope.project_id), subscriptionId = h.next('sub_canary');
    const sub = dto('wait-subscription', supervisor, taskScope, task.spec, p.epochs, task.revision, now,
      {subscription_id: subscriptionId, event_type: type, resume_state: task.state, cursor, deadline: '2026-11-05T12:00:30.000Z'});
    const transition = h.transitionDto(type === 'owner-action.updated' ? 'WAITING_FOR_OWNER' : 'WAITING_FOR_EVENT',
      {...taskScope, operation_id: task.control_operation_id}, supervisor,
      {scope: taskScope, subscription_id: subscriptionId, owner_action_id: ownerActionId, resume_state: task.state});
    return service.subscribe(supervisor, sub, transition, ownerActionId);
  };
  h.wake = subscription => {
    const task = service.getTask(supervisor, subscription.dto.scope);
    return service.wake(supervisor, subscription.dto.scope.project_id, subscription.dto.subscription_id, task.revision, task.lease);
  };
  return h;
}
