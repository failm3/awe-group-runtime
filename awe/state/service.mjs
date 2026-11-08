import {canonicalize, digest} from '../../contracts/canonical.mjs';
import {createValidationContext, validate} from '../../contracts/validate.mjs';
import {validateShape} from '../../contracts/schema-validator.mjs';
import {validateSpecSuccessor} from '../../contracts/revisions.mjs';
import {appendEvent, bodyHash, enqueue, matchSubscription} from '../events/journal.mjs';
import {compensateCanary, newProject, provisionCanary, validateDag} from '../project_factory/factory.mjs';
import {copy, increment, requireState, terminal} from './errors.mjs';
import {catalogueView,prepareCatalogue,commitCatalogue,catalogueContext} from './catalogue.mjs';
import {prepareArtifact,commitArtifact} from './artifact-catalogue.mjs';
import {literalCompletionGuards} from './literal-guards.mjs';
import {isReviewedLocalCompletion} from '../execution_security/local-d09.mjs';
import {isPostgresStateStorage} from './postgres-storage.mjs';

const hashPattern = /^sha256:[a-f0-9]{64}$/;
const active = ['READY', 'RUNNING', 'QA_PENDING', 'REWORK', 'PERSISTING'];
const waiting = ['WAITING_FOR_OWNER', 'WAITING_FOR_EVENT', 'BLOCKED', 'RECONCILING'];
const unresolved = op => ['INTENT', 'DISPATCHED', 'OUTCOME_UNKNOWN'].includes(op.status);
const base = (contract, body) => ({schema_version: '1.0.0', contract, ...body});
const shape = (contract, value) => {
  const errors = validateShape(contract, value);
  requireState(errors.length === 0, 'CONTRACT_INVALID', errors);
};
const id = (value, prefix) => requireState(typeof value === 'string'
  && new RegExp(`^${prefix}_[a-z0-9][a-z0-9_-]{0,63}$`).test(value), 'ID_INVALID');
const text = value => requireState(typeof value === 'string' && value.length > 0 && value.length <= 128, 'NAME_INVALID');
const cas = (task, expected) => requireState(task.revision === expected, 'STALE_REVISION');
const jsonCopy = value => {canonicalize(value); return copy(value);};
const opsFor = (project, task) => Object.values(project.operations).filter(op => op.scope.task_id === task.id);
const controlScope = (project, task) => ({project_id: project.id, task_id: task.id, operation_id: task.control_operation_id});

// E0 ONLY. Registry/evidence/receipt ports are trusted harness inputs, never HTTP/model DTOs.
// No method accepts a real-effect executor, network client, connection string or process handle.
export class StateService {
  #store;
  #principals;
  #sessions = new WeakSet();
  #clock;
  #evidence;
  #verifyEvent;
  #verifyReconciliation;
  #pep;
  constructor({storage, principals, clock, evidence = () => ({}), verifyEvent = () => false,
    verifyReconciliation = () => false, pep = () => ({decision: 'DENY'})}) {
    this.#store = storage;
    this.#principals = copy(principals);
    this.#clock = clock;
    this.#evidence = evidence;
    this.#verifyEvent = verifyEvent;
    this.#verifyReconciliation = verifyReconciliation;
    this.#pep = pep;
  }
  session(identity) {
    const principal = this.#principals[identity];
    requireState(principal, 'IDENTITY_UNKNOWN');
    const session = Object.freeze({identity_id: identity, role: principal.role});
    shape('actor-ref', base('actor-ref', {actor: session}));
    this.#sessions.add(session);
    return session;
  }
  #now() {
    const now = this.#clock();
    requireState(typeof now === 'string' && new Date(now).toISOString() === now, 'CLOCK_INVALID');
    return now;
  }
  #access(session, projectId, roles) {
    requireState(this.#sessions.has(session), 'SESSION_UNTRUSTED');
    id(projectId, 'prj');
    requireState(this.#principals[session.identity_id].projects.includes(projectId), 'SCOPE_DENIED');
    if (roles) requireState(roles.includes(session.role), 'ROLE_DENIED');
  }
  #project(db, projectId) {
    requireState(db.projects[projectId], 'PROJECT_MISSING');
    return db.projects[projectId];
  }
  #task(project, scope, control = false) {
    shape('scope-ids', base('scope-ids', {scope}));
    requireState(project.id === scope.project_id, 'SCOPE_DENIED');
    const task = project.tasks[scope.task_id];
    requireState(task, 'TASK_MISSING');
    if (control) requireState(task.control_operation_id === scope.operation_id, 'OPERATION_SCOPE_MISMATCH');
    return task;
  }
  #liveLease(task, session, token, now) {
    const lease = task.lease;
    requireState(!task.restore_pending, 'RESTORE_RECOVERY_REQUIRED');
    requireState(lease && token && lease.holder === session.identity_id && lease.expires_at > now
      && token.lease_epoch === lease.lease_epoch && token.fence === lease.fence, 'STALE_LEASE_OR_FENCE');
  }
  #context(project, task, session, scope, overrides = {}) {
    return createValidationContext({
      now: this.#now(), principals: this.#principals, authenticated_identity_id: session.identity_id,
      project_id: project.id, task_id: scope.task_id, operation: {id: scope.operation_id, ...project.operations[scope.operation_id]?.binding},
      epochs: project.epochs, spec: task?.spec, revision: task?.revision ?? project.revision,
      state: task?.state, lease_epoch: task?.lease_epoch, fence: task?.fence,
      resume_state: task?.resume_state, cancel_requested: task?.cancel_requested,
      stream_id: project.stream_id, last_sequence: project.sequence, ...overrides
    });
  }
  #validate(contract, dto, project, task, session, overrides) {
    requireState(dto.actor?.identity_id === session.identity_id, 'ACTOR_CONTEXT_MISMATCH');
    const result = validate(contract, dto, this.#context(project, task, session, dto.scope, overrides));
    requireState(result.ok, 'CONTRACT_REJECTED', result.errors);
  }
  #binding(project, task) {
    return {mode: 'E0', scope: controlScope(project, task), spec: task.spec, epochs: project.epochs,
      revision: task.revision, fence: task.fence, config_revision: project.config_revision,
      operations_hash: digest(opsFor(project, task))};
  }
  #guards(project, task,db) {
    const binding = this.#binding(project, task);
    const guards = copy(this.#evidence(copy(binding)));
    if(project.specs[`${task.spec.spec_id}:${task.spec.revision}`]?.content.dialect==='MASTER01_LITERAL_TEXT_V1'){
      for(const kind of ['local_qa','examiner_qa','auditor_qa','integration_qa','persisted','independent_readback'])delete guards[kind];
      Object.assign(guards,literalCompletionGuards(db,project,task,binding));
    }
    for (const ref of Object.values(guards)) requireState(hashPattern.test(ref), 'EVIDENCE_PORT_INVALID');
    // These guards MUST be derived from authoritative state, never caller/QA assertions.
    delete guards.deps_complete;
    delete guards.project_ready;
    delete guards.checkpoint;
    delete guards.outbox;
    delete guards.effects_reconciled;
    if (task.dependencies.every(dep => project.tasks[dep]?.state === 'COMPLETE' && !project.tasks[dep].acceptance_stale)) guards.deps_complete = digest({deps: task.dependencies, binding});
    if (project.status === 'READY' && project.qa02) guards.project_ready = project.qa02;
    if (!opsFor(project, task).some(unresolved)) guards.effects_reconciled = digest({reconciled: true, binding});
    if (task.checkpoint) {
      const checkpoint = project.checkpoints[task.checkpoint];
      if (checkpoint?.revision === task.revision && checkpoint.fence === task.fence
        && digest(checkpoint.epochs) === digest(project.epochs) && digest(checkpoint.spec) === digest(task.spec)) {
        guards.checkpoint = task.checkpoint;
        guards.outbox = digest(this.#finalBody(project, task));
      }
    }
    return guards;
  }
  #finalBody(project, task) {
    return {kind: 'final-report', project_id: project.id, task_id: task.id,
      revision: increment(task.revision), spec: task.spec, checkpoint: task.checkpoint};
  }
  #change(project, task, dto, session, guards) {
    this.#liveLease(task, session, dto, this.#now());
    this.#validate('state-transition', dto, project, task, session, {guards});
    requireState(!['COMPLETE', 'FAILED', 'CANCELLED'].includes(dto.to_state) || !opsFor(project, task).some(unresolved), 'EFFECTS_UNRESOLVED');
    if (dto.to_state === 'RUNNING') requireState(guards.deps_complete && guards.project_ready, 'START_GUARD_MISSING');
    if (dto.to_state === 'READY' || dto.to_state === 'RUNNING') requireState(project.status === 'READY', 'PROJECT_NOT_READY');
    if (waiting.includes(dto.to_state) && !waiting.includes(task.state)) task.resume_state = task.state;
    const was = task.state;
    task.state = dto.to_state;
    task.revision = increment(task.revision);
    if (active.includes(task.state)) task.resume_state = null;
    if (dto.to_state === 'CANCELLING') task.cancel_requested = true;
    project.transitions.push(copy(dto));
    appendEvent(project, {scope: dto.scope, actor: session, spec: task.spec, revision: dto.expected_revision,
      type: 'task.transitioned', payload: {from_state: was, to_state: task.state, revision: task.revision,
        lease_epoch: task.lease_epoch, fence: task.fence, config_revision: task.config_revision, reason: dto.reason},
      now: this.#now(), eventId: dto.event_id, causation: dto.causation_id});
    return task;
  }
  #dto(project, task, session, to, eventId, extras = {}) {
    return base('state-transition', {
      request_id: `req_svc_${increment(project.sequence)}`, correlation_id: `corr_svc_${increment(project.sequence)}`,
      causation_id: null, actor: session, scope: controlScope(project, task), epochs: project.epochs,
      spec: task.spec, created_at: this.#now(), expected_revision: task.revision, event_id: eventId,
      from_state: task.state, to_state: to, lease_epoch: task.lease_epoch, fence: task.fence,
      resume_state: task.resume_state, reason: 'E0 supervised state change', guard_refs: [],
      owner_action_id: null, subscription_id: null, ...extras
    });
  }
  #once(project, key, payload, operation) {
    text(key);
    const hash = digest(payload);
    const previous = project.idempotency[key];
    if (previous) {
      requireState(previous.hash === hash, 'IDEMPOTENCY_CONFLICT');
      return previous.result;
    }
    const result = copy(operation());
    project.idempotency[key] = {hash, result};
    return result;
  }
  createProject(session, input, key) {
    input = jsonCopy(input);
    this.#access(session, input.project_id, ['OWNER', 'PROJECT_FACTORY']);
    canonicalize(input);
    id(input.config_owner, 'act'); text(input.name); text(key);
    requireState(Object.keys(input).sort().join(',') === 'config,config_owner,name,project_id', 'PROJECT_INPUT_INVALID');
    requireState(this.#principals[input.config_owner]?.projects.includes(input.project_id)
      && ['OWNER','PROJECT_FACTORY'].includes(this.#principals[input.config_owner].role), 'CONFIG_OWNER_INVALID');
    return this.#store.transaction(db => {
      const existing = db.projects[input.project_id];
      if (existing) {
        requireState(existing.creation_hash === digest(input), 'PROJECT_CREATION_CONFLICT');
        return this.#once(existing, `create:${key}`, input, () => this.#projectView(existing));
      }
      const project = newProject(input, {policy: 1, auth: 1, stop: 0, owner: 1});
      project.creation_hash = digest(input);
      db.projects[project.id] = project;
      return this.#once(project, `create:${key}`, input, () => this.#projectView(project));
    });
  }
  #projectView(project) {
    return {id: project.id, name: project.name, status: project.status, revision: project.revision,
      config_owner: project.config_owner, config_revision: project.config_revision, provision: project.provision,
      qa02: project.qa02, epochs: project.epochs};
  }
  provision(session, projectId, expectedRevision, qa02 = null) {
    this.#access(session, projectId, ['OWNER', 'PROJECT_FACTORY']);
    return this.#store.transaction(db => {
      const project = this.#project(db, projectId); cas(project, expectedRevision);
      provisionCanary(project);
      if (qa02 !== null) {
        const binding = {mode: 'E0', kind: 'QA02', project_id: projectId, config_owner: project.config_owner,
          config_revision: project.config_revision, config_hash: project.configs[project.config_revision].hash, epochs: project.epochs};
        requireState(this.#evidence(copy(binding)).qa02 === qa02 && hashPattern.test(qa02), 'QA02_UNVERIFIED');
        project.qa02 = qa02; project.status = 'READY'; project.provision.phase = 'READY';
      }
      project.revision = increment(project.revision);
      return this.#projectView(project);
    });
  }
  compensate(session, projectId, expectedRevision) {
    this.#access(session, projectId, ['OWNER', 'PROJECT_FACTORY']);
    return this.#store.transaction(db => {
      const project = this.#project(db, projectId); cas(project, expectedRevision);
      compensateCanary(project); project.revision = increment(project.revision);
      return this.#projectView(project);
    });
  }
  reviseConfig(session, projectId, expectedRevision, content) {
    content = jsonCopy(content);
    this.#access(session, projectId, ['OWNER', 'PROJECT_FACTORY']); canonicalize(content);
    return this.#store.transaction(db => {
      const project = this.#project(db, projectId); cas(project, expectedRevision);
      requireState(!Object.values(project.tasks).some(task => !terminal(task.state)), 'ACTIVE_TASKS_CONFIG_PINNED');
      project.config_revision = increment(project.config_revision);
      project.configs[project.config_revision] = {hash: digest(content), content: copy(content)};
      project.qa02 = null; project.status = 'PROVISIONING'; project.provision.phase = 'RESOURCES_CREATED';
      project.revision = increment(project.revision);
      return this.#projectView(project);
    });
  }
  storeSpec(session, dto, content) {
    shape('spec-revision', dto); dto = copy(dto); content = jsonCopy(content);
    this.#access(session, dto.scope?.project_id, ['OWNER']); canonicalize(content);
    return this.#store.transaction(db => {
      const project = this.#project(db, dto.scope.project_id);
      const existing = project.specs[`${dto.spec.spec_id}:${dto.spec.revision}`];
      if (existing) {
        requireState(digest(existing) === digest({dto, content}), 'IMMUTABLE_SPEC_REVISION');
        return existing;
      }
      this.#validate('spec-revision', dto, project, null, session, {spec: dto.spec});
      requireState(dto.status === 'APPROVED' && digest(content) === dto.spec.content_hash, 'SPEC_CONTENT_MISMATCH');
      const key = `${dto.spec.spec_id}:${dto.spec.revision}`;
      const previous = project.specs[key];
      if (previous) {
        requireState(digest(previous) === digest({dto, content}), 'IMMUTABLE_SPEC_REVISION');
        return previous;
      }
      const revisions = Object.values(project.specs).filter(item => item.dto.spec.spec_id === dto.spec.spec_id);
      const latest = revisions.sort((a, b) => b.dto.spec.revision - a.dto.spec.revision)[0];
      if (latest) requireState(validateSpecSuccessor(latest.dto, dto).ok, 'SPEC_SUCCESSOR_INVALID');
      else requireState(dto.spec.revision === 1 && dto.supersedes === null, 'SPEC_SUCCESSOR_INVALID');
      project.specs[key] = copy({dto, content});
      // Immutable old acceptance remains; current-spec visibility is explicitly stale.
      for (const task of Object.values(project.tasks)) if (task.spec.spec_id === dto.spec.spec_id) task.acceptance_stale = true;
      project.revision = increment(project.revision);
      return project.specs[key];
    });
  }
  createTask(session, input, key) {
    input = jsonCopy(input); text(key);
    this.#access(session, input.scope?.project_id, ['OWNER', 'SUPERVISOR']);
    canonicalize(input); shape('scope-ids', base('scope-ids', {scope: input.scope})); text(input.name);
    requireState(Array.isArray(input.dependencies) && new Set(input.dependencies).size === input.dependencies.length, 'DEPENDENCIES_INVALID');
    input.dependencies.forEach(dep => id(dep, 'task'));
    return this.#store.transaction(db => {
      const project = this.#project(db, input.scope.project_id);
      return this.#once(project, `task:${key}`, input, () => {
        requireState(!project.tasks[input.scope.task_id], 'TASK_EXISTS');
        requireState(!project.operations[input.scope.operation_id] && !Object.values(project.tasks)
          .some(task => task.control_operation_id === input.scope.operation_id), 'OPERATION_EXISTS');
        const stored = project.specs[`${input.spec.spec_id}:${input.spec.revision}`];
        requireState(stored && digest(stored.dto.spec) === digest(input.spec), 'SPEC_MISSING');
        requireState(!Object.values(project.specs).some(item => item.dto.spec.spec_id === input.spec.spec_id && item.dto.spec.revision > input.spec.revision), 'SPEC_SUPERSEDED');
        if (input.supersedes) requireState(project.tasks[input.supersedes] && terminal(project.tasks[input.supersedes].state), 'SUCCESSOR_INVALID');
        const task = {id: input.scope.task_id, project_id: project.id, name: input.name,
          control_operation_id: input.scope.operation_id, spec: copy(input.spec), config_revision: project.config_revision,
          dependencies: copy(input.dependencies), state: 'DRAFT', revision: 0, lease: null, lease_epoch: 0, fence: 0,
          cancel_requested: false, resume_state: null, wait_subscription: null, checkpoint: null, acceptance_stale: false,
          supersedes: input.supersedes ?? null, rework_count: 0, restore_pending: false};
        project.tasks[task.id] = task; validateDag(project.tasks);
        return task;
      });
    });
  }
  setDependencies(session, scope, expectedRevision, dependencies) {
    scope = jsonCopy(scope); dependencies = jsonCopy(dependencies);
    this.#access(session, scope.project_id, ['SUPERVISOR']);
    requireState(Array.isArray(dependencies) && new Set(dependencies).size === dependencies.length, 'DEPENDENCIES_INVALID');
    dependencies.forEach(dep => id(dep, 'task'));
    return this.#store.transaction(db => {
      const project = this.#project(db, scope.project_id), task = this.#task(project, scope, true);
      cas(task, expectedRevision); requireState(task.state === 'DRAFT', 'DAG_FROZEN');
      task.dependencies = copy(dependencies); validateDag(project.tasks);
      task.revision = increment(task.revision); return task;
    });
  }
  acquireLease(session, scope, expectedRevision, ttlMs = 10000) {
    scope = jsonCopy(scope);
    this.#access(session, scope.project_id, ['SUPERVISOR']);
    requireState(Number.isSafeInteger(ttlMs) && ttlMs > 0 && ttlMs <= 60000, 'LEASE_TTL_INVALID');
    return this.#store.transaction(db => {
      const project = this.#project(db, scope.project_id), task = this.#task(project, scope, true), now = this.#now();
      cas(task, expectedRevision); requireState(!terminal(task.state), 'TERMINAL_IMMUTABLE');
      requireState(!task.restore_pending, 'RESTORE_RECOVERY_REQUIRED');
      requireState(!task.lease || task.lease.expires_at <= now, 'LEASE_BUSY');
      task.lease_epoch = increment(task.lease_epoch); task.fence = increment(task.fence);
      task.lease = {holder: session.identity_id, lease_epoch: task.lease_epoch, fence: task.fence,
        expires_at: new Date(Date.parse(now) + ttlMs).toISOString()};
      task.revision = increment(task.revision); return task;
    });
  }
  getTransitionContext(session, scope) {
    this.#access(session, scope.project_id);
    return this.#store.read(db => {
      const project = this.#project(db, scope.project_id), task = this.#task(project, scope, true);
      return {task, guards: this.#guards(project, task,db), epochs: project.epochs,binding:this.#binding(project,task)};
    });
  }
  getTaskBinding(session,scope){
    this.#access(session,scope.project_id);return this.#store.read(db=>{const p=this.#project(db,scope.project_id),t=this.#task(p,scope,true);return this.#binding(p,t);});
  }
  transition(session, dto) {
    this.#access(session, dto.scope?.project_id, ['SUPERVISOR']); shape('state-transition', dto);
    dto = copy(dto);
    requireState(!['WAITING_FOR_EVENT', 'WAITING_FOR_OWNER', 'CANCELLING', 'CANCELLED'].includes(dto.to_state), 'USE_ATOMIC_COMMAND');
    return this.#store.transaction(db => {
      const project = this.#project(db, dto.scope.project_id), task = this.#task(project, dto.scope, true);
      return this.#once(project, `transition:${dto.event_id}`, dto, () => {
        requireState(!waiting.includes(task.state), 'USE_RESUME_COMMAND');
        requireState(!task.acceptance_stale, 'SPEC_SUPERSEDED');
        const guards = this.#guards(project, task,db);
        if (dto.to_state === 'REWORK') {
          requireState(task.rework_count < 1, 'REWORK_LIMIT');
          task.rework_count = increment(task.rework_count);
        }
        this.#change(project, task, dto, session, guards);
        if (dto.to_state === 'COMPLETE') enqueue(project, `final:${task.id}:${task.revision}`, this.#finalBody(project, {...task, revision: dto.expected_revision}));
        return task;
      });
    });
  }
  checkpoint(session, scope, expectedRevision, lease) {
    scope = jsonCopy(scope); lease = jsonCopy(lease);
    this.#access(session, scope.project_id, ['SUPERVISOR']);
    return this.#store.transaction(db => {
      const project = this.#project(db, scope.project_id), task = this.#task(project, scope, true);
      cas(task, expectedRevision); this.#liveLease(task, session, lease, this.#now());
      requireState(task.state === 'PERSISTING' && !task.cancel_requested && !opsFor(project, task).some(unresolved), 'CHECKPOINT_UNSAFE');
      const guards = this.#guards(project, task,db);
      requireState(guards.persisted && guards.independent_readback, 'READBACK_REQUIRED');
      task.revision = increment(task.revision);
      const snapshot = {...this.#binding(project, task), state: task.state, rework_count: task.rework_count,
        persisted: guards.persisted, independent_readback: guards.independent_readback};
      task.checkpoint = digest(snapshot); project.checkpoints[task.checkpoint] = snapshot;
      return {task, checkpoint_ref: task.checkpoint, outbox_ref: digest(this.#finalBody(project, task))};
    });
  }
  cancel(session, scope, expectedRevision, key) {
    scope = jsonCopy(scope); text(key);
    this.#access(session, scope.project_id, ['OWNER', 'SUPERVISOR']);
    return this.#store.transaction(db => {
      const project = this.#project(db, scope.project_id), task = this.#task(project, scope, true);
      return this.#once(project, `cancel:${key}`, {scope, expectedRevision}, () => {
        cas(task, expectedRevision); requireState(!terminal(task.state), 'TERMINAL_IMMUTABLE');
        const fromState = task.state;
        task.cancel_requested = true; task.state = 'CANCELLING'; task.resume_state = null;
        task.fence = increment(task.fence); task.lease_epoch = increment(task.lease_epoch); task.lease = null;
        task.revision = increment(task.revision);
        // Global/project stop epoch belongs to D-02. Cancel invalidates this task's fence.
        for (const sub of Object.values(project.subscriptions)) if (sub.dto.scope.task_id === task.id && sub.status === 'ACTIVE') sub.status = 'CANCELLED';
        for (const sub of Object.values(project.subscriptions)) if (sub.dto.scope.task_id === task.id && sub.status === 'SIGNALLED') {
          sub.status = 'CANCELLED';
          const wake = project.outbox[`wake:${sub.dto.subscription_id}`];
          if (wake) wake.status = 'CANCELLED';
        }
        for (const op of opsFor(project, task)) if (op.status === 'INTENT') op.status = 'ABORTED';
        appendEvent(project, {scope, actor: session, spec: task.spec, revision: expectedRevision,
          type: 'task.transitioned', payload: {from_state: fromState, to_state: 'CANCELLING', cancel_requested: true,
            revision: task.revision, lease_epoch: task.lease_epoch, fence: task.fence,
            config_revision: task.config_revision, reason: 'STICKY_CANCEL_REQUESTED'}, now: this.#now()});
        return task;
      });
    });
  }
  finishCancel(session, scope, expectedRevision, lease) {
    scope = jsonCopy(scope); lease = jsonCopy(lease);
    this.#access(session, scope.project_id, ['SUPERVISOR']);
    return this.#store.transaction(db => {
      const project = this.#project(db, scope.project_id), task = this.#task(project, scope, true);
      cas(task, expectedRevision); requireState(task.cancel_requested && task.state === 'CANCELLING', 'CANCEL_NOT_PENDING');
      const guards = this.#guards(project, task,db);
      const dto = this.#dto(project, task, session, 'CANCELLED', `evt_cancelled_${increment(project.sequence)}`,
        {lease_epoch: lease.lease_epoch, fence: lease.fence, guard_refs: Object.values(guards)});
      return this.#change(project, task, dto, session, guards);
    });
  }
  // No external provider/tool execution is possible, even with an injected ALLOW mock.
  requestEffect(session, scope, lease) {
    this.#access(session, scope.project_id, ['SUPERVISOR']);
    return this.#store.read(db => {
      const project = this.#project(db, scope.project_id), task = this.#task(project, scope);
      this.#liveLease(task, session, lease, this.#now());
      const op = project.operations[scope.operation_id];
      requireState(op && op.scope.task_id === task.id, 'OPERATION_MISSING');
      requireState(!task.cancel_requested && task.state === 'RUNNING' && !task.acceptance_stale, 'EFFECT_STATE_DENIED');
      requireState(op.status === 'INTENT' || (op.status === 'RECONCILED' && op.retry_authorized), 'RECONCILIATION_REQUIRED');
      requireState(digest(op.epochs) === digest(project.epochs) && digest(op.spec) === digest(task.spec), 'OPERATION_VERSION_MISMATCH');
      const boundary = {schema_version: 'd03-pep-proposal-1', boundary: 'effect.dispatch',
        actor: session, scope, spec: task.spec, epochs: project.epochs, expected_revision: task.revision,
        lease_epoch: task.lease_epoch, fence: task.fence, action: op.action, resource: op.resource,
        payload_hash: op.binding.payload_hash, tool_id: op.binding.tool_id, tool_digest: op.binding.tool_digest,
        approval_ref: op.approval_ref, operation_status: op.status, mode: 'E0'};
      const observed = this.#pep(copy(boundary));
      return {decision: 'DENY', reason: 'E0_NO_TRUSTED_D02_OR_ACTUAL_EFFECT_ADAPTER', boundary,
        observed_decision: observed?.decision === 'ALLOW' ? 'ALLOW_IGNORED' : 'DENY'};
    });
  }
  intent(session, input, expectedRevision, lease, key) {
    input = jsonCopy(input); lease = jsonCopy(lease); text(key);
    this.#access(session, input.scope?.project_id, ['SUPERVISOR']); canonicalize(input);
    shape('scope-ids', base('scope-ids', {scope: input.scope}));
    requireState(['READ_ONLY', 'IDEMPOTENT_WRITE', 'NON_IDEMPOTENT'].includes(input.effect_class), 'EFFECT_CLASS_INVALID');
    id(input.tool_id, 'tool'); requireState(hashPattern.test(input.tool_digest), 'TOOL_DIGEST_INVALID');
    text(input.action); text(input.resource);
    return this.#store.transaction(db => {
      const project = this.#project(db, input.scope.project_id), task = this.#task(project, input.scope);
      return this.#once(project, `intent:${key}`, input, () => {
        cas(task, expectedRevision); this.#liveLease(task, session, lease, this.#now());
        requireState(task.state === 'RUNNING' && !task.cancel_requested && !task.acceptance_stale, 'EFFECT_STATE_DENIED');
        requireState(!project.operations[input.scope.operation_id], 'OPERATION_EXISTS');
        requireState(!Object.values(project.tasks).some(other => other.control_operation_id === input.scope.operation_id), 'OPERATION_EXISTS');
        requireState(!opsFor(project, task).some(op => op.action === input.action && op.resource === input.resource
          && op.binding.payload_hash === digest(input.payload) && op.binding.tool_id === input.tool_id
          && op.binding.tool_digest === input.tool_digest), 'LOGICAL_OPERATION_EXISTS');
        requireState(!opsFor(project, task).some(unresolved), 'RECONCILIATION_REQUIRED');
        const operation = {scope: copy(input.scope), spec: copy(task.spec), epochs: copy(project.epochs),
          binding: {payload_hash: digest(input.payload), tool_id: input.tool_id, tool_digest: input.tool_digest},
          effect_class: input.effect_class, action: input.action, resource: input.resource,
          approval_ref: input.approval_ref ?? null, status: 'INTENT', attempts: 0, max_attempts: 2,
          retry_authorized: false, retained_reservation: false, receipt: null};
        project.operations[input.scope.operation_id] = operation;
        task.revision = increment(task.revision); return operation;
      });
    });
  }
  simulateDispatch(session, scope, expectedRevision, lease) {
    scope = jsonCopy(scope); lease = jsonCopy(lease);
    this.#access(session, scope.project_id, ['SUPERVISOR']);
    return this.#store.transaction(db => {
      const project = this.#project(db, scope.project_id), task = this.#task(project, scope);
      cas(task, expectedRevision); this.#liveLease(task, session, lease, this.#now());
      requireState(task.state === 'RUNNING' && !task.cancel_requested && !task.acceptance_stale, 'EFFECT_STATE_DENIED');
      const op = project.operations[scope.operation_id];
      requireState(op && op.scope.task_id === task.id, 'OPERATION_MISSING');
      requireState(digest(op.epochs) === digest(project.epochs) && digest(op.spec) === digest(task.spec), 'OPERATION_VERSION_MISMATCH');
      requireState(op.status === 'INTENT' || (op.status === 'RECONCILED' && op.retry_authorized), 'RECONCILIATION_REQUIRED');
      requireState(op.attempts < op.max_attempts, 'RETRY_LIMIT');
      op.attempts = increment(op.attempts); op.status = 'DISPATCHED'; op.retry_authorized = false;
      op.retained_reservation = true; task.revision = increment(task.revision);
      return {operation_id: scope.operation_id, payload_hash: op.binding.payload_hash, mode: 'CANARY_ONLY', attempts: op.attempts};
    });
  }
  recordToolReceipt(session, dto) {
    this.#access(session, dto.scope?.project_id, ['STATE_SERVICE']); shape('tool-receipt', dto);
    dto = copy(dto);
    return this.#store.transaction(db => {
      const project = this.#project(db, dto.scope.project_id), task = this.#task(project, dto.scope);
      return this.#once(project, `receipt:${dto.receipt_id}`, dto, () => {
        this.#validate('tool-receipt', dto, project, task, session);
        const op = project.operations[dto.scope.operation_id];
        requireState(op && op.scope.task_id === task.id && op.effect_class === dto.effect_class, 'OPERATION_BINDING_MISMATCH');
        requireState(op.status === 'DISPATCHED' && !terminal(task.state), 'RECONCILIATION_REQUIRED');
        op.receipt = copy(dto); op.status = dto.outcome;
        op.retained_reservation = dto.outcome === 'OUTCOME_UNKNOWN';
        // ABORTED is ambiguous unless independent reconciliation proves NOT_APPLIED.
        if (dto.outcome === 'ABORTED') { op.status = 'OUTCOME_UNKNOWN'; op.retained_reservation = true; }
        if (op.status === 'OUTCOME_UNKNOWN' && !task.cancel_requested) { task.resume_state = task.state; task.state = 'RECONCILING'; }
        task.revision = increment(task.revision);
        appendEvent(project, {scope: dto.scope, actor: session, spec: task.spec, revision: dto.expected_revision,
          type: 'operation.receipted', payload: {status: op.status, operation_id: dto.scope.operation_id}, now: this.#now()});
        return op;
      });
    });
  }
  recordLocalToolReceipt(session,dto,completion){
    this.#access(session,dto.scope?.project_id,['STATE_SERVICE']);shape('tool-receipt',dto);
    requireState(isReviewedLocalCompletion(completion),'REAL_D09_LOCAL_COMPLETION_REQUIRED');dto=copy(dto);
    return this.#store.transaction(db=>{
      const project=this.#project(db,dto.scope.project_id),task=this.#task(project,dto.scope),op=project.operations[dto.scope.operation_id];
      requireState(op?.status==='INTENT'&&task.state==='RUNNING'&&!task.cancel_requested&&!task.restore_pending&&!task.acceptance_stale&&task.lease?.expires_at>this.#now(),'LOCAL_OPERATION_STATE');
      this.#validate('tool-receipt',dto,project,task,session);
      requireState(completion.status==='SUCCEEDED'&&completion.accounting_status==='SETTLED'&&completion.actual_micros==='0'&&completion.committed===true&&completion.local_execution_authorized===true&&completion.lineage_enforced===true&&completion.physical_decision==='DENY'&&completion.dispatch_authorized===false&&completion.project_id===dto.scope.project_id&&completion.task_id===dto.scope.task_id&&completion.operation_id===dto.scope.operation_id&&completion.payload_hash===op.binding.payload_hash&&completion.spec_hash===digest(task.spec)&&digest(completion.epochs)===digest(project.epochs)&&dto.outcome==='CONFIRMED'&&dto.effect_class===op.effect_class,'LOCAL_D09_RECEIPT_BINDING');
      const persisted=Object.values(project.catalogue?.artifacts??{}).find(a=>a.status==='PERSISTED'&&digest(a.record.reference)===digest(dto.output));
      requireState(persisted&&persisted.record.manifest.files.length===1&&dto.external_receipt===digest(completion)&&dto.tool_id===op.binding.tool_id&&dto.tool_digest===op.binding.tool_digest&&completion.task_revision===task.revision&&completion.task_fence===task.fence,'LOCAL_D09_ARTIFACT_BINDING');
      // tool-receipt.output references the D07 manifest descriptor. Its bytes
      // must match full_output_bytes (the unchanged shared contract). The real
      // file's separate path/length/hash remain bound by the D09 output digest.
      const f=persisted.record.manifest.files[0];requireState(completion.output_hash===digest({path:f.path,bytes:f.bytes,sha256:f.content_hash})&&dto.full_output_bytes===persisted.record.reference.bytes&&!dto.truncated&&!dto.retry_allowed,'LOCAL_D09_EXACT_OUTPUT');
      op.receipt=copy(dto);op.status='CONFIRMED';op.attempts++;op.retained_reservation=false;op.d09_local_ack_hash=digest(completion);task.revision=increment(task.revision);
      appendEvent(project,{scope:dto.scope,actor:session,spec:task.spec,revision:dto.expected_revision,type:'operation.receipted',payload:{status:op.status,operation_id:dto.scope.operation_id,d09_ack_hash:op.d09_local_ack_hash},now:this.#now()});return op;
    });
  }
  reconcile(session, scope, expectedRevision, resolution) {
    scope = jsonCopy(scope); resolution = jsonCopy(resolution);
    this.#access(session, scope.project_id, ['STATE_SERVICE']); canonicalize(resolution);
    return this.#store.transaction(db => {
      const project = this.#project(db, scope.project_id), task = this.#task(project, scope);
      cas(task, expectedRevision); const op = project.operations[scope.operation_id];
      requireState(op && op.scope.task_id === task.id && ['OUTCOME_UNKNOWN', 'DISPATCHED', 'INTENT'].includes(op.status), 'RECONCILIATION_NOT_PENDING');
      requireState(['APPLIED', 'NOT_APPLIED'].includes(resolution.outcome), 'RESOLUTION_INVALID');
      const binding = {scope, spec: task.spec, epochs: project.epochs, revision: task.revision,
        payload_hash: op.binding.payload_hash, outcome: resolution.outcome};
      requireState(this.#verifyReconciliation(copy(binding), copy(resolution)) === true, 'RECONCILIATION_UNVERIFIED');
      op.status = 'RECONCILED'; op.resolution = copy(resolution); op.retained_reservation = false;
      op.retry_authorized = !task.cancel_requested && resolution.outcome === 'NOT_APPLIED'
        && op.effect_class !== 'NON_IDEMPOTENT' && op.attempts < op.max_attempts;
      task.revision = increment(task.revision);
      appendEvent(project, {scope, actor: session, spec: task.spec, revision: expectedRevision,
        type: 'operation.receipted', payload: {status: op.status, outcome: resolution.outcome, operation_id: scope.operation_id}, now: this.#now()});
      return op;
    });
  }
  recover(session, projectId) {
    this.#access(session, projectId, ['STATE_SERVICE']);
    return this.#store.transaction(db => {
      const project = this.#project(db, projectId), now = this.#now(), recovered = [];
      if (project.status === 'PROVISIONING') project.provision.recovery_required = true;
      for (const task of Object.values(project.tasks)) {
        if (terminal(task.state) || (!task.restore_pending && task.lease && task.lease.expires_at > now)) continue;
        const freshIntent = opsFor(project, task).some(op => ['INTENT', 'DISPATCHED'].includes(op.status));
        if (!task.restore_pending && (task.state === 'DRAFT'
          || (!task.lease && [...waiting, 'CANCELLING'].includes(task.state) && !freshIntent))) continue;
        const fromState = task.state;
        task.lease = null; task.fence = increment(task.fence); task.lease_epoch = increment(task.lease_epoch);
        task.restore_pending = false;
        for (const op of opsFor(project, task)) if (['INTENT', 'DISPATCHED'].includes(op.status)) {
          op.status = 'OUTCOME_UNKNOWN'; op.retained_reservation = true;
        }
        const preserveWait = ['DRAFT', 'WAITING_FOR_OWNER', 'WAITING_FOR_EVENT', 'BLOCKED'].includes(task.state)
          && !opsFor(project, task).some(unresolved) && !task.cancel_requested;
        task.resume_state = task.cancel_requested ? null : (task.resume_state ?? task.state);
        if (!preserveWait) task.state = task.cancel_requested ? 'CANCELLING' : 'RECONCILING';
        task.revision = increment(task.revision); recovered.push(task.id);
        appendEvent(project, {scope: controlScope(project, task), actor: session, spec: task.spec, revision: task.revision - 1,
          type: 'task.transitioned', payload: {from_state: fromState, to_state: task.state, revision: task.revision,
            lease_epoch: task.lease_epoch, fence: task.fence, config_revision: task.config_revision, reason: 'LEASE_LOST_RECOVERY'}, now});
      }
      return {recovered, provision: project.provision};
    });
  }
  resume(session, scope, expectedRevision, lease) {
    scope = jsonCopy(scope); lease = jsonCopy(lease);
    this.#access(session, scope.project_id, ['SUPERVISOR']);
    return this.#store.transaction(db => {
      const project = this.#project(db, scope.project_id), task = this.#task(project, scope, true);
      cas(task, expectedRevision); requireState(!task.cancel_requested && !task.acceptance_stale, 'RESUME_DENIED');
      requireState(!task.wait_subscription, 'WAIT_REQUIRES_VERIFIED_WAKE');
      requireState(['RECONCILING', 'BLOCKED'].includes(task.state) && active.includes(task.resume_state), 'RESUME_DENIED');
      requireState(!opsFor(project, task).some(unresolved), 'RECONCILIATION_REQUIRED');
      const guards = this.#guards(project, task,db);
      const dto = this.#dto(project, task, session, task.resume_state, `evt_resume_${increment(project.sequence)}`,
        {lease_epoch: lease.lease_epoch, fence: lease.fence, guard_refs: Object.values(guards)});
      return this.#change(project, task, dto, session, guards);
    });
  }
  recordAttemptReceipt(session, dto) {
    this.#access(session, dto.scope?.project_id, ['ROUTE_BROKER']); shape('attempt-receipt', dto);
    dto = copy(dto);
    return this.#store.transaction(db => {
      const project = this.#project(db, dto.scope.project_id), task = this.#task(project, dto.scope);
      return this.#once(project, `attempt:${dto.attempt_id}`, dto, () => {
        this.#validate('attempt-receipt', dto, project, task, session);
        const op = project.operations[dto.scope.operation_id];
        requireState(op && op.scope.task_id === task.id && op.status === 'DISPATCHED'
          && op.attempts === dto.attempt_number && !terminal(task.state), 'ATTEMPT_BINDING_MISMATCH');
        op.receipt = copy(dto);
        op.status = dto.status === 'RECEIVED' ? 'CONFIRMED' : 'OUTCOME_UNKNOWN';
        op.retained_reservation = dto.status !== 'RECEIVED';
        op.reservation_micros = dto.reservation_micros;
        if (op.status === 'OUTCOME_UNKNOWN' && !task.cancel_requested) { task.resume_state = task.state; task.state = 'RECONCILING'; }
        task.revision = increment(task.revision);
        appendEvent(project, {scope: dto.scope, actor: session, spec: task.spec, revision: dto.expected_revision,
          type: 'operation.receipted', payload: {status: op.status, operation_id: dto.scope.operation_id}, now: this.#now()});
        return op;
      });
    });
  }
  storeOwnerAction(session, dto) {
    this.#access(session, dto.scope?.project_id, ['OWNER', 'STATE_SERVICE']); shape('owner-action', dto);
    dto = copy(dto);
    return this.#store.transaction(db => {
      const project = this.#project(db, dto.scope.project_id), task = this.#task(project, dto.scope);
      return this.#once(project, `owner-action:${dto.request_id}`, dto, () => {
        this.#validate('owner-action', dto, project, task, session);
        requireState(!terminal(task.state), 'TERMINAL_IMMUTABLE');
        const previous = project.owner_actions[dto.owner_action_id];
        if (!previous) requireState(session.role === 'OWNER' && dto.status === 'OPEN' && dto.uses === 0, 'OWNER_ACTION_OPEN_REQUIRED');
        else {
          const allowed = {OPEN: ['SUBMITTED', 'EXPIRED', 'REVOKED'], SUBMITTED: ['VERIFYING', 'REJECTED', 'REVOKED'],
            VERIFYING: ['VERIFIED', 'REJECTED', 'REVOKED'], VERIFIED: ['REVOKED']};
          requireState(allowed[previous.dto.status]?.includes(dto.status) && previous.uses === 0, 'OWNER_ACTION_TRANSITION');
          for (const field of ['scope', 'spec', 'action', 'resource', 'payload_hash', 'expires_at', 'max_uses'])
            requireState(digest(previous.dto[field]) === digest(dto[field]), 'OWNER_ACTION_BINDING_MISMATCH');
          requireState(dto.uses === 0, 'OWNER_ACTION_USES_MANAGED');
        }
        if (['VERIFYING', 'VERIFIED'].includes(dto.status)) requireState(session.role === 'STATE_SERVICE', 'VERIFIER_REQUIRED');
        if (dto.status === 'VERIFIED') {
          const binding = {...this.#binding(project, task), kind: 'OWNER_ACTION', owner_action_id: dto.owner_action_id, payload_hash: dto.payload_hash};
          requireState(this.#evidence(copy(binding)).owner_verification === dto.verification_receipt, 'OWNER_VERIFICATION_REQUIRED');
        }
        project.owner_actions[dto.owner_action_id] = {dto: copy(dto), uses: 0};
        task.revision = increment(task.revision);
        appendEvent(project, {scope: dto.scope, actor: session, spec: task.spec, revision: dto.expected_revision,
          type: 'owner-action.updated', payload: {owner_action_id: dto.owner_action_id, status: dto.status}, now: this.#now()});
        this.#signal(project);
        return project.owner_actions[dto.owner_action_id];
      });
    });
  }
  #signal(project) {
    for (const sub of Object.values(project.subscriptions)) {
      const event = matchSubscription(project, sub, this.#now());
      if (event) {
        sub.status = 'SIGNALLED'; sub.event_id = event.event_id;
        enqueue(project, `wake:${sub.dto.subscription_id}`, {kind: 'wake', project_id: project.id,
          task_id: sub.dto.scope.task_id, subscription_id: sub.dto.subscription_id, event_id: event.event_id});
      }
    }
  }
  subscribe(session, dto, transition, ownerActionId = null) {
    this.#access(session, dto.scope?.project_id, ['SUPERVISOR']); shape('wait-subscription', dto); shape('state-transition', transition);
    dto = copy(dto); transition = copy(transition);
    return this.#store.transaction(db => {
      const project = this.#project(db, dto.scope.project_id), task = this.#task(project, dto.scope);
      return this.#once(project, `subscribe:${dto.subscription_id}`, {dto, transition, ownerActionId}, () => {
        this.#validate('wait-subscription', dto, project, task, session);
        requireState(digest(dto.scope) === digest(transition.scope) && dto.resume_state === task.state
          && transition.resume_state === task.state && transition.subscription_id === dto.subscription_id, 'SUBSCRIPTION_BINDING_MISMATCH');
        requireState(dto.deadline <= dto.cursor.expires_at, 'CURSOR_TOO_SHORT');
        requireState(!task.cancel_requested && !task.acceptance_stale && !terminal(task.state), 'SUBSCRIPTION_STATE_DENIED');
        requireState(!Object.values(project.subscriptions).some(sub => sub.dto.scope.task_id === task.id
          && ['ACTIVE', 'SIGNALLED'].includes(sub.status)), 'SUBSCRIPTION_EXISTS');
        if (dto.event_type === 'owner-action.updated') {
          const action = project.owner_actions[ownerActionId];
          requireState(action && action.dto.expires_at > this.#now() && action.uses === 0
            && !['EXPIRED', 'REVOKED', 'REJECTED'].includes(action.dto.status)
            && digest(action.dto.scope) === digest(dto.scope) && digest(action.dto.spec) === digest(dto.spec), 'OWNER_ACTION_UNUSABLE');
          requireState(transition.to_state === 'WAITING_FOR_OWNER' && transition.owner_action_id === ownerActionId, 'OWNER_ACTION_BINDING_MISMATCH');
        } else {
          requireState(project.operations[dto.scope.operation_id]?.scope.task_id === task.id, 'OPERATION_MISSING');
          requireState(transition.to_state === 'WAITING_FOR_EVENT' && ownerActionId === null, 'SUBSCRIPTION_BINDING_MISMATCH');
        }
        this.#change(project, task, transition, session, this.#guards(project, task,db));
        task.wait_subscription = dto.subscription_id;
        project.subscriptions[dto.subscription_id] = {dto: copy(dto), owner_action_id: ownerActionId,
          status: 'ACTIVE', event_id: null};
        enqueue(project, `waiting:${dto.subscription_id}`, {kind: 'waiting-report', scope: dto.scope, subscription_id: dto.subscription_id});
        this.#signal(project); // subscribe+scan occurs under the SAME serializable write
        return project.subscriptions[dto.subscription_id];
      });
    });
  }
  receiveEvent(session, dto, payload) {
    this.#access(session, dto.scope?.project_id, ['STATE_SERVICE']); shape('event-envelope', dto); canonicalize(payload);
    dto = copy(dto); payload = copy(payload);
    return this.#store.transaction(db => {
      const project = this.#project(db, dto.scope.project_id), task = this.#task(project, dto.scope);
      return this.#once(project, `inbox:${dto.event_id}`, {dto, payload}, () => {
        const receipt = this.#verifyEvent(copy(dto), copy(payload));
        requireState(receipt && typeof receipt.then !== 'function', 'EVENT_PRODUCER_UNVERIFIED');
        this.#validate('event-envelope', dto, project, task, session, {event_receipts: {[dto.event_id]: receipt}});
        requireState(receipt.body_hash === bodyHash(dto), 'EVENT_PRODUCER_UNVERIFIED');
        requireState(dto.sequence === increment(project.sequence), 'EVENT_SEQUENCE_MISMATCH');
        requireState(!project.events.some(event => event.event_id === dto.event_id), 'EVENT_ID_CONFLICT');
        requireState(digest(payload) === dto.payload_ref.content_hash
          && Buffer.byteLength(canonicalize(payload)) === dto.payload_ref.bytes, 'EVENT_PAYLOAD_MISMATCH');
        // An envelope is a notification of independently verified state, never an approval.
        if (dto.event_type === 'owner-action.updated') {
          const action = project.owner_actions[payload.owner_action_id];
          requireState(action && digest(action.dto.scope) === digest(dto.scope) && action.dto.status === payload.status, 'EVENT_STATE_UNVERIFIED');
        } else if (dto.event_type === 'operation.receipted') {
          const op = project.operations[dto.scope.operation_id];
          requireState(op && op.scope.task_id === task.id && op.status === payload.status, 'EVENT_STATE_UNVERIFIED');
        } else requireState(false, 'EXTERNAL_EVENT_TYPE_DENIED');
        project.sequence = dto.sequence; project.events.push(copy(dto));
        project.payloads[dto.payload_ref.content_hash] = copy(payload);
        project.inbox[dto.event_id] = {body_hash: bodyHash(dto), status: task.cancel_requested || terminal(task.state) ? 'LATE_IGNORED' : 'ACCEPTED'};
        enqueue(project, `event:${dto.sequence}`, {kind: 'event', event: dto});
        this.#signal(project); return project.inbox[dto.event_id];
      });
    });
  }
  wake(session, projectId, subscriptionId, expectedRevision, lease) {
    lease = jsonCopy(lease);
    this.#access(session, projectId, ['SUPERVISOR']); id(subscriptionId, 'sub');
    return this.#store.transaction(db => {
      const project = this.#project(db, projectId), sub = project.subscriptions[subscriptionId];
      requireState(sub, 'SUBSCRIPTION_MISSING');
      const task = this.#task(project, sub.dto.scope); cas(task, expectedRevision);
      requireState(!task.cancel_requested && !task.acceptance_stale && ['WAITING_FOR_EVENT', 'WAITING_FOR_OWNER'].includes(task.state), 'WAKE_DENIED');
      requireState(sub.status === 'SIGNALLED' && sub.dto.deadline > this.#now(), 'WAKE_NOT_READY');
      requireState(project.events.some(event => event.event_id === sub.event_id && event.expires_at > this.#now()), 'WAKE_EVENT_EXPIRED');
      requireState(digest(sub.dto.epochs) === digest(project.epochs) && digest(sub.dto.spec) === digest(task.spec), 'WAKE_VERSION_MISMATCH');
      if (sub.owner_action_id) {
        const action = project.owner_actions[sub.owner_action_id];
        requireState(action.dto.status === 'VERIFIED' && action.dto.expires_at > this.#now() && action.uses === 0, 'OWNER_ACTION_UNUSABLE');
        action.uses = 1;
      }
      const guards = this.#guards(project, task,db);
      const dto = this.#dto(project, task, session, sub.dto.resume_state, `evt_wake_${increment(project.sequence)}`,
        {lease_epoch: lease.lease_epoch, fence: lease.fence, scope: sub.dto.scope, resume_state: sub.dto.resume_state,
          guard_refs: Object.values(guards), causation_id: sub.event_id});
      this.#change(project, task, dto, session, guards);
      sub.status = 'CONSUMED'; task.wait_subscription = null;
      project.inbox[`consume:${subscriptionId}:${sub.event_id}`] = {status: 'CONSUMED', revision: task.revision};
      project.outbox[`wake:${subscriptionId}`].status = 'ACKNOWLEDGED';
      return task;
    });
  }
  expireSubscription(session, projectId, subscriptionId, expectedRevision) {
    this.#access(session, projectId, ['STATE_SERVICE']); id(subscriptionId, 'sub');
    return this.#store.transaction(db => {
      const project = this.#project(db, projectId), sub = project.subscriptions[subscriptionId];
      requireState(sub && ['ACTIVE', 'SIGNALLED'].includes(sub.status) && sub.dto.deadline <= this.#now(), 'SUBSCRIPTION_NOT_EXPIRED');
      const task = this.#task(project, sub.dto.scope); cas(task, expectedRevision);
      requireState(['WAITING_FOR_EVENT', 'WAITING_FOR_OWNER'].includes(task.state) && !task.cancel_requested, 'TIMEOUT_STATE_DENIED');
      const fromState = task.state;
      sub.status = 'EXPIRED'; task.state = 'BLOCKED'; task.revision = increment(task.revision);
      task.fence = increment(task.fence); task.lease_epoch = increment(task.lease_epoch); task.lease = null;
      appendEvent(project, {scope: sub.dto.scope, actor: session, spec: task.spec, revision: expectedRevision,
        type: 'task.transitioned', payload: {from_state: fromState, to_state: 'BLOCKED', revision: task.revision,
          lease_epoch: task.lease_epoch, fence: task.fence, config_revision: task.config_revision, reason: 'WAIT_DEADLINE'}, now: this.#now()});
      return task;
    });
  }
  syncEpochs(session, projectId, expectedRevision, epochs) {
    this.#access(session, projectId, ['STATE_SERVICE']); shape('epochs', base('epochs', {epochs}));
    epochs = copy(epochs);
    return this.#store.transaction(db => {
      const project = this.#project(db, projectId); cas(project, expectedRevision);
      requireState(Object.keys(epochs).every(key => epochs[key] >= project.epochs[key])
        && digest(epochs) !== digest(project.epochs), 'EPOCH_NOT_MONOTONIC');
      if (epochs.stop > project.epochs.stop) project.status = 'PAUSED';
      project.epochs = copy(epochs); project.revision = increment(project.revision);
      for (const sub of Object.values(project.subscriptions)) if (['ACTIVE', 'SIGNALLED'].includes(sub.status)) sub.status = 'REVOKED';
      for (const task of Object.values(project.tasks)) if (!terminal(task.state)) {
        const fromState = task.state;
        task.lease = null; task.fence = increment(task.fence); task.lease_epoch = increment(task.lease_epoch);
        task.revision = increment(task.revision);
        if (task.state !== 'DRAFT') {
          task.resume_state = task.cancel_requested ? null : (task.resume_state ?? task.state);
          task.state = task.cancel_requested ? 'CANCELLING' : 'RECONCILING';
        }
        for (const op of opsFor(project, task)) if (['DISPATCHED', 'INTENT'].includes(op.status)) {
          op.status = 'OUTCOME_UNKNOWN'; op.retained_reservation = true;
        }
        appendEvent(project, {scope: controlScope(project, task), actor: session, spec: task.spec, revision: task.revision - 1,
          type: 'task.transitioned', payload: {from_state: fromState, to_state: task.state, revision: task.revision,
            lease_epoch: task.lease_epoch, fence: task.fence, config_revision: task.config_revision, reason: 'CURRENT_EPOCH_CHANGED'}, now: this.#now()});
      }
      return this.#projectView(project);
    });
  }
  claimOutbox(session, projectId, key, ttlMs = 10000) {
    this.#access(session, projectId, ['STATE_SERVICE']);
    requireState(Number.isSafeInteger(ttlMs) && ttlMs > 0 && ttlMs <= 60000, 'LEASE_TTL_INVALID');
    return this.#store.transaction(db => {
      const project = this.#project(db, projectId), item = project.outbox[key], now = this.#now();
      requireState(item && !['ACKNOWLEDGED', 'CANCELLED'].includes(item.status), 'OUTBOX_UNAVAILABLE');
      requireState(!item.lease || item.lease.expires_at <= now, 'OUTBOX_LEASE_BUSY');
      item.delivery_fence = increment(item.delivery_fence); item.attempts = increment(item.attempts);
      item.lease = {holder: session.identity_id, expires_at: new Date(Date.parse(now) + ttlMs).toISOString()};
      item.status = 'SENT'; return item;
    });
  }
  ackOutbox(session, projectId, key, fence) {
    this.#access(session, projectId, ['STATE_SERVICE']);
    return this.#store.transaction(db => {
      const project = this.#project(db, projectId), item = project.outbox[key];
      requireState(item?.delivery_fence === fence && item.lease?.holder === session.identity_id
        && item.lease.expires_at > this.#now(), 'OUTBOX_STALE_FENCE');
      item.status = 'ACKNOWLEDGED'; return item;
    });
  }
  getProject(session, projectId) {
    this.#access(session, projectId);
    return this.#store.read(db => this.#projectView(this.#project(db, projectId)));
  }
  // OWNER02 additive sidecar uses the same D03 serial storage queue and genuine
  // sessions. DATA02 receives no reducer, storage writer or ACL replacement API.
  readCatalogue(session, scope) {
    scope=jsonCopy(scope);shape('scope-ids',base('scope-ids',{scope}));
    this.#access(session,scope.project_id);
    return this.#store.read(db=>({...catalogueView(db,scope,this.#principals,session),durable_binding:isPostgresStateStorage(this.#store)?'MASTER01_POSTGRES_D03':'NOT_BOUND'}));
  }
  prepareCatalogue(session, scope, input) {
    scope=jsonCopy(scope);input=jsonCopy(input);shape('scope-ids',base('scope-ids',{scope}));
    this.#access(session,scope.project_id,['OWNER']);
    return this.#store.read(db=>prepareCatalogue(db,scope,input,this.#principals,session,this.#now()));
  }
  commitCatalogue(session, scope, prepared) {
    scope=jsonCopy(scope);prepared=jsonCopy(prepared);shape('scope-ids',base('scope-ids',{scope}));
    this.#access(session,scope.project_id,['OWNER']);
    return this.#store.transaction(db=>{this.#access(session,scope.project_id,['OWNER']);return commitCatalogue(db,scope,prepared,this.#principals,session,this.#now());});
  }
  prepareArtifact(session,scope,input){
    scope=jsonCopy(scope);input=jsonCopy(input);this.#access(session,scope.project_id,['STATE_SERVICE']);
    return this.#store.transaction(db=>prepareArtifact(db,scope,input,this.#principals,this.#now()));
  }
  commitArtifact(session,scope,prepared,readbacks){
    scope=jsonCopy(scope);prepared=jsonCopy(prepared);readbacks=jsonCopy(readbacks);this.#access(session,scope.project_id,['STATE_SERVICE']);
    return this.#store.transaction(db=>commitArtifact(db,scope,prepared,readbacks,this.#principals,this.#now()));
  }
  tombstoneCatalogue(session,scope,expected,recordId) {
    scope=jsonCopy(scope);expected=jsonCopy(expected);shape('scope-ids',base('scope-ids',{scope}));
    this.#access(session,scope.project_id,['OWNER']);
    return this.#store.transaction(db=>{this.#access(session,scope.project_id,['OWNER']);const {p,c,pin}=catalogueContext(db,scope);requireState(digest(pin)===digest(expected),'CATALOGUE_AUTHORITY_STALE');const key=p.id+'/'+recordId;requireState(c.heads.memory[key],'CATALOGUE_RECORD_MISSING');p.catalogue??=c;if(!c.tombstones.memory.includes(key))c.tombstones.memory.push(key);return {status:'TOMBSTONED',authority_revision:db.commit+1};});
  }
  getTask(session, scope) {
    this.#access(session, scope.project_id);
    return this.#store.read(db => this.#task(this.#project(db, scope.project_id), scope));
  }
  getOperation(session, scope) {
    this.#access(session, scope.project_id);
    return this.#store.read(db => {
      const project = this.#project(db, scope.project_id); this.#task(project, scope);
      const op = project.operations[scope.operation_id];
      requireState(op?.scope.task_id === scope.task_id, 'OPERATION_MISSING'); return op;
    });
  }
  getOwnerActions(session, projectId) {
    this.#access(session, projectId);
    return this.#store.read(db => Object.values(this.#project(db, projectId).owner_actions));
  }
  getSubscriptions(session, projectId) {
    this.#access(session, projectId);
    return this.#store.read(db => Object.values(this.#project(db, projectId).subscriptions));
  }
  peekOutbox(session, projectId) {
    this.#access(session, projectId);
    return this.#store.read(db => Object.values(this.#project(db, projectId).outbox));
  }
  cursor(session, projectId, lastSequence = 0, ttlMs = 60000) {
    this.#access(session, projectId);
    requireState(Number.isSafeInteger(ttlMs) && ttlMs > 0 && ttlMs <= 86400000, 'CURSOR_TTL_INVALID');
    return this.#store.read(db => {
      const project = this.#project(db, projectId);
      const cursor = base('event-cursor', {recipient: session, project_id: projectId, stream_id: project.stream_id,
        last_sequence: lastSequence, epochs: project.epochs, expires_at: new Date(Date.parse(this.#now()) + ttlMs).toISOString()});
      const result = validate('event-cursor', cursor, this.#context(project, null, session,
        {project_id: projectId}, {revision: project.revision}));
      requireState(result.ok, 'CURSOR_REJECTED', result.errors); return cursor;
    });
  }
  scanEvents(session, cursor, limit = 100) {
    this.#access(session, cursor.project_id); shape('event-cursor', cursor);
    requireState(Number.isSafeInteger(limit) && limit > 0 && limit <= 1000, 'LIMIT_INVALID');
    return this.#store.read(db => {
      const project = this.#project(db, cursor.project_id);
      const result = validate('event-cursor', cursor, this.#context(project, null, session, {project_id: project.id}));
      requireState(result.ok, 'CURSOR_REJECTED', result.errors);
      const events = project.events.filter(event => event.sequence > cursor.last_sequence).slice(0, limit);
      return {events, cursor: {...cursor, last_sequence: events.at(-1)?.sequence ?? cursor.last_sequence}};
    });
  }
}
