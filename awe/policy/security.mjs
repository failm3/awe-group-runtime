import {digest} from '../../contracts/canonical.mjs';
import {validate, createValidationContext} from '../../contracts/validate.mjs';
import {validateShape} from '../../contracts/schema-validator.mjs';
import {parseIntent, copy, freeze, requireKeys} from './json.mjs';
import {createRecordingSink} from '../sandbox/recording-sink.mjs';

export const SIMULATION_POLICY = 'd02-simulation-v1';
const roles = new Set(['OWNER', 'SUPERVISOR', 'EXECUTOR', 'EXAMINER', 'AUDITOR',
  'ARTIFACT_SERVICE', 'ROUTE_BROKER', 'STATE_SERVICE', 'CONTEXT_BUILDER', 'PROJECT_FACTORY']);
const actions = new Set(['publish', 'delete', 'charge', 'send_sensitive', 'inference', 'read']);
const classes = new Set(['PUBLIC', 'WORK', 'TRACE', 'QA_HIDDEN', 'LOCAL_QA', 'QA_EVIDENCE', 'SECRET']);
const terminal = new Set(['COMPLETE', 'CANCELLED', 'FAILED', 'CANCELLING']);
const effectKeys = ['scope', 'actor', 'action', 'resource', 'payload', 'payload_hash', 'epochs',
  'spec', 'expected_revision', 'tool_id', 'tool_digest', 'input_schema_hash',
  'run_id', 'approval_id', 'quote_id', 'reservation_micros'];
const fail = reason => { throw new Error(reason); };
const ensure = (condition, reason) => { if (!condition) fail(reason); };
const same = (a, b) => digest(a) === digest(b);
const amount = value => typeof value === 'string' && /^(0|[1-9][0-9]{0,29})$/.test(value);
const shape = (name, value) => ensure(validateShape(name, value).length === 0, 'INVALID_' + name.toUpperCase());

/** Trusted synthetic control-plane factory. Never expose `control` to a worker.
 * All state is process-local; no authority or durable grant for a real effect.
 * Construction/configuration is trusted. Worker inputs are strict JSON text.
 */
export function createOfflineSecurity(seed, {clock = () => '2026-11-05T12:00:00.000Z'} = {}) {
  const data = copy(seed);
  ensure(data.mode === 'SYNTHETIC_ONLY', 'SIMULATION_REQUIRED');
  const principals = new Map(), projects = new Map(), resources = new Map();
  const sessions = new WeakMap(), contexts = new WeakMap();
  const approvals = new Map(), grants = new Map(), tools = new Map(), quotes = new Map();
  const operations = new Map(), quotas = new Map(), sink = createRecordingSink();
  let lastClock = '';
  function now() {
    const time = clock();
    ensure(typeof time === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[.]\d{3}Z$/.test(time) &&
      Number.isFinite(Date.parse(time)) && new Date(time).toISOString() === time, 'CLOCK_INVALID');
    ensure(time >= lastClock, 'CLOCK_ROLLBACK'); lastClock = time;
    return time;
  }
  for (const p of data.principals) {
    shape('actor-ref', {schema_version: '1.0.0', contract: 'actor-ref', actor: p.actor});
    ensure(roles.has(p.actor.role) && !principals.has(p.actor.identity_id), 'PRINCIPAL_INVALID');
    ensure(typeof p.subject === 'string' && p.subject.length > 0 && Array.isArray(p.tasks), 'SUBJECT_REQUIRED');
    principals.set(p.actor.identity_id, {...p, active: true, generation: 1});
  }
  // One subject cannot be executor/supervisor, Examiner and Auditor under aliases.
  const lane = role => role === 'EXAMINER' ? 'examiner' : role === 'AUDITOR' ? 'auditor' : 'producer';
  for (const p of principals.values()) for (const q of principals.values())
    if (p.subject === q.subject) ensure(lane(p.actor.role) === lane(q.actor.role), 'QA_SUBJECT_CONFLICT');
  for (const p of data.projects) {
    shape('epochs', {schema_version: '1.0.0', contract: 'epochs', epochs: p.epochs});
    ensure(!projects.has(p.project_id) && p.tasks.length > 0, 'PROJECT_INVALID');
    projects.set(p.project_id, {...p, cancel: false});
    for (const task of p.tasks) {
      shape('scope-ids', {schema_version: '1.0.0', contract: 'scope-ids', scope: {
        project_id: p.project_id, task_id: task.task_id, operation_id: 'op_validation'}});
      ensure(Number.isSafeInteger(task.revision) && task.revision >= 0, 'REVISION_INVALID');
      ensure(amount(task.quota_micros), 'QUOTA_INVALID');
      quotas.set(digest([p.project_id, task.task_id]), BigInt(task.quota_micros));
    }
  }
  for (const r of data.resources) {
    ensure(!resources.has(r.id) && classes.has(r.classification), 'RESOURCE_INVALID');
    const p = projects.get(r.project_id);
    ensure(p?.tasks.some(t => t.task_id === r.task_id), 'RESOURCE_SCOPE_INVALID');
    ensure(Array.isArray(r.roles) && r.roles.every(role => roles.has(role)), 'RESOURCE_ROLE_INVALID');
    resources.set(r.id, r);
  }
  function project(scope) {
    shape('scope-ids', {schema_version: '1.0.0', contract: 'scope-ids', scope});
    const p = projects.get(scope.project_id), task = p?.tasks.find(t => t.task_id === scope.task_id);
    ensure(task, 'SCOPE_DENIED');
    return {p, task};
  }
  function member(principal, scope) {
    return principal.tasks.some(t => t.project_id === scope.project_id && t.task_id === scope.task_id);
  }
  function authenticate(session, scope) {
    // A JSON identity or a session from a second instance has no WeakMap entry.
    const s = sessions.get(session), identity = s && principals.get(s.identity_id);
    ensure(identity?.active && identity.generation === s.generation, 'SESSION_INVALID');
    const {p} = project(scope);
    ensure(member(identity, scope), 'SCOPE_DENIED');
    const context = freeze({actor: copy(identity.actor), scope: copy(scope), epochs: copy(p.epochs),
      trust_source: 'SYNTHETIC_IDENTITY_ONLY'});
    contexts.set(context, {identity_id: s.identity_id, generation: s.generation,
      scope: copy(scope), epochs: copy(p.epochs)});
    return context;
  }
  function trusted(context, scope) {
    const c = contexts.get(context), principal = c && principals.get(c.identity_id);
    ensure(principal?.active && principal.generation === c.generation, 'AUTH_CONTEXT_INVALID');
    ensure(same(c.scope, scope) && member(principal, scope), 'AUTH_SCOPE_DENIED');
    const {p, task} = project(scope);
    ensure(same(c.epochs, p.epochs), 'AUTH_EPOCH_REVOKED');
    return {principal, p, task};
  }
  function validationContext(principal, scope, time, parent) {
    const {p, task} = project(scope);
    return createValidationContext({now: time, authenticated_identity_id: principal.actor.identity_id,
      principals: Object.fromEntries([...principals.values()].filter(x => x.active).map(x =>
        [x.actor.identity_id, {role: x.actor.role, projects: [...new Set(x.tasks.map(t => t.project_id))]}])),
      project_id: p.project_id, task_id: task.task_id, operation: {id: scope.operation_id},
      epochs: p.epochs, spec: task.spec, revision: task.revision, parent_grant: parent});
  }
  function contract(context, name, dto, parent) {
    const {principal} = trusted(context, dto.scope);
    const result = validate(name, dto, validationContext(principal, dto.scope, now(), parent));
    ensure(result.ok, 'CONTRACT_DENIED:' + result.errors.join('|'));
    return principal;
  }
  function visible(principal, resource) {
    const role = principal.actor.role, level = resource.classification;
    ensure(resource.roles.includes(role), 'RESOURCE_ROLE_DENIED');
    ensure(level !== 'SECRET', 'SECRET_DENIED');
    ensure(level !== 'QA_HIDDEN' || role === 'EXAMINER', 'HIDDEN_QA_DENIED');
    ensure(level !== 'LOCAL_QA' || !['EXAMINER', 'AUDITOR'].includes(role), 'BLIND_QA_DENIED');
    ensure(level !== 'QA_EVIDENCE' || ['EXAMINER', 'AUDITOR'].includes(role), 'QA_EVIDENCE_DENIED');
    // Worker traces are metadata projections only, never raw text/log/context.
    ensure(level !== 'TRACE' || ['OWNER', 'SUPERVISOR', 'AUDITOR'].includes(role), 'TRACE_DENIED');
  }
  function currentGrant(record, intent, time, seen = new Set()) {
    ensure(record && !record.revoked && !seen.has(record.dto.run_id), 'GRANT_REVOKED_OR_UNKNOWN');
    seen.add(record.dto.run_id);
    const g = record.dto;
    ensure(record.subject === intent.actor.identity_id && same(g.scope, intent.scope), 'GRANT_SCOPE_DENIED');
    ensure(g.deadline > time && same(g.epochs, intent.epochs) && same(g.spec, intent.spec) &&
      g.expected_revision === intent.expected_revision, 'GRANT_STALE');
    ensure(g.capabilities.includes(intent.tool_id) && record.remaining > 0, 'GRANT_CAPABILITY_DENIED');
    const subject = principals.get(record.subject);
    ensure(subject?.active && subject.generation === record.subjectGeneration && member(subject, intent.scope), 'GRANT_SUBJECT_REVOKED');
    const issuer = principals.get(g.actor.identity_id);
    ensure(issuer?.active && issuer.generation === record.issuerGeneration && member(issuer, intent.scope), 'GRANT_ISSUER_REVOKED');
    if (g.parent_run_id) currentGrant(grants.get(g.parent_run_id), {...intent, actor: {identity_id:
      grants.get(g.parent_run_id)?.subject ?? '', role: intent.actor.role}}, time, seen);
    return record;
  }
  function decide(context, intent) {
    requireKeys(intent, effectKeys);
    const time = now(), {principal, p, task} = trusted(context, intent.scope);
    ensure(same(intent.actor, principal.actor), 'ACTOR_FORGED');
    ensure(p.policy_id === SIMULATION_POLICY, 'POLICY_UNKNOWN');
    ensure(p.cancel === false && !terminal.has(task.state), 'STOP_OR_CANCEL');
    ensure(same(intent.epochs, p.epochs), 'STALE_EPOCH');
    ensure(same(intent.spec, task.spec) && intent.expected_revision === task.revision, 'STALE_STATE');
    ensure(actions.has(intent.action), 'ACTION_UNKNOWN');
    ensure(digest(intent.payload) === intent.payload_hash, 'PAYLOAD_HASH_MISMATCH');
    const resource = resources.get(intent.resource);
    ensure(resource && resource.project_id === p.project_id && resource.task_id === task.task_id, 'RESOURCE_SCOPE_DENIED');
    visible(principal, resource);
    const t = tools.get(intent.tool_id);
    ensure(t && !t.revoked && t.dto.network_scope === 'NONE' && t.dto.credential_handle === null, 'TOOL_UNKNOWN');
    const toolIssuer = principals.get(t.dto.actor.identity_id);
    ensure(toolIssuer?.active && toolIssuer.generation === t.issuerGeneration, 'TOOL_ISSUER_REVOKED');
    ensure(intent.tool_digest === t.dto.tool_digest && intent.input_schema_hash === t.dto.input_schema_hash, 'TOOL_IDENTITY_MISMATCH');
    ensure(same(t.dto.scope, intent.scope) && same(t.dto.epochs, p.epochs) && same(t.dto.spec, task.spec) &&
      t.dto.expected_revision === task.revision, 'TOOL_STALE');
    ensure(t.actions.includes(intent.action) && t.resources.includes(intent.resource) &&
      t.roles.includes(principal.actor.role), 'TOOL_POLICY_DENIED');
    ensure((intent.action === 'read') === (t.dto.effect_class === 'READ_ONLY'), 'EFFECT_CLASS_MISMATCH');
    const grant = currentGrant(grants.get(intent.run_id), intent, time);
    ensure(amount(intent.reservation_micros), 'QUOTA_INVALID');
    const cost = BigInt(intent.reservation_micros);
    // Caller cannot choose a cheap quote/reservation: exact simulated tariff is trusted.
    ensure(cost === BigInt(t.cost_micros), 'RESERVATION_MISMATCH');
    const quotaKey = digest([p.project_id, task.task_id]);
    ensure(cost <= quotas.get(quotaKey), 'QUOTA_EXCEEDED');
    if (['inference', 'charge'].includes(intent.action)) {
      const quote = quotes.get(intent.quote_id);
      ensure(quote && !quote.revoked && quote.tool_id === intent.tool_id && same(quote.scope, intent.scope), 'QUOTE_UNKNOWN');
      const quoteIssuer = principals.get(quote.issuer);
      ensure(quoteIssuer?.active && quoteIssuer.generation === quote.issuerGeneration, 'QUOTE_ISSUER_REVOKED');
      const result = validate('provider-price', quote.dto, validationContext(principal, intent.scope, time));
      ensure(result.ok && quote.dto.status === 'QUOTED', 'QUOTE_UNKNOWN_OR_STALE');
    } else ensure(intent.quote_id === null, 'UNEXPECTED_QUOTE');
    const approval = approvals.get(intent.approval_id);
    ensure(approval && !approval.revoked && !approval.used, 'APPROVAL_UNUSABLE');
    const a = approval.dto, approver = principals.get(a.approver.identity_id);
    ensure(approver?.active && approver.actor.role === 'OWNER' && approver.generation === approval.issuerGeneration &&
      member(approver, intent.scope), 'APPROVER_REVOKED');
    ensure(same(a.scope, intent.scope) && a.action === intent.action && a.resource === intent.resource &&
      a.payload_hash === intent.payload_hash && approval.subject === principal.actor.identity_id,
    'APPROVAL_BINDING_MISMATCH');
    ensure(a.expires_at > time && same(a.epochs, p.epochs) && a.policy_revision === p.epochs.policy &&
      same(a.spec, task.spec) && a.expected_revision === task.revision, 'APPROVAL_STALE');
    const opKey = digest(intent.scope);
    ensure(!operations.has(opKey), 'OPERATION_REPLAY');
    const projection = intent.action === 'read' ? (resource.classification === 'TRACE'
      ? {kind: 'TRACE', operation_id: intent.scope.operation_id, status: 'SIMULATED'}
      : copy(resource.value)) : null;
    ensure(Buffer.byteLength(JSON.stringify(projection)) <= t.dto.max_output_bytes, 'OUTPUT_TOO_LARGE');
    return {time, principal, resource, approval, grant, quotaKey, cost, opKey, projection};
  }
  const deny = error => freeze({decision: 'DENY', reason: error.message.split(':')[0]});
  function pdp(context, text) {
    try { decide(context, parseIntent(text)); return freeze({decision: 'ALLOW_SIMULATION', policy: SIMULATION_POLICY}); }
    catch (error) { return deny(error); }
  }
  function execute(context, text) {
    try {
      // Never accept a caller's previous PDP decision/ticket. Re-read all current state.
      const intent = parseIntent(text), d = decide(context, intent);
      // No await/user callback between recheck, consume/reserve and recording.
      // Failed/unknown downstream outcomes retain consumption and reservation.
      d.approval.used = true;
      quotas.set(d.quotaKey, quotas.get(d.quotaKey) - d.cost);
      let g = d.grant;
      while (g) { g.remaining--; g = grants.get(g.dto.parent_run_id); }
      operations.set(d.opKey, 'DISPATCHING');
      const effect = {scope: intent.scope, actor: intent.actor, action: intent.action,
        resource: intent.resource, payload_hash: intent.payload_hash, tool_id: intent.tool_id,
        tool_digest: intent.tool_digest, input_schema_hash: intent.input_schema_hash,
        run_id: intent.run_id, epochs: intent.epochs, reservation_micros: intent.reservation_micros};
      const result = sink.dispatch(sink.mint(effect), effect);
      operations.set(d.opKey, result.decision === 'RECORDED_SIMULATION' ? 'CONFIRMED_SIMULATION' : 'OUTCOME_UNKNOWN');
      return freeze({...result, value: d.projection, effect_hash: digest(effect)});
    } catch (error) { return deny(error); }
  }
  const control = freeze({
    issueSession(identityId) {
      const p = principals.get(identityId); ensure(p?.active, 'PRINCIPAL_UNKNOWN');
      const session = Object.freeze({}); sessions.set(session, {identity_id: identityId, generation: p.generation});
      return session;
    },
    revokeIdentity(identityId) { const p = principals.get(identityId); ensure(p, 'PRINCIPAL_UNKNOWN'); p.active = false; p.generation++; },
    revokeApproval(id) { const a = approvals.get(id); ensure(a, 'APPROVAL_UNKNOWN'); a.revoked = true; },
    revokeGrant(id) { const g = grants.get(id); ensure(g, 'GRANT_UNKNOWN'); g.revoked = true; },
    revokeTool(id) { const t = tools.get(id); ensure(t, 'TOOL_UNKNOWN'); t.revoked = true; },
    revokeQuote(id) { const q = quotes.get(id); ensure(q, 'QUOTE_UNKNOWN'); q.revoked = true; },
    advanceEpoch(projectId, key) {
      const p = projects.get(projectId); ensure(p && ['policy', 'auth', 'stop', 'owner'].includes(key), 'EPOCH_INVALID');
      ensure(p.epochs[key] < Number.MAX_SAFE_INTEGER, 'EPOCH_OVERFLOW'); p.epochs[key]++;
    },
    cancel(projectId) {
      const p = projects.get(projectId); ensure(p, 'SCOPE_DENIED');
      ensure(p.epochs.stop < Number.MAX_SAFE_INTEGER, 'EPOCH_OVERFLOW'); p.cancel = true; p.epochs.stop++;
    },
    setTaskState(scope, state, revision) {
      const {task} = project(scope);
      ensure(['READY', 'RUNNING', 'COMPLETE', 'CANCELLED', 'FAILED', 'CANCELLING'].includes(state) &&
        Number.isSafeInteger(revision) && revision > task.revision, 'STATE_UPDATE_INVALID');
      ensure(!terminal.has(task.state), 'TERMINAL_IMMUTABLE'); task.state = state; task.revision = revision;
    },
    setPolicy(projectId, policyId) {
      const p = projects.get(projectId); ensure(p, 'SCOPE_DENIED');
      ensure(p.epochs.policy < Number.MAX_SAFE_INTEGER, 'EPOCH_OVERFLOW'); p.policy_id = policyId; p.epochs.policy++;
    },
    registerTool(context, dto, policy) {
      dto = copy(dto); policy = copy(policy);
      const principal = contract(context, 'tool-capability', dto);
      ensure(principal.actor.role === 'SUPERVISOR', 'SUPERVISOR_REQUIRED');
      requireKeys(policy, ['actions', 'resources', 'roles', 'cost_micros']);
      ensure(policy.actions.length > 0 && policy.actions.every(x => actions.has(x)) &&
        policy.roles.length > 0 && policy.roles.every(x => roles.has(x)) && amount(policy.cost_micros), 'TOOL_POLICY_INVALID');
      ensure(policy.resources.length > 0 && policy.resources.every(id => {
        const r = resources.get(id); return r && r.project_id === dto.scope.project_id && r.task_id === dto.scope.task_id;
      }), 'TOOL_RESOURCE_INVALID');
      ensure(!tools.has(dto.tool_id), 'TOOL_IMMUTABLE');
      tools.set(dto.tool_id, {dto, ...policy, issuerGeneration: principal.generation, revoked: false});
    },
    registerQuote(context, dto, binding) {
      dto = copy(dto); binding = copy(binding);
      const {principal} = trusted(context, binding.scope);
      ensure(principal.actor.role === 'SUPERVISOR', 'SUPERVISOR_REQUIRED');
      ensure(validate('provider-price', dto, validationContext(principal, binding.scope, now())).ok, 'QUOTE_INVALID');
      ensure(!quotes.has(dto.price_profile_id) && tools.has(binding.tool_id), 'QUOTE_BINDING_INVALID');
      quotes.set(dto.price_profile_id, {dto, scope: binding.scope, tool_id: binding.tool_id,
        issuer: principal.actor.identity_id, issuerGeneration: principal.generation, revoked: false});
    },
    registerApproval(context, dto, subject) {
      dto = copy(dto);
      const principal = contract(context, 'approval', dto);
      ensure(principal.actor.role === 'OWNER' && member(principals.get(subject) ?? {tasks: []}, dto.scope), 'APPROVAL_SUBJECT_INVALID');
      ensure(!approvals.has(dto.approval_id), 'APPROVAL_IMMUTABLE');
      approvals.set(dto.approval_id, {dto, subject, issuerGeneration: principal.generation, used: false, revoked: false});
    },
    registerGrant(context, dto, subject) {
      dto = copy(dto);
      const parent = dto.parent_run_id === null ? null : grants.get(dto.parent_run_id);
      const principal = contract(context, 'run-grant', dto, parent?.dto);
      ensure(principal.actor.role === 'SUPERVISOR', 'SUPERVISOR_REQUIRED');
      ensure(principals.get(subject)?.active && member(principals.get(subject), dto.scope), 'GRANT_SUBJECT_INVALID');
      ensure(dto.capabilities.every(id => {
        const tool = tools.get(id); return tool && !tool.revoked && same(tool.dto.scope, dto.scope);
      }), 'GRANT_TOOL_UNKNOWN');
      ensure(!grants.has(dto.run_id), 'GRANT_IMMUTABLE');
      if (parent) {
        ensure(!parent.revoked && parent.dto.depth === 0 && dto.depth === 1 &&
          parent.children < parent.dto.max_children && parent.dto.deadline > now(), 'CHILD_LIMIT');
        ensure(same(dto.scope, parent.dto.scope) && same(dto.epochs, parent.dto.epochs) &&
          same(dto.spec, parent.dto.spec) && dto.expected_revision === parent.dto.expected_revision &&
          dto.config_hash === parent.dto.config_hash && dto.manifest_hash === parent.dto.manifest_hash &&
          dto.max_physical_attempts <= parent.remaining, 'CHILD_ESCALATION');
        parent.children++;
      }
      grants.set(dto.run_id, {dto, subject, issuerGeneration: principal.generation,
        subjectGeneration: principals.get(subject).generation,
        remaining: dto.max_physical_attempts, children: 0, revoked: false});
    },
    inspect() {
      return copy({effects: sink.inspect(), operations: [...operations.entries()],
        approvals: [...approvals].map(([id, a]) => ({id, used: a.used, revoked: a.revoked})),
        quotas: [...quotas].map(([id, remaining]) => ({id, remaining_micros: String(remaining)})),
        grants: [...grants].map(([id, g]) => ({id, remaining: g.remaining, children: g.children}))});
    }
  });
  const worker = freeze({
    authenticate, pdp, execute,
    // Exposes the untrusted endpoint to exercise a direct-worker-bypass attempt.
    directDispatch(ticket, text) {
      try { return sink.dispatch(ticket, parseIntent(text)); } catch (error) { return deny(error); }
    }
  });
  return Object.freeze({control, worker});
}
