import {digest, immutable, need, validateBoundValue, validateMissionBinding} from '../contracts/index.mjs';
import {isActivatedTool} from './review.mjs';
import {runFixedTextTool} from './local-execution.mjs';

/** Host constructs this using real authenticated A1 + project A2 ports. A
 * catalog row, E0 BOUND_E0_ONLY proposal, or planner choice is not a permit. */
export function createToolDispatcher({lookup, authenticate, coordinator, resolveGrant, binaryResolver, clock = () => new Date().toISOString(), launchObserver = null}) {
  need([lookup, authenticate, resolveGrant, binaryResolver].every(fn => typeof fn === 'function') && coordinator && typeof coordinator.snapshot === 'function' && typeof coordinator.heartbeat === 'function', 'TOOL_NATIVE_HOST_PORTS_REQUIRED');
  need(launchObserver === null || typeof launchObserver === 'function', 'TOOL_LAUNCH_OBSERVER');
  const sync = value => { need(!value?.then, 'TOOL_FINAL_AUTH_MUST_BE_SYNCHRONOUS'); return value; };
  const heartbeatLeaseMs = 6000, executionWindowMs = 4000;
  function current({context, scope, choice, input}, snapshot, minimumWindow = 0, heartbeatStarted = null) {
    // Host A1 context/grant/registry reads must be synchronous here. No task,
    // model or catalog callback can interleave a revocation before launch.
    const principal = sync(authenticate(context)), grant = sync(resolveGrant(scope, context));
    need(choice?.decision === 'SELECTED' && choice.selected?.ref_digest, 'TOOL_CHOICE_REQUIRED');
    const entry = sync(lookup(choice.selected.ref_digest)), now = clock(), nowMs = Date.parse(now);
    need(principal?.role === 'EXECUTOR' && principal.principal_id === scope.worker_id && principal.project_id === coordinator.project_id, 'TOOL_ACTOR_SCOPE');
    need(grant && grant.project_id === principal.project_id && grant.mission_id === scope.mission_id && grant.revoked_at === null && grant.issued_at <= now && now < grant.expires_at && grant.allowed_principals.includes(principal.principal_id), 'TOOL_CURRENT_GRANT_REQUIRED');
    need(isActivatedTool(entry) && entry.installed && entry.available && now < entry.health_until, 'TOOL_HOST_ACTIVATION_REQUIRED');
    need(digest(entry.descriptor.ref) === choice.selected.ref_digest && grant.allowed_capabilities.some(ref => digest(ref) === digest(entry.descriptor.ref)) && entry.descriptor.permissions.every(permission => grant.permissions.includes(permission)), 'TOOL_CAPABILITY_GRANT_REQUIRED');
    need(entry.descriptor.effect_class === 'NONE' && grant.allowed_effect_classes.includes('NONE'), 'TOOL_EFFECT_SCOPE');
    need(snapshot.project.project_id === principal.project_id, 'TOOL_NATIVE_PROJECT');
    const task = snapshot.tasks.find(item => item.mission_id === scope.mission_id && item.task_id === scope.task_id && item.is_current);
    const lease = snapshot.leases.find(item => item.mission_id === scope.mission_id && item.task_id === scope.task_id);
    const mission = snapshot.missions.find(item => item.mission_id === scope.mission_id);
    need(task?.state === 'RUNNING' && task.producer_id === scope.worker_id && String(task.fence) === String(scope.fence) && task.plan_digest === scope.plan_digest && task.capability_id === entry.descriptor.ref.capability_id && task.capability_version === entry.descriptor.ref.version && digest(task.document.capability) === digest(entry.descriptor.ref), 'TOOL_NATIVE_CLAIM_REQUIRED');
    need(lease && !lease.held && lease.worker_id === scope.worker_id && String(lease.fence) === String(scope.fence) && Date.parse(lease.expires_at) > Date.parse(now) && Date.parse(lease.execution_deadline) > Date.parse(now), 'TOOL_NATIVE_LEASE_REQUIRED');
    need(mission?.state === 'ACTIVE' && mission.grant_digest === digest(grant) && Date.parse(mission.deadline) > Date.parse(now), 'TOOL_NATIVE_MISSION_REQUIRED');
    need(mission.plan_digest === scope.plan_digest && Date.parse(task.deadline) > Date.parse(now) && task.document.effect?.effect_class === 'NONE', 'TOOL_NATIVE_PLAN_OR_EFFECT');
    validateMissionBinding(mission.spec, grant, now);
    validateBoundValue(entry.descriptor.input_schema, input);
    need(digest(input) === digest(task.document.input), 'TOOL_NATIVE_INPUT_BINDING');
    if (minimumWindow) {
      // Conservatively retain the earlier observed lease expiry too. A short
      // prior lease may reject despite renewal; it never grants extra time.
      const deadlines = [grant.expires_at, entry.health_until, task.deadline, mission.deadline, lease.expires_at, lease.execution_deadline].map(Date.parse);
      if (heartbeatStarted !== null) deadlines.push(heartbeatStarted + heartbeatLeaseMs);
      need(Number.isFinite(nowMs) && deadlines.every(deadline => Number.isFinite(deadline) && deadline - nowMs >= minimumWindow), 'TOOL_EXECUTION_WINDOW_TOO_SHORT');
    }
    return {entry, task, grant};
  }
  return Object.freeze({async dispatch({context, scope, choice, input}) {
    const frozen = immutable({scope, choice, input}), frozenDigest = digest(frozen), call = {context, ...frozen};
    const before = current(call, await coordinator.snapshot());
    // All potentially yielding resolution occurs before the final native/A1
    // permission check. Paths remain trusted host configuration, never input.
    const binaries = immutable(await binaryResolver(before.entry.profile_id));
    const finalSnapshot = await coordinator.snapshot(), heartbeatStarted = Date.parse(clock());
    need((await coordinator.heartbeat({...frozen.scope, lease_ms: heartbeatLeaseMs}))?.status === 'RENEWED', 'TOOL_NATIVE_FENCE_DENIED');
    let permission;
    const finalGuard = () => {
      need(digest(frozen) === frozenDigest, 'TOOL_FROZEN_REQUEST_CHANGED');
      permission = current(call, finalSnapshot, executionWindowMs, heartbeatStarted);
      need(permission.entry.review_digest === before.entry.review_digest && digest(permission.grant) === digest(before.grant), 'TOOL_REVIEW_OR_GRANT_CHANGED');
    };
    finalGuard();
    const execution = runFixedTextTool({profile_id: permission.entry.profile_id, binaries, pins: permission.entry.review.payload.binary_pins, input: frozen.input,
      beforeSpawn() { finalGuard(); },
      onSpawned(value) { if (launchObserver) sync(launchObserver({...value, profile_id: permission.entry.profile_id, native_scope: frozen.scope})); }});
    need((await coordinator.heartbeat({...frozen.scope, lease_ms: heartbeatLeaseMs}))?.status === 'RENEWED', 'TOOL_NATIVE_FENCE_DENIED');
    const after = current(call, await coordinator.snapshot());
    need(after.entry.review_digest === before.entry.review_digest && digest(after.grant) === digest(before.grant), 'TOOL_REVIEW_OR_GRANT_CHANGED');
    const result = immutable({output_schema_digest: before.entry.descriptor.ref.output_schema.digest, output: execution.output, artifact_digest: digest(execution.output), evidence: {tool_review_digest: before.entry.review_digest, choice_digest: digest(frozen.choice), execution, native_scope: frozen.scope}});
    return immutable({decision: 'EXECUTED_PENDING_COMPLETE_AND_QA', result, result_hash: digest(result), native_claim_checked: true, accepted: false, external_mutations: 0});
  }});
}
