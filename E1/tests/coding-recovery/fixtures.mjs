import {digest} from '../../contracts/index.mjs';
import {MODEL_POLICY} from '../../broker/schemas.mjs';
import {PROGRAM_PROFILE, PROGRAM_PROFILE_DIGEST, validateProgramRequest} from '../../host/program-runner/profiles.mjs';
import {programByteDigest} from '../../host/program-runner/receipts.mjs';

// OFFLINE_TEST_DOUBLE data. No model, PostgreSQL, WSL or live receipt is used.
export const now = '2026-11-08T12:00:00.000Z', future = '2026-11-08T13:00:00.000Z';
export const scope = {mission_id: 'fixture_mission', task_id: 'fixture_task', worker_id: 'fixture_worker', fence: 1, logical_request_id: 'fixture_logical', attempt_id: 'fixture_attempt'};
export function snapshot() { return {project: {project_id: 'fixture_project'}, missions: [{mission_id: scope.mission_id, project_id: 'fixture_project', state: 'ACTIVE', deadline: future}], tasks: [{project_id: 'fixture_project', mission_id: scope.mission_id, task_id: scope.task_id, producer_id: scope.worker_id, fence: 1, is_current: true, state: 'RUNNING', deadline: future}], leases: [{mission_id: scope.mission_id, task_id: scope.task_id, worker_id: scope.worker_id, fence: 1, held: false, expires_at: future, execution_deadline: future}], attempts: []}; }
export const modelArgs = () => ({grant_ref: 'fixture_grant', attempt_scope: scope, issue: {title: 'OFFLINE fixture', body: 'not a generated solution'}, baseline: {base_sha: 'a'.repeat(40), files: []}, output_schema_digest: 'sha256:' + 'b'.repeat(64), max_attempts: 1, budget_cap_micros: 0, deadline: future});
export function confirmed(state) {
  const usage = {input_tokens: 1, output_tokens: 1}, attempt = {...scope, state: 'CONFIRMED', route_id: MODEL_POLICY.route_id, actual_cost: '0', request_hash: 'sha256:' + 'c'.repeat(64), usage};
  state.attempts = [attempt];
  const inner = {decision: 'PROPOSED', accounting_status: 'CONFIRMED', evidence_level: 'LIVE_LOCAL_MODEL', wire_attempts: 1, request_hash: attempt.request_hash, usage, fixture: 'OFFLINE_TEST_DOUBLE'},
    native_receipt = {response: inner, native_attempt: attempt, scope};
  return {proposal: {base_sha: 'a'.repeat(40), summary: 'OFFLINE fixture patch', changes: [{path: 'normalizer.py', before_digest: 'ABSENT', after_text: '# OFFLINE fixture only\n'}]}, accounting_status: 'CONFIRMED', wire_attempts: 1, route_id: MODEL_POLICY.route_id, attempt_id: scope.attempt_id, actual_cost_micros: 0, usage,
    model: {id: MODEL_POLICY.model, digest: MODEL_POLICY.digest}, evidence_level: 'LIVE_SCOPED_HOST', native_receipt, host_binding_digest: digest(native_receipt)};
}
export function modelPort(run) { return {kind: 'ACCOUNTED_PATCH_MODEL_PORT', mode: 'LIVE_SCOPED_HOST', capability_id: 'e1.coding.patch', route_id: MODEL_POLICY.route_id, lastReceipt: null, proposePatch: run}; }
export function programRequest(invocation_id = 'fixture_nonce_123') { return {files: [{path: 'normalizer.py', content_utf8: '# OFFLINE fixture only\n'}, {path: 'cli.py', content_utf8: '# OFFLINE fixture only\n'}], stdin: '', entrypoint: 'cli.py', binding: {tested_head_sha: 'd'.repeat(40), tested_tree_sha: 'e'.repeat(40), invocation_id}}; }
export function testArgs() { const r = programRequest(); return {worktree_id: 'fixture_worktree', capability: {capability_id: 'fixture.public-test', command_digest: 'sha256:' + 'f'.repeat(64), timeout_ms: 20000}, grant_ref: 'fixture_grant', deadline: future, expected_head_sha: r.binding.tested_head_sha, expected_tree_sha: r.binding.tested_tree_sha, profile_digest: PROGRAM_PROFILE_DIGEST, invocation_id: r.binding.invocation_id}; }
export function programResult(request, exit_code = 1) {
  const expected = validateProgramRequest(request), stdout = '', stderr = '', timed_out = false, output_truncated = false;
  const value = {schema: 'awe.e1.program-receipt/1', status: 'EXECUTED', sandbox_enforced: true, network: 'DENY', profile_digest: PROGRAM_PROFILE_DIGEST, limits: PROGRAM_PROFILE.limits, ...request.binding,
    source_files: expected.source_files, source_digest: expected.source_digest, stdin_digest: expected.stdin_digest, entrypoint: request.entrypoint, stdout, stderr, exit_code, timed_out, output_truncated, output_encoding_valid: true, stdout_bytes_digest: programByteDigest(stdout), stderr_bytes_digest: programByteDigest(stderr),
    output_digest: digest({stdout, stderr, exit_code, timed_out, output_truncated}), fixture: 'OFFLINE_TEST_DOUBLE',
    boundary: Object.fromEntries(['home_absent', 'windows_absent', 'repository_absent', 'private_absent', 'source_readonly', 'network_namespace', 'mount_namespace', 'pid_namespace', 'socket_denied', 'fork_denied', 'exec_denied', 'seccomp_enforced', 'no_new_privileges', 'tmpfs_bounded'].map(k => [k, true])),
    toolchain: {platform: 'linux-x86_64', python_version: '3.12.3', python_digest: 'sha256:' + 'a'.repeat(64), bwrap_version: 'OFFLINE_TEST_DOUBLE'}};
  const receipt = {...value, receipt_digest: digest(value)}, args = testArgs();
  return {...receipt, capability_id: args.capability.capability_id, command_digest: args.capability.command_digest, timeout_ms: args.capability.timeout_ms, program_receipt: receipt};
}
export function completionArgs() {
  const state = snapshot(), response = confirmed(state), patch = response.proposal;
  return {proposal: patch, artifact: {patch, head_sha: 'd'.repeat(40), tree_sha: 'e'.repeat(40), artifact_digest: 'sha256:' + 'd'.repeat(64), fixture: 'OFFLINE_TEST_DOUBLE'}, model_receipt: response, product_status: 'PRODUCER_TEST_FAILED'};
}
