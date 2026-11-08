import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {canonicalize, digest, immutable, need} from '../../contracts/index.mjs';
import {MODEL_POLICY} from '../../broker/schemas.mjs';
import {verifyProgramReceipt} from '../program-runner/receipts.mjs';
import {buildCodingResult, completeCodingResult} from './coordinator-binding.mjs';

/** Private process-crash journal. File contents are fsync'ed before atomic
 * rename. This does not claim power-loss durability of the Windows directory.
 * Root owns the exclusive supervisor lock; workers never get these paths. */
function store(directory) {
  need(typeof directory === 'string' && path.isAbsolute(directory), 'RECOVERY_PRIVATE_DIRECTORY');
  fs.mkdirSync(directory, {recursive: true, mode: 0o700});
  const stat = fs.lstatSync(directory);
  need(stat.isDirectory() && !stat.isSymbolicLink() && fs.realpathSync(directory).toLowerCase() === path.resolve(directory).toLowerCase(), 'RECOVERY_DIRECTORY_ALIAS');
  const filename = name => { need(/^[a-z0-9_-]{1,180}\.json$/.test(name), 'RECOVERY_RECORD_NAME'); return path.join(directory, name); };
  function read(name) {
    const file = filename(name); if (!fs.existsSync(file)) return null;
    const st = fs.lstatSync(file); need(st.isFile() && !st.isSymbolicLink() && st.nlink === 1 && st.size <= 65537, 'RECOVERY_RECORD_UNSAFE');
    const value = JSON.parse(fs.readFileSync(file, 'utf8')); canonicalize(value); return value;
  }
  function write(name, value, exclusive = false) {
    const file = filename(name), bytes = canonicalize(value) + '\n', temporary = filename('tmp_' + randomUUID().replaceAll('-', '') + '.json');
    let fd;
    if (exclusive) {
      fd = fs.openSync(file, 'wx', 0o600);
      try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      return;
    }
    if (fs.existsSync(file)) read(name);
    fd = fs.openSync(temporary, 'wx', 0o600);
    try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(temporary, file);
  }
  return Object.freeze({read, write,
    object(value) { const ref = digest(value), name = 'obj_' + ref.slice(7) + '.json'; const old = read(name); if (old) need(digest(old) === ref, 'RECOVERY_OBJECT_CONFLICT'); else write(name, value); return ref; },
    dereference(ref) { need(/^sha256:[a-f0-9]{64}$/.test(ref), 'RECOVERY_OBJECT_REF'); const value = read('obj_' + ref.slice(7) + '.json'); need(value && digest(value) === ref, 'RECOVERY_OBJECT_LOST_OR_CHANGED'); return immutable(value); }
  });
}
const key = value => digest(value).slice(7);
function scopePin(scope) {
  need(scope && ['mission_id', 'task_id', 'worker_id'].every(field => typeof scope[field] === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/.test(scope[field])) && /^[1-9][0-9]*$/.test(String(scope.fence)), 'RECOVERY_SCOPE');
  return {mission_id: scope.mission_id, task_id: scope.task_id, worker_id: scope.worker_id, fence: String(scope.fence),
    ...(typeof scope.attempt_id === 'string' ? {attempt_id: scope.attempt_id} : {}), ...(typeof scope.logical_request_id === 'string' ? {logical_request_id: scope.logical_request_id} : {})};
}
function nativeRows(snapshot, scope, project_id) {
  need(snapshot?.project?.project_id === project_id, 'RECOVERY_NATIVE_PROJECT');
  const task = snapshot.tasks?.find(item => item.mission_id === scope.mission_id && item.task_id === scope.task_id && item.is_current);
  const mission = snapshot.missions?.find(item => item.mission_id === scope.mission_id);
  const lease = snapshot.leases?.find(item => item.mission_id === scope.mission_id && item.task_id === scope.task_id);
  const attempt = snapshot.attempts?.find(item => item.attempt_id === scope.attempt_id);
  need(task && task.project_id === project_id && task.producer_id === scope.worker_id && String(task.fence) === String(scope.fence) && mission?.project_id === project_id, 'RECOVERY_NATIVE_SCOPE');
  return {task, mission, lease, attempt};
}
function assertRunning(rows, scope, now) {
  need(rows.task.state === 'RUNNING' && rows.mission.state === 'ACTIVE' && Date.parse(rows.task.deadline) > Date.parse(now) && Date.parse(rows.mission.deadline) > Date.parse(now), 'RECOVERY_TASK_NOT_RUNNING');
  const lease = rows.lease;
  need(lease && !lease.held && lease.worker_id === scope.worker_id && String(lease.fence) === String(scope.fence) && Date.parse(lease.expires_at) > Date.parse(now) && Date.parse(lease.execution_deadline) > Date.parse(now), 'RECOVERY_LEASE_EXPIRED_OR_CHANGED');
}
function assertAttempt(attempt, response, scope) {
  need(attempt?.state === 'CONFIRMED' && attempt.attempt_id === scope.attempt_id && attempt.logical_request_id === scope.logical_request_id && attempt.mission_id === scope.mission_id && attempt.task_id === scope.task_id && attempt.worker_id === scope.worker_id && String(attempt.fence) === String(scope.fence) && attempt.route_id === MODEL_POLICY.route_id && Number(attempt.actual_cost) === 0, 'RECOVERY_CONFIRMED_ATTEMPT_REQUIRED');
  const inner = response?.native_receipt?.response;
  need(response.accounting_status === 'CONFIRMED' && response.wire_attempts === 1 && response.attempt_id === scope.attempt_id && response.evidence_level === 'LIVE_SCOPED_HOST' && inner?.evidence_level === 'LIVE_LOCAL_MODEL' && inner.accounting_status === 'CONFIRMED' && inner.wire_attempts === 1 && digest(attempt.usage) === digest(inner.usage), 'RECOVERY_PROVIDER_RECEIPT');
  if (inner.request_hash) need(inner.request_hash === attempt.request_hash, 'RECOVERY_REQUEST_HASH');
  if (response.proposal) need(response.route_id === attempt.route_id && digest(response.usage) === digest(attempt.usage) && response.model?.id === MODEL_POLICY.model && response.model?.digest === MODEL_POLICY.digest && response.host_binding_digest === digest(response.native_receipt), 'RECOVERY_MODEL_BINDING');
}

export function createRecoverableModelPort({modelPort, directory, project_id, readNativeState, onModelPersisted, clock = () => new Date().toISOString()}) {
  need(modelPort?.kind === 'ACCOUNTED_PATCH_MODEL_PORT' && typeof modelPort.proposePatch === 'function' && typeof readNativeState === 'function', 'RECOVERY_MODEL_PORT');
  const journal = store(directory); let lastReceipt = null;
  return Object.freeze({kind: modelPort.kind, mode: modelPort.mode, capability_id: modelPort.capability_id, route_id: modelPort.route_id,
    get lastReceipt() { return lastReceipt ?? modelPort.lastReceipt; },
    async proposePatch(args) {
      const scope = scopePin(args.attempt_scope), id = key(scope), name = 'model_' + id + '.json';
      need(scope.attempt_id && scope.logical_request_id, 'RECOVERY_MODEL_SCOPE');
      const context_digest = digest({...args, attempt_scope: scope});
      const rows = nativeRows(await readNativeState(scope), scope, project_id);
      let record = journal.read(name);
      if (record?.response_ref) lastReceipt = journal.dereference(record.response_ref).native_receipt ?? null;
      need(!['OUTCOME_UNKNOWN', 'SENDING', 'RESERVED'].includes(rows.attempt?.state), 'RECOVERY_HOLD_MODEL_OUTCOME_UNKNOWN');
      assertRunning(rows, scope, clock());
      if (record) {
        need(record.context_digest === context_digest && record.scope_digest === digest(scope), 'RECOVERY_MODEL_CONTEXT_CHANGED');
        if (!record.response_ref) {
          need(rows.attempt?.state !== 'CONFIRMED', 'RECOVERY_BLOCK_LOST_CONFIRMED_RESPONSE');
          need(false, 'RECOVERY_HOLD_MODEL_INTENT_UNCERTAIN_NO_RETRY');
        }
        const response = journal.dereference(record.response_ref); lastReceipt = response.native_receipt ?? null;
        need(!/UNKNOWN|UNCERTAIN/.test(response.accounting_status ?? '') && !['SENDING', 'OUTCOME_UNKNOWN', 'RESERVED'].includes(rows.attempt?.state), 'RECOVERY_HOLD_MODEL_OUTCOME_UNKNOWN');
        assertAttempt(rows.attempt, response, scope);
        return response; // Exact original bytes/labels, never relabelled live.
      }
      need(!rows.attempt, rows.attempt?.state === 'CONFIRMED' ? 'RECOVERY_BLOCK_LOST_CONFIRMED_RESPONSE' : 'RECOVERY_HOLD_EXISTING_ATTEMPT_NO_RETRY');
      const context_ref = journal.object({...args, attempt_scope: scope});
      record = {schema: 'awe.e1.model-recovery/1', scope_digest: digest(scope), context_digest, context_ref, state: 'INTENT_BEFORE_WIRE'};
      journal.write(name, record, true); // Exclusive and fsync'ed BEFORE broker.
      const response = await modelPort.proposePatch(args);
      lastReceipt = response.native_receipt ?? modelPort.lastReceipt ?? null;
      const response_ref = journal.object(response);
      journal.write(name, {...record, response_ref, state: response.accounting_status === 'CONFIRMED' ? 'RESPONSE_PERSISTED' : 'OUTCOME_HELD'});
      if (response.accounting_status === 'CONFIRMED') {
        const after = nativeRows(await readNativeState(scope), scope, project_id); assertRunning(after, scope, clock()); assertAttempt(after.attempt, response, scope);
      }
      if (onModelPersisted) await onModelPersisted(immutable({scope, context_digest, response_ref, accounting_status: response.accounting_status ?? 'UNKNOWN'}));
      return response;
    }
  });
}

export function createStableInvocationIdFactory({directory, scope}) {
  const journal = store(directory), scoped = scopePin(scope);
  return ({grant, capability, readback}) => {
    const binding = {scope: scoped, grant_digest: digest(grant), capability, head_sha: readback.head_sha, tree_sha: readback.tree_sha}, id = key(binding), name = 'nonce_' + id + '.json';
    const old = journal.read(name);
    if (old) { need(old.binding_digest === digest(binding) && /^[a-f0-9]{32}$/.test(old.invocation_id), 'RECOVERY_NONCE_BINDING'); return old.invocation_id; }
    const invocation_id = randomUUID().replaceAll('-', ''); journal.write(name, {schema: 'awe.e1.test-invocation/1', binding_digest: digest(binding), invocation_id}, true); return invocation_id;
  };
}

export function createRecoverableTestRunner({testRunner, directory, scope, project_id, readNativeState, resolveTestRequest, onTestPersisted, clock = () => new Date().toISOString()}) {
  need(typeof testRunner?.run === 'function' && typeof resolveTestRequest === 'function' && typeof readNativeState === 'function', 'RECOVERY_TEST_RUNNER');
  const journal = store(directory), scoped = scopePin(scope);
  return Object.freeze({kind: testRunner.kind, mode: testRunner.mode, isolation: testRunner.isolation, network: testRunner.network,
    async run(args) {
      const rows = nativeRows(await readNativeState(scoped), scoped, project_id); assertRunning(rows, scoped, clock());
      const request = await resolveTestRequest(args);
      need(request.binding.tested_head_sha === args.expected_head_sha && request.binding.tested_tree_sha === args.expected_tree_sha && request.binding.invocation_id === args.invocation_id, 'RECOVERY_TEST_REQUEST_BINDING');
      const binding = {scope: scoped, args, program_request_digest: digest(request)}, id = key({scope: scoped, args}), name = 'test_' + id + '.json';
      const record = journal.read(name);
      if (record) {
        need(record.binding_digest === digest(binding), 'RECOVERY_TEST_REQUEST_CHANGED');
        need(record.response_ref, 'RECOVERY_TEST_OUTCOME_UNCERTAIN');
        const result = journal.dereference(record.response_ref); verifyProgramReceipt(result.program_receipt, request);
        need(result.profile_digest === args.profile_digest && result.tested_head_sha === args.expected_head_sha && result.tested_tree_sha === args.expected_tree_sha && result.invocation_id === args.invocation_id && result.command_digest === args.capability.command_digest && result.capability_id === args.capability.capability_id, 'RECOVERY_TEST_RECEIPT_BINDING');
        return result;
      }
      const request_ref = journal.object(request);
      journal.write(name, {schema: 'awe.e1.test-recovery/1', binding_digest: digest(binding), request_ref, state: 'INTENT_BEFORE_TEST'}, true);
      const result = await testRunner.run(args); verifyProgramReceipt(result.program_receipt, request);
      need(result.profile_digest === args.profile_digest && result.tested_head_sha === args.expected_head_sha && result.tested_tree_sha === args.expected_tree_sha && result.invocation_id === args.invocation_id && result.command_digest === args.capability.command_digest && result.capability_id === args.capability.capability_id, 'RECOVERY_TEST_RECEIPT_BINDING');
      const after = nativeRows(await readNativeState(scoped), scoped, project_id); assertRunning(after, scoped, clock());
      const response_ref = journal.object(result);
      journal.write(name, {schema: 'awe.e1.test-recovery/1', binding_digest: digest(binding), request_ref, response_ref, state: 'TEST_PERSISTED'});
      if (onTestPersisted) await onTestPersisted(immutable({scope: scoped, response_ref, invocation_id: args.invocation_id}));
      return result;
    }
  });
}

export function createRecoverableCoordinatorBinding({client, scope, directory, project_id, readNativeState, verifyArtifactReadback, onNativeCompleted, clock = () => new Date().toISOString()}) {
  need(typeof client?.complete === 'function' && typeof readNativeState === 'function' && typeof verifyArtifactReadback === 'function', 'RECOVERY_COMPLETION_PORTS');
  const journal = store(directory), scoped = scopePin(scope), name = 'complete_' + key(scoped) + '.json'; let completion = null;
  async function verifiedNative(expected) {
    const rows = nativeRows(await readNativeState(scoped), scoped, project_id);
    if (['WAIT_QA', 'ACCEPTED', 'FAILED'].includes(rows.task.state)) {
      need(rows.task.result_hash === expected.result_hash && digest(rows.task.result) === expected.result_hash && digest(rows.task.result) === digest(expected.result), 'RECOVERY_NATIVE_RESULT_CONFLICT');
      need(await verifyArtifactReadback(expected.result.evidence.coding_artifact) === true, 'RECOVERY_ARTIFACT_READBACK');
      completion = immutable({...expected, value: {status: rows.task.state}, recovered: true}); return completion;
    }
    assertRunning(rows, scoped, clock()); return null;
  }
  return Object.freeze({get completion() { return completion; },
    async restore() {
      const record = journal.read(name);
      if (!record) {
        const rows = nativeRows(await readNativeState(scoped), scoped, project_id);
        need(!['WAIT_QA', 'ACCEPTED', 'FAILED'].includes(rows.task.state), 'RECOVERY_COMPLETION_INTENT_LOST');
        assertRunning(rows, scoped, clock()); return null;
      }
      const restored = await verifiedNative(journal.dereference(record.result_ref));
      need(restored || record.state !== 'NATIVE_COMPLETED', 'RECOVERY_NATIVE_COMPLETION_REGRESSED');
      return restored;
    },
    async complete(args) {
      const expected = buildCodingResult(args), old = journal.read(name);
      if (old) { const cached = journal.dereference(old.result_ref); need(cached.result_hash === expected.result_hash && digest(cached.result) === digest(expected.result), 'RECOVERY_COMPLETION_CHANGED'); }
      const native = await verifiedNative(expected); if (native) return native;
      need(old?.state !== 'NATIVE_COMPLETED', 'RECOVERY_NATIVE_COMPLETION_REGRESSED');
      need(await verifyArtifactReadback(expected.result.evidence.coding_artifact) === true, 'RECOVERY_ARTIFACT_READBACK');
      const result_ref = journal.object(expected);
      if (!old) journal.write(name, {schema: 'awe.e1.completion-recovery/1', result_ref, state: 'INTENT_BEFORE_COMPLETE'}, true);
      const actual = await completeCodingResult(client, scope, args);
      need(actual.result_hash === expected.result_hash && digest(actual.result) === digest(expected.result), 'RECOVERY_COMPLETION_ENVELOPE');
      const persisted = await verifiedNative(expected); need(persisted?.value.status === 'WAIT_QA', 'RECOVERY_NATIVE_COMPLETE_READBACK');
      journal.write(name, {schema: 'awe.e1.completion-recovery/1', result_ref, state: 'NATIVE_COMPLETED'});
      completion = immutable({...actual, recovered: false});
      if (onNativeCompleted) await onNativeCompleted(completion);
      return completion;
    }
  });
}
