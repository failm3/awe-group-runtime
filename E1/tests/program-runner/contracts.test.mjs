import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../../contracts/index.mjs';
import {PROGRAM_PROFILE, PROGRAM_PROFILE_DIGEST, validateProgramRequest} from '../../host/program-runner/profiles.mjs';
import {verifyProgramReceipt, programByteDigest} from '../../host/program-runner/receipts.mjs';

// ENGINEERING_TEST_FIXTURE: these never serve as an AWE-authored candidate.
const request = () => ({files: [{path: 'normalizer.py', content_utf8: 'def normalize_event(value):\n    return value\n'}, {path: 'cli.py', content_utf8: 'print("fixture")\n'}], stdin: '[]', entrypoint: 'library-probe.py', binding: {tested_head_sha: 'a'.repeat(40), tested_tree_sha: 'b'.repeat(40), invocation_id: 'engineering-fixture-01'}});
function fixtureReceipt(r) {
  const expected = validateProgramRequest(r), stdout = '[]\n', stderr = '', exit_code = 0, timed_out = false, output_truncated = false;
  const value = {schema: 'awe.e1.program-receipt/1', status: 'EXECUTED', sandbox_enforced: true, network: 'DENY', profile_digest: PROGRAM_PROFILE_DIGEST, limits: PROGRAM_PROFILE.limits, ...r.binding,
    source_files: expected.source_files, source_digest: expected.source_digest, stdin_digest: expected.stdin_digest, entrypoint: r.entrypoint, stdout, stderr, exit_code, timed_out, output_truncated,
    output_encoding_valid: true, stdout_bytes_digest: programByteDigest(stdout), stderr_bytes_digest: programByteDigest(stderr),
    output_digest: digest({stdout, stderr, exit_code, timed_out, output_truncated}),
    boundary: Object.fromEntries(['home_absent', 'windows_absent', 'repository_absent', 'private_absent', 'source_readonly', 'network_namespace', 'mount_namespace', 'pid_namespace', 'socket_denied', 'fork_denied', 'exec_denied', 'seccomp_enforced', 'no_new_privileges', 'tmpfs_bounded'].map(key => [key, true])),
    toolchain: {platform: 'linux-x86_64', python_version: '3.12.3', python_digest: 'sha256:' + 'c'.repeat(64), bwrap_version: 'fixture-only'}, evidence: 'OFFLINE_TEST_DOUBLE'};
  return {...value, receipt_digest: digest(value)};
}
test('profile is bounded and immutable; source/input/binding canonical hashes', () => {
  const r = request(), expected = validateProgramRequest(r);
  assert.equal(PROGRAM_PROFILE.limits.candidate_processes, 1);
  assert.ok(Object.isFrozen(PROGRAM_PROFILE.limits));
  assert.equal(expected.source_files[0].path, 'cli.py');
  assert.equal(expected.stdin_digest, programByteDigest(r.stdin));
  assert.deepEqual(verifyProgramReceipt(fixtureReceipt(r), r).source_files, expected.source_files);
});
for (const [name, mutate] of [
  ['path traversal', r => r.files[0].path = '../normalizer.py'],
  ['host file name', r => r.files[0].path = '/etc/passwd'],
  ['third file/import shadow', r => r.files.push({path: 'json.py', content_utf8: ''})],
  ['duplicate path', r => r.files[0].path = 'cli.py'],
  ['unpaired surrogate', r => r.files[0].content_utf8 = '\ud800'],
  ['source bound', r => r.files[0].content_utf8 = 'x'.repeat(32769)],
  ['stdin bound', r => r.stdin = 'x'.repeat(8193)],
  ['shell entrypoint', r => r.entrypoint = '/bin/sh'],
  ['missing tree pin', r => delete r.binding.tested_tree_sha],
  ['unsafe invocation', r => r.binding.invocation_id = '../other'],
]) test('request rejects ' + name, () => { const r = request(); mutate(r); assert.throws(() => validateProgramRequest(r)); });
for (const [name, mutate] of [
  ['stale head', v => v.tested_head_sha = 'd'.repeat(40)],
  ['stale tree', v => v.tested_tree_sha = 'd'.repeat(40)],
  ['other nonce', v => v.invocation_id = 'other'],
  ['different input', v => v.stdin_digest = 'sha256:' + 'd'.repeat(64)],
  ['source bytes', v => v.source_files[0].bytes++],
  ['namespace missing', v => v.boundary.network_namespace = false],
  ['seccomp missing', v => v.boundary.seccomp_enforced = false],
  ['resource widening', v => v.limits = {...v.limits, candidate_processes: 64}],
  ['forged stdout', v => v.stdout = 'PASS'],
  ['toolchain absent', v => delete v.toolchain.python_digest],
]) test('receipt rejects ' + name + ' even when self-hash is recomputed', () => {
  const r = request(), v = structuredClone(fixtureReceipt(r)); mutate(v); delete v.receipt_digest; v.receipt_digest = digest(v);
  assert.throws(() => verifyProgramReceipt(v, r));
});
