import {createHash} from 'node:crypto';
import {digest, immutable, need} from '../../contracts/index.mjs';
import {PROGRAM_PROFILE, PROGRAM_PROFILE_DIGEST, validateProgramRequest} from './profiles.mjs';

const byteDigest = text => 'sha256:' + createHash('sha256').update(text, 'utf8').digest('hex');
export function verifyProgramReceipt(value, request) {
  const expected = validateProgramRequest(request), p = PROGRAM_PROFILE;
  need(value?.schema === 'awe.e1.program-receipt/1' && value.status === 'EXECUTED' && value.sandbox_enforced === true && value.network === 'DENY', 'PROGRAM_RECEIPT_SANDBOX');
  need(value.profile_digest === PROGRAM_PROFILE_DIGEST && digest(value.limits) === digest(p.limits), 'PROGRAM_RECEIPT_PROFILE');
  for (const key of ['tested_head_sha', 'tested_tree_sha', 'invocation_id']) need(value[key] === request.binding[key], 'PROGRAM_RECEIPT_BINDING');
  need(digest(value.source_files) === digest(expected.source_files) && value.source_digest === expected.source_digest && value.stdin_digest === expected.stdin_digest && value.entrypoint === request.entrypoint, 'PROGRAM_RECEIPT_SOURCES');
  need(typeof value.stdout === 'string' && value.stdout.isWellFormed() && Buffer.byteLength(value.stdout) <= p.limits.stdout_bytes && typeof value.stderr === 'string' && value.stderr.isWellFormed() && Buffer.byteLength(value.stderr) <= p.limits.stderr_bytes, 'PROGRAM_RECEIPT_OUTPUT_BOUND');
  need(Number.isSafeInteger(value.exit_code) && value.exit_code >= -128 && value.exit_code <= 255 && typeof value.timed_out === 'boolean' && typeof value.output_truncated === 'boolean' && value.output_digest === digest({stdout: value.stdout, stderr: value.stderr, exit_code: value.exit_code, timed_out: value.timed_out, output_truncated: value.output_truncated}), 'PROGRAM_RECEIPT_OUTPUT');
  need(typeof value.output_encoding_valid === 'boolean' && /^sha256:[a-f0-9]{64}$/.test(value.stdout_bytes_digest) && /^sha256:[a-f0-9]{64}$/.test(value.stderr_bytes_digest), 'PROGRAM_RECEIPT_ENCODING');
  if (value.output_encoding_valid) need(value.stdout_bytes_digest === byteDigest(value.stdout) && value.stderr_bytes_digest === byteDigest(value.stderr), 'PROGRAM_RECEIPT_OUTPUT_BYTES');
  const boundaries = ['home_absent', 'windows_absent', 'repository_absent', 'private_absent', 'source_readonly', 'network_namespace', 'mount_namespace', 'pid_namespace', 'socket_denied', 'fork_denied', 'exec_denied', 'seccomp_enforced', 'no_new_privileges', 'tmpfs_bounded'];
  need(value.boundary && boundaries.every(key => value.boundary[key] === true), 'PROGRAM_RECEIPT_BOUNDARY');
  need(value.toolchain?.platform === 'linux-x86_64' && /^3\.\d+\.\d+$/.test(value.toolchain.python_version) && /^sha256:[a-f0-9]{64}$/.test(value.toolchain.python_digest) && typeof value.toolchain.bwrap_version === 'string' && value.toolchain.bwrap_version.length <= 128, 'PROGRAM_RECEIPT_TOOLCHAIN');
  const {receipt_digest, ...rest} = value;
  need(receipt_digest === digest(rest), 'PROGRAM_RECEIPT_DIGEST');
  return immutable(value);
}

// Exported for trusted host fixture/receipt construction, not verdict authority.
export const programByteDigest = byteDigest;
