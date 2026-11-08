import {createHash} from 'node:crypto';
import {digest, immutable, need, exact} from '../../contracts/index.mjs';

// New bounded program profile. The existing score-only profile is unchanged.
// This is deliberately a two-file, no-dependency pilot, not arbitrary shell.
export const PROGRAM_PROFILE = immutable({
  schema: 'awe.e1.program-profile/1',
  profile_id: 'python-stdlib-two-file-single-process',
  version: '1.0.0',
  platform: 'linux-x86_64',
  files: ['cli.py', 'normalizer.py'],
  entrypoints: ['cli.py', 'library-probe.py'],
  cwd: '/work',
  network: 'DENY',
  process_policy: 'SECCOMP_NO_FORK_CLONE_EXEC',
  limits: {source_bytes: 32768, stdin_bytes: 8192, stdout_bytes: 16384, stderr_bytes: 4096,
    address_space_bytes: 268435456, cpu_seconds: 2, wall_seconds: 5,
    tmpfs_bytes: 16777216, file_bytes: 1048576, open_fds: 32, candidate_processes: 1},
});
export const PROGRAM_PROFILE_DIGEST = digest(PROGRAM_PROFILE);
export const programProfileDigest = PROGRAM_PROFILE_DIGEST;
const SHA = /^[a-f0-9]{40}$/;
const byteDigest = text => 'sha256:' + createHash('sha256').update(text, 'utf8').digest('hex');

export function validateProgramRequest(request) {
  exact(request, ['files', 'stdin', 'entrypoint', 'binding']);
  need(Array.isArray(request.files) && request.files.length === PROGRAM_PROFILE.files.length, 'PROGRAM_FILES');
  const seen = new Set(); let size = 0;
  const files = request.files.map(file => {
    exact(file, ['path', 'content_utf8']);
    need(PROGRAM_PROFILE.files.includes(file.path) && !seen.has(file.path), 'PROGRAM_PATH_DENIED'); seen.add(file.path);
    need(typeof file.content_utf8 === 'string' && file.content_utf8.isWellFormed() && !file.content_utf8.includes('\0'), 'PROGRAM_ENCODING');
    const bytes = Buffer.byteLength(file.content_utf8); size += bytes;
    need(size <= PROGRAM_PROFILE.limits.source_bytes, 'PROGRAM_SOURCE_BOUND');
    return {...file, digest: byteDigest(file.content_utf8), bytes};
  }).sort((a, b) => a.path.localeCompare(b.path, 'en'));
  need(typeof request.stdin === 'string' && request.stdin.isWellFormed() && Buffer.byteLength(request.stdin) <= PROGRAM_PROFILE.limits.stdin_bytes, 'PROGRAM_INPUT_BOUND');
  need(PROGRAM_PROFILE.entrypoints.includes(request.entrypoint), 'PROGRAM_ENTRYPOINT_DENIED');
  exact(request.binding, ['tested_head_sha', 'tested_tree_sha', 'invocation_id']);
  need(SHA.test(request.binding.tested_head_sha) && SHA.test(request.binding.tested_tree_sha) && typeof request.binding.invocation_id === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/.test(request.binding.invocation_id), 'PROGRAM_BINDING');
  const source_files = files.map(({path, digest, bytes}) => ({path, digest, bytes}));
  return immutable({request, source_files, source_digest: digest(source_files), stdin_digest: byteDigest(request.stdin)});
}
