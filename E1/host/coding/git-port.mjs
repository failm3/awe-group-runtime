import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {digest, immutable, need} from '../../contracts/index.mjs';
import {safeRepositoryPath, assertUnprotected, byteDigest} from '../../executors/coding/contracts.mjs';

const SHA = /^[a-f0-9]{40}$/;
const samePath = (a, b) => process.platform === 'win32' ? path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase() : path.resolve(a) === path.resolve(b);
function directory(value, create = false) {
  need(typeof value === 'string' && path.isAbsolute(value), 'CODING_GIT_DIRECTORY');
  if (create) fs.mkdirSync(value, {recursive: true});
  const st = fs.lstatSync(value);
  need(st.isDirectory() && !st.isSymbolicLink() && samePath(fs.realpathSync(value), value), 'CODING_GIT_DIRECTORY');
  return path.resolve(value);
}
function contained(root, relative, missing = true) {
  safeRepositoryPath(relative);
  const target = path.resolve(root, relative), prefix = root + path.sep;
  need((process.platform === 'win32' ? target.toLowerCase().startsWith(prefix.toLowerCase()) : target.startsWith(prefix)), 'CODING_GIT_PATH_ESCAPE');
  const parts = relative.split('/');
  for (let i = 1; i <= parts.length; i++) {
    const next = path.join(root, ...parts.slice(0, i));
    if (!fs.existsSync(next)) { need(missing, 'CODING_GIT_FILE_MISSING'); continue; }
    const st = fs.lstatSync(next);
    need(!st.isSymbolicLink() && samePath(fs.realpathSync(next), next), 'CODING_GIT_LINK_DENIED');
    if (i < parts.length) need(st.isDirectory(), 'CODING_GIT_ANCESTRY');
    else need(st.isFile() && st.nlink === 1, 'CODING_GIT_HARDLINK_OR_TYPE');
  }
  return target;
}
function jsonRead(filename) {
  const st = fs.lstatSync(filename); need(st.isFile() && !st.isSymbolicLink() && st.nlink === 1 && st.size <= 131072, 'CODING_GIT_JOURNAL_FILE');
  return JSON.parse(fs.readFileSync(filename, 'utf8'));
}
function atomicJson(filename, value) {
  const temporary = filename + '.tmp';
  if (fs.existsSync(temporary)) need(fs.lstatSync(temporary).isFile() && !fs.lstatSync(temporary).isSymbolicLink() && fs.lstatSync(temporary).nlink === 1, 'CODING_GIT_JOURNAL_FILE');
  fs.writeFileSync(temporary, JSON.stringify(value, null, 2) + '\n', {mode: 0o600});
  fs.renameSync(temporary, filename);
}

/** Host-only port. It never executes candidate code, accepts shell commands,
 * fetches a remote, edits the runtime repository, or runs commit hooks.
 * Per-file rename is journalled; interrupted multi-file application is detected
 * and reconciled against the immutable before/after bytes, never guessed. */
export function createGitPort({repositoryRoot, worktreesRoot, journalRoot, repository, allowedPaths, readPaths = allowedPaths, hostProtectedRoots = [], clock = () => new Date().toISOString(), faultInjector = null}) {
  repositoryRoot = directory(repositoryRoot); worktreesRoot = directory(worktreesRoot, true); journalRoot = directory(journalRoot, true);
  need(!samePath(repositoryRoot, worktreesRoot) && !samePath(repositoryRoot, journalRoot) && !worktreesRoot.startsWith(repositoryRoot + path.sep) && !journalRoot.startsWith(repositoryRoot + path.sep), 'CODING_GIT_ROOT_OVERLAP');
  need(Array.isArray(allowedPaths) && allowedPaths.length > 0 && allowedPaths.length <= 32 && new Set(allowedPaths.map(p => p.toLowerCase())).size === allowedPaths.length, 'CODING_GIT_ALLOWLIST');
  allowedPaths.forEach(p => assertUnprotected(p, hostProtectedRoots));
  need(Array.isArray(readPaths) && readPaths.length > 0 && readPaths.length <= 32 && new Set(readPaths.map(p => p.toLowerCase())).size === readPaths.length && allowedPaths.every(p => readPaths.includes(p)), 'CODING_GIT_READ_ALLOWLIST');
  readPaths.forEach(p => assertUnprotected(p, hostProtectedRoots));
  const emptyConfig = path.join(journalRoot, 'empty-git-config');
  if (!fs.existsSync(emptyConfig)) fs.writeFileSync(emptyConfig, '', {flag: 'wx'});
  need(fs.lstatSync(emptyConfig).isFile() && !fs.lstatSync(emptyConfig).isSymbolicLink() && fs.readFileSync(emptyConfig).length === 0, 'CODING_GIT_CONFIG');
  const emptyHooks = directory(path.join(journalRoot, 'empty-hooks'), true);
  need(fs.readdirSync(emptyHooks).length === 0, 'CODING_GIT_HOOKS');
  const env = Object.fromEntries(['SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP'].filter(k => process.env[k]).map(k => [k, process.env[k]]));
  Object.assign(env, {GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: emptyConfig, GIT_NO_REPLACE_OBJECTS: '1', GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0'});
  const git = (args, cwd = repositoryRoot, binary = false) => execFileSync('git', ['-c', 'core.hooksPath=' + emptyHooks, '-c', 'core.autocrlf=false', '-c', 'core.fsmonitor=false', '-c', 'commit.gpgSign=false', '-c', 'protocol.allow=never', '-c', 'user.name=AWE Synthetic Coding', '-c', 'user.email=fixture@localhost.invalid', ...args], {cwd, env, windowsHide: true, encoding: binary ? null : 'utf8', maxBuffer: 1048576, timeout: 15000, stdio: ['ignore', 'pipe', 'pipe']});
  const text = (args, cwd) => git(args, cwd).trim();
  need(text(['remote']) === '' && text(['status', '--porcelain']) === '', 'CODING_GIT_BASE_NOT_DISPOSABLE_CLEAN');
  need(text(['ls-files', '--', '.gitattributes', '.gitmodules']) === '', 'CODING_GIT_FILTER_OR_SUBMODULE');
  const rootHead = text(['rev-parse', 'HEAD']), rootBranch = text(['symbolic-ref', '--short', 'HEAD']);
  need(SHA.test(rootHead), 'CODING_GIT_BASE');
  const assertRoot = () => need(text(['rev-parse', 'HEAD']) === rootHead && text(['symbolic-ref', '--short', 'HEAD']) === rootBranch && text(['status', '--porcelain']) === '' && text(['remote']) === '', 'CODING_GIT_ORIGINAL_CHANGED');
  const checkRepository = value => need(digest(value) === digest(repository), 'CODING_GIT_REPOSITORY_SCOPE');
  const allowed = relative => { assertUnprotected(relative, hostProtectedRoots); need(allowedPaths.includes(relative), 'CODING_GIT_PATH_DENIED'); };
  const readable = relative => { assertUnprotected(relative, hostProtectedRoots); need(readPaths.includes(relative), 'CODING_GIT_READ_PATH_DENIED'); };
  const assertBase = sha => { need(SHA.test(sha) && text(['rev-parse', '--verify', '--end-of-options', sha + '^{commit}']) === sha, 'CODING_GIT_BASE'); };
  const blobFile = (cwd, sha, relative, checkBytes) => {
    readable(relative); const absolute = contained(cwd, relative);
    const entry = git(['ls-tree', '-z', sha, '--', relative], cwd);
    if (!entry) { need(!fs.existsSync(absolute), 'CODING_GIT_UNTRACKED_BASE'); return {path: relative, kind: 'missing', mode: null, content_utf8: null, digest: null, blob_sha: null, ancestry_verified: true, ancestor_symlinks: false}; }
    const match = /^([0-9]{6}) blob ([a-f0-9]{40})\t([^\x00]+)\x00$/.exec(entry);
    need(match && ['100644', '100755'].includes(match[1]) && match[3] === relative, 'CODING_GIT_SYMLINK_OR_TYPE');
    const bytes = git(['cat-file', 'blob', match[2]], cwd, true), content = bytes.toString('utf8');
    need(Buffer.from(content, 'utf8').equals(bytes) && bytes.length <= 65536, 'CODING_GIT_ENCODING_BOUND');
    if (checkBytes) need(fs.existsSync(absolute) && fs.readFileSync(absolute).equals(bytes), 'CODING_GIT_WORKTREE_BLOB_MISMATCH');
    return {path: relative, kind: 'file', mode: match[1], content_utf8: content, digest: byteDigest(content), blob_sha: match[2], ancestry_verified: true, ancestor_symlinks: false};
  };
  const recordPath = id => { need(/^wt_[a-f0-9]{32}$/.test(id), 'CODING_GIT_WORKTREE_ID'); return path.join(journalRoot, id + '.json'); };
  const record = id => {
    const value = jsonRead(recordPath(id)); need(value.worktree_id === id && value.base_sha === rootHead && value.root === path.join(worktreesRoot, id), 'CODING_GIT_WORKTREE_JOURNAL');
    directory(value.root); need(text(['rev-parse', '--show-toplevel'], value.root).replaceAll('\\', '/').toLowerCase() === value.root.replaceAll('\\', '/').toLowerCase(), 'CODING_GIT_WORKTREE_ROOT');
    need(text(['symbolic-ref', '--short', 'HEAD'], value.root) === value.branch, 'CODING_GIT_BRANCH_CHANGED'); return value;
  };
  const save = value => atomicJson(recordPath(value.worktree_id), value);
  const resolveWorktree = worktree_id => {
    assertRoot(); const value = record(worktree_id), head = text(['rev-parse', 'HEAD'], value.root), tree = text(['rev-parse', 'HEAD^{tree}'], value.root);
    need(SHA.test(head) && SHA.test(tree) && text(['status', '--porcelain'], value.root) === '', 'CODING_GIT_DIRTY_READBACK');
    if (head !== value.base_sha) need(text(['rev-parse', 'HEAD^'], value.root) === value.base_sha && value.patch && text(['log', '-1', '--format=%s'], value.root) === 'AWE bounded patch ' + value.patch.patch_digest, 'CODING_GIT_COMMIT_CHAIN');
    const changed = head === value.base_sha ? [] : git(['diff', '--name-only', '-z', value.base_sha, head, '--'], value.root).split('\0').filter(Boolean);
    changed.forEach(allowed);
    need(head === value.base_sha || !value.patch || digest([...changed].sort()) === digest(value.patch.changes.map(c => c.path).sort()), 'CODING_GIT_CHANGED_PATHS');
    const files = changed.map(p => blobFile(value.root, head, p, true));
    if (value.patch) need(files.every(f => value.patch.changes.some(c => c.path === f.path && c.after_digest === f.digest)), 'CODING_GIT_PATCH_READBACK');
    const all_files = readPaths.map(p => blobFile(value.root, head, p, true));
    return immutable({root: value.root, worktree_id, base_sha: value.base_sha, head_sha: head, tree_sha: tree, branch: value.branch, files, all_files});
  };
  return Object.freeze({kind: 'ISOLATED_GIT_WORKTREE_PORT', mode: 'LIVE_SCOPED_HOST', isolation: 'ISOLATED_WORKTREE',
    resolveWorktree,
    async inspectBase({repository: repo, base_sha, paths}) {
      checkRepository(repo); assertRoot(); assertBase(base_sha); need(base_sha === rootHead && digest([...paths].sort()) === digest([...readPaths].sort()), 'CODING_GIT_BASE_SCOPE');
      return immutable({base_sha, tree_sha: text(['rev-parse', base_sha + '^{tree}']), files: paths.map(p => blobFile(repositoryRoot, base_sha, p, true))});
    },
    async createWorktree({repository: repo, base_sha, branch, grant_ref, deadline}) {
      checkRepository(repo); assertRoot(); assertBase(base_sha);
      need(base_sha === rootHead && typeof branch === 'string' && /^codex\/[a-z0-9_/-]{1,100}$/.test(branch) && !branch.includes('..') && typeof grant_ref === 'string' && deadline > clock(), 'CODING_GIT_WORKTREE_SCOPE');
      const worktree_id = 'wt_' + digest({base_sha, branch, grant_ref}).slice(7, 39), filename = recordPath(worktree_id), root = path.join(worktreesRoot, worktree_id);
      let value;
      if (fs.existsSync(filename)) { value = jsonRead(filename); need(value.root === root && value.branch === branch && value.grant_ref === grant_ref && value.base_sha === base_sha, 'CODING_GIT_WORKTREE_CONFLICT'); }
      else { need(!fs.existsSync(root), 'CODING_GIT_WORKTREE_CONFLICT'); value = {schema: 'awe.e1.coding-git-journal/1', worktree_id, root, base_sha, branch, grant_ref, state: 'CREATE_INTENT', patch: null}; save(value); }
      if (!fs.existsSync(root)) git(['worktree', 'add', '-b', branch, root, base_sha]);
      directory(root); need(text(['symbolic-ref', '--short', 'HEAD'], root) === branch, 'CODING_GIT_BRANCH_CHANGED');
      if (value.state === 'CREATE_INTENT') { value.state = 'CREATED'; save(value); }
      assertRoot(); return immutable({isolated: true, base_sha, branch, worktree_id});
    },
    async applyPatch({worktree_id, base_sha, patch, grant_ref, deadline}) {
      assertRoot(); const value = record(worktree_id);
      need(base_sha === value.base_sha && grant_ref === value.grant_ref && deadline > clock(), 'CODING_GIT_PATCH_SCOPE');
      const {patch_digest, ...payload} = patch;
      need(patch_digest === digest(payload) && patch.base_sha === base_sha && Array.isArray(patch.changes) && patch.changes.length > 0 && patch.changes.length <= allowedPaths.length && new Set(patch.changes.map(c => c.path)).size === patch.changes.length, 'CODING_GIT_PATCH_DIGEST');
      for (const change of patch.changes) { allowed(change.path); need(typeof change.after_text === 'string' && byteDigest(change.after_text) === change.after_digest && Buffer.byteLength(change.after_text) <= 65536, 'CODING_GIT_PATCH_BYTES'); }
      need(patch.patch_bytes === patch.changes.reduce((n,c) => n + Buffer.byteLength(c.after_text),0) && patch.patch_bytes <= 32768, 'CODING_GIT_PATCH_BYTES');
      for (const change of patch.changes) { const before = blobFile(repositoryRoot, base_sha, change.path, true); need(change.before_digest === (before.kind === 'missing' ? 'ABSENT' : before.digest), 'CODING_GIT_BEFORE_DIGEST'); }
      if (value.patch) need(value.patch.patch_digest === patch_digest, 'CODING_GIT_PATCH_CONFLICT');
      else { need(text(['rev-parse', 'HEAD'], value.root) === base_sha && text(['status', '--porcelain'], value.root) === '', 'CODING_GIT_PRE_APPLY_DIRTY'); value.patch = patch; value.state = 'APPLY_INTENT'; save(value); }
      if (text(['rev-parse', 'HEAD'], value.root) !== base_sha) {
        const restored = resolveWorktree(worktree_id); value.state = 'COMMITTED'; value.head_sha = restored.head_sha; value.tree_sha = restored.tree_sha; save(value);
        return immutable({patch_digest, head_sha: restored.head_sha, repeated: true});
      }
      // Only before/after bytes in the exact patch may exist after a crash.
      const dirty = git(['diff', '--name-only', '-z', '--'], value.root).split('\0').filter(Boolean);
      const staged = git(['diff', '--cached', '--name-only', '-z', '--'], value.root).split('\0').filter(Boolean);
      const untracked = git(['ls-files', '--others', '--exclude-standard', '-z'], value.root).split('\0').filter(Boolean);
      need([...dirty, ...staged, ...untracked].every(p => patch.changes.some(c => c.path === p)), 'CODING_GIT_UNEXPECTED_MUTATION');
      for (const change of patch.changes) {
        const baseFile = blobFile(repositoryRoot, base_sha, change.path, true);
        need(change.before_digest === (baseFile.kind === 'missing' ? 'ABSENT' : baseFile.digest), 'CODING_GIT_BEFORE_DIGEST');
        const target = contained(value.root, change.path), actual = fs.existsSync(target) ? byteDigest(fs.readFileSync(target, 'utf8')) : 'ABSENT';
        need(actual === change.before_digest || actual === change.after_digest, 'CODING_GIT_PARTIAL_WRITE_CONFLICT');
      }
      for (let i = 0; i < patch.changes.length; i++) {
        const change = patch.changes[i], target = contained(value.root, change.path), stage = path.join(journalRoot, worktree_id + '-stage-' + i);
        if (fs.existsSync(stage)) need(fs.lstatSync(stage).isFile() && !fs.lstatSync(stage).isSymbolicLink() && fs.lstatSync(stage).nlink === 1 && fs.readFileSync(stage, 'utf8') === change.after_text, 'CODING_GIT_STAGE_CONFLICT');
        else fs.writeFileSync(stage, change.after_text, {flag: 'wx', mode: 0o600});
        fs.mkdirSync(path.dirname(target), {recursive: true}); contained(value.root, change.path); fs.renameSync(stage, target);
        if (faultInjector) faultInjector('AFTER_FILE_RENAME', {index: i, worktree_id});
      }
      for (const change of patch.changes) need(byteDigest(fs.readFileSync(contained(value.root, change.path, false), 'utf8')) === change.after_digest, 'CODING_GIT_APPLY_READBACK');
      value.state = 'FILES_APPLIED'; save(value);
      git(['add', '--', ...patch.changes.map(c => c.path)], value.root);
      git(['commit', '-m', 'AWE bounded patch ' + patch_digest], value.root);
      if (faultInjector) faultInjector('AFTER_COMMIT_BEFORE_ACK', {worktree_id});
      const done = resolveWorktree(worktree_id); value.state = 'COMMITTED'; value.head_sha = done.head_sha; value.tree_sha = done.tree_sha; save(value);
      assertRoot(); return immutable({patch_digest, head_sha: done.head_sha, repeated: false});
    },
    async readback({worktree_id, base_sha}) {
      const value = resolveWorktree(worktree_id); need(value.base_sha === base_sha && value.head_sha !== base_sha, 'CODING_GIT_NOT_COMMITTED');
      return immutable({...value, isolated: true, clean: true, committed: true});
    }
  });
}
