import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createGitPort} from '../../host/coding/git-port.mjs';
import {validatePatchProposal} from '../../executors/coding/contracts.mjs';

test('one-file repair exposes verified unchanged library bytes for whole-program runner', async t => {
  const parent = path.resolve(os.tmpdir()), root = fs.mkdtempSync(path.join(parent, 'awe-whole-tree-'));
  t.after(() => { assert.ok(path.resolve(root).startsWith(parent + path.sep)); fs.rmSync(root, {recursive: true, force: true}); });
  const repo = path.join(root, 'repo'); fs.mkdirSync(repo);
  const git = args => execFileSync('git', ['-c', 'core.autocrlf=false', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@localhost.invalid', ...args], {cwd: repo, encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']}).trim();
  git(['init', '-b', 'main']); fs.writeFileSync(path.join(repo, 'library.txt'), 'unchanged source fixture\n'); fs.writeFileSync(path.join(repo, 'entry.txt'), 'old fixture\n'); git(['add', '--', '.']); git(['commit', '-m', 'Synthetic fixture baseline']);
  const base = git(['rev-parse', 'HEAD']), repository = {owner: 'fixture', name: 'text-fixture'};
  const port = createGitPort({repositoryRoot: repo, worktreesRoot: path.join(root, 'worktrees'), journalRoot: path.join(root, 'journal'), repository, allowedPaths: ['entry.txt', 'library.txt']});
  const baseline = await port.inspectBase({repository, base_sha: base, paths: ['entry.txt', 'library.txt']});
  const patch = validatePatchProposal({base_sha: base, summary: 'Repair only entry fixture', changes: [{path: 'entry.txt', before_digest: baseline.files.find(f => f.path === 'entry.txt').digest, after_text: 'new fixture\n'}]}, {grant: {base_sha: base, max_files: 2, max_patch_bytes: 4096, path_allowlist: ['entry.txt', 'library.txt']}, baseline});
  const deadline = '2099-01-01T00:00:00.000Z';
  const w = await port.createWorktree({repository, base_sha: base, branch: 'codex/whole-tree', grant_ref: 'fixture', deadline});
  await port.applyPatch({worktree_id: w.worktree_id, base_sha: base, patch, grant_ref: 'fixture', deadline});
  const readback = port.resolveWorktree(w.worktree_id);
  assert.equal(readback.files.length, 1); assert.equal(readback.all_files.length, 2);
  assert.equal(readback.all_files.find(f => f.path === 'library.txt').content_utf8, 'unchanged source fixture\n');
  assert.equal(git(['rev-parse', 'HEAD']), base);
});
