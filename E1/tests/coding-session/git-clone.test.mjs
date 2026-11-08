import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {prepareRepairRound} from '../../host/coding/repair-session.mjs';

// Explicit host-only test: reads the preserved synthetic G1 repository, clones
// its actual AWE failure into a new temporary repository, never executes code.
test('actual local Git clone/resume preserves old G1 and uses independent objects, no remote', {skip: process.env.AWE_REPAIR_SESSION_NATIVE_GIT !== '1', timeout: 30000}, async t => {
  const root = fileURLToPath(new URL('../../../', import.meta.url)), report = JSON.parse(fs.readFileSync(new URL('../../coding/evidence/g1_normalize_01.json', import.meta.url))), artifact = report.outcome.artifact;
  const privateRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'awe-session-git-')), prefix = fs.realpathSync(privateRoot);
  t.after(() => {
    // This exact mkdtemp-owned tree only. Verify the absolute target and its
    // temporary-root containment before any recursive deletion.
    assert.equal(fs.realpathSync(privateRoot), prefix); assert.equal(path.basename(privateRoot).startsWith('awe-session-git-'), true);
    assert.equal(path.resolve(privateRoot).startsWith(path.resolve(os.tmpdir()) + path.sep), true);
    fs.rmSync(privateRoot, {recursive: true, force: false});
  });
  const source = path.join(root, '.private', 'coding-' + report.run_id, 'repository'), env = {...process.env, GIT_OPTIONAL_LOCKS: '0', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null'};
  const git = (args, cwd) => execFileSync('git', ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=' + path.join(privateRoot, 'no-hooks'), ...args], {cwd, env, encoding: 'utf8', windowsHide: true, timeout: 10000}).trim();
  const originalHead = git(['rev-parse', 'HEAD'], source), originalStatus = git(['status', '--porcelain'], source);
  const args = {task_id: 'code_r02', base_sha: artifact.head_sha, privateRoot, prior: {head_sha: artifact.head_sha}, report, issue: report.issue, readPreviousTask: async () => null};
  const first = await prepareRepairRound(args), second = await prepareRepairRound(args);
  assert.equal(first.repositoryRoot, second.repositoryRoot); assert.equal(first.base_sha, artifact.head_sha); assert.equal(first.tree_sha, artifact.tree_sha);
  assert.equal(git(['symbolic-ref', '--short', 'HEAD'], first.repositoryRoot), 'main'); assert.equal(git(['remote'], first.repositoryRoot), '');
  const baseline = await second.gitPort.inspectBase({repository: report.issue.repository, base_sha: artifact.head_sha, paths: ['normalizer.py', 'cli.py']});
  for (const file of baseline.files) assert.equal(file.content_utf8, artifact.patch.changes.find(change => change.path === file.path).after_text);
  const objects = path.join(first.repositoryRoot, '.git', 'objects');
  function noHardlinks(folder) { for (const entry of fs.readdirSync(folder, {withFileTypes: true})) { const full = path.join(folder, entry.name); assert.equal(fs.lstatSync(full).isSymbolicLink(), false); if (entry.isDirectory()) noHardlinks(full); else assert.equal(fs.lstatSync(full).nlink, 1); } }
  noHardlinks(objects);
  assert.equal(git(['rev-parse', 'HEAD'], source), originalHead); assert.equal(git(['status', '--porcelain'], source), originalStatus);
  await assert.rejects(prepareRepairRound({...args, base_sha: '0'.repeat(40)}), /REPAIR_ROUND_ORIGINAL_BASE/);
});
