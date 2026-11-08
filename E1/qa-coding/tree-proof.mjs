import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';

export const PATHS = Object.freeze(['cli.py', 'normalizer.py']);
export const sha256 = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
export function gitOid(type, bytes) {
  const body = Buffer.from(bytes);
  return createHash('sha1').update(type + ' ' + body.length + '\0').update(body).digest('hex');
}

export function treeFromFiles(files) {
  assert.equal(files.length, PATHS.length, 'unexpected tree size');
  const sorted = [...files].sort((a, b) => Buffer.from(a.path).compare(Buffer.from(b.path)));
  assert.deepEqual(sorted.map(file => file.path), PATHS);
  const entries = sorted.map(file => {
    assert.ok(['100644', '100755'].includes(file.mode));
    assert.equal(typeof file.content_utf8, 'string');
    const bytes = Buffer.from(file.content_utf8, 'utf8');
    assert.equal(bytes.toString('utf8'), file.content_utf8);
    const blob = gitOid('blob', bytes);
    if (file.blob_sha !== undefined) assert.equal(file.blob_sha, blob);
    if (file.digest !== undefined) assert.equal(file.digest, sha256(bytes));
    if (file.kind !== undefined) assert.equal(file.kind, 'file');
    return Buffer.concat([Buffer.from(file.mode + ' ' + file.path + '\0'), Buffer.from(blob, 'hex')]);
  });
  return gitOid('tree', Buffer.concat(entries));
}

export function verifyTrees(trees, proposal, artifact) {
  assert.match(trees.base.head_sha, /^[0-9a-f]{40}$/);
  assert.match(trees.final.head_sha, /^[0-9a-f]{40}$/);
  assert.notEqual(trees.base.head_sha, trees.final.head_sha);
  assert.equal(treeFromFiles(trees.base.files), trees.base.tree_sha);
  assert.equal(treeFromFiles(trees.final.files), trees.final.tree_sha);
  assert.notEqual(trees.base.tree_sha, trees.final.tree_sha);
  assert.equal(proposal.base_sha, trees.base.head_sha);
  assert.equal(artifact.base_sha, trees.base.head_sha);
  assert.equal(artifact.head_sha, trees.final.head_sha);
  assert.deepEqual(proposal.changes.map(change => change.path).sort(), PATHS);
  assert.deepEqual(artifact.patch.changes.map(change => change.path).sort(), PATHS);
  for (const path of PATHS) {
    const before = trees.base.files.find(file => file.path === path);
    const after = trees.final.files.find(file => file.path === path);
    const change = proposal.changes.find(item => item.path === path);
    const verified = artifact.patch.changes.find(item => item.path === path);
    assert.equal(after.mode, before.mode);
    assert.equal(sha256(before.content_utf8), change.before_digest);
    assert.equal(after.content_utf8, change.after_text);
    assert.equal(verified.after_digest, sha256(after.content_utf8));
    assert.equal(verified.before_digest, change.before_digest);
    assert.equal(verified.after_text, change.after_text);
    assert.notEqual(verified.before_digest, verified.after_digest);
  }
}

// QA projections have reproducible tree IDs, but have never been written to Git.
export function diagnosticTree(files, parent, label) {
  const tree = treeFromFiles(files);
  const body = 'tree ' + tree + '\nparent ' + parent + '\nauthor qa <qa@fixture.invalid> 0 +0000\ncommitter qa <qa@fixture.invalid> 0 +0000\n\nQA projection ' + label + '\n';
  return {files, tree_sha: tree, head_sha: gitOid('commit', body), projection: label};
}
