// Read-only proof for the two-file, SHA-1, loose-object pilot repository.
import assert from 'node:assert/strict';
import {readFileSync, lstatSync, realpathSync} from 'node:fs';
import {join, resolve, sep} from 'node:path';
import {inflateSync} from 'node:zlib';
import {gitOid, PATHS, sha256, treeFromFiles} from './tree-proof.mjs';

const oidPattern = /^[a-f0-9]{40}$/;
function read(root, relative, limit) {
  const filename = join(root, ...relative.split('/'));
  assert.ok(filename.startsWith(root + sep));
  assert.equal(realpathSync.native(filename), filename, 'unexpected symbolic link');
  const stat = lstatSync(filename);
  assert.ok(stat.isFile() && stat.size <= limit, 'unexpected file type or size');
  return readFileSync(filename);
}

export function inspectCommittedTrees({repository_root, worktree_root, branch, base_sha, head_sha}) {
  assert.ok(oidPattern.test(base_sha) && oidPattern.test(head_sha));
  assert.match(branch, /^codex\/(?:[a-z0-9_-]{1,24}\/)?[a-z][a-z0-9_.-]{0,79}$/);
  const repo = realpathSync.native(resolve(repository_root));
  const working = realpathSync.native(resolve(worktree_root));
  assert.notEqual(repo, working);
  const git = join(repo, '.git');
  assert.equal(realpathSync.native(git), git);
  assert.equal(read(git, 'refs/heads/main', 80).toString('ascii').trim(), base_sha);
  assert.equal(read(git, 'refs/heads/' + branch, 80).toString('ascii').trim(), head_sha);

  function object(oid, type) {
    assert.match(oid, oidPattern);
    const raw = inflateSync(read(git, 'objects/' + oid.slice(0, 2) + '/' + oid.slice(2), 131072), {maxOutputLength:131072});
    const boundary = raw.indexOf(0);
    assert.ok(boundary > 0 && boundary < 32);
    const body = raw.subarray(boundary + 1);
    assert.equal(raw.subarray(0, boundary).toString('ascii'), type + ' ' + body.length);
    assert.equal(gitOid(type, body), oid);
    return body;
  }

  function snapshot(head) {
    const headers = object(head, 'commit').toString('utf8').split('\n\n', 1)[0].split('\n');
    const trees = headers.filter(line => line.startsWith('tree '));
    assert.equal(trees.length, 1);
    const tree_sha = trees[0].slice(5);
    const data = object(tree_sha, 'tree');
    let offset = 0;
    const files = [];
    while (offset < data.length) {
      const separator = data.indexOf(0, offset);
      assert.ok(separator > offset && separator + 21 <= data.length);
      const match = /^(100644|100755) (cli\.py|normalizer\.py)$/.exec(data.subarray(offset, separator).toString('ascii'));
      assert.ok(match, 'unexpected or unsafe tree entry');
      const [, mode, path] = match;
      const blob_sha = data.subarray(separator+1, separator+21).toString('hex');
      const contents = object(blob_sha,'blob');
      const content_utf8 = new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(contents);
      files.push({path,mode,kind:'file',content_utf8,blob_sha,digest:sha256(contents)});
      offset = separator + 21;
    }
    assert.deepEqual(files.map(file => file.path), PATHS);
    assert.equal(treeFromFiles(files), tree_sha);
    return {head_sha: head, tree_sha, files, parents: headers.filter(line => line.startsWith('parent ')).map(line => line.slice(7))};
  }
  const base = snapshot(base_sha), final = snapshot(head_sha);
  assert.deepEqual(final.parents,[base_sha]);
  for (const file of final.files) assert.equal(sha256(read(working,file.path,65536)),file.digest);
  return {base, final};
}
