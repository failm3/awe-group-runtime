import assert from 'node:assert/strict';
import {readFileSync, readdirSync, lstatSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';

export const BASE_SHA = '3abee561ae97428680a4fe5826b0f40ae676319a';
export const BASE_MANIFEST_SHA = 'ee21d139b231b56be77b2f68a3d81df0fdce3cdf8b0bd6c44fd24992e36b8467';
export const root = fileURLToPath(new URL('../../', import.meta.url));
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const owned = path => /^(awe\/policy\/|awe\/sandbox\/|tests\/security\/)/.test(path);
export function inventory(prefix = '') {
  const entries = [];
  for (const name of readdirSync(join(root, prefix)).sort()) {
    const path = (prefix ? prefix + '/' : '') + name;
    if (path === '.git' || path === 'baseline/evidence' || path === 'tests/security/evidence') continue;
    const stat = lstatSync(join(root, path));
    assert(!stat.isSymbolicLink(), 'Symlink/junction not allowed in package: ' + path);
    if (stat.isDirectory()) entries.push(...inventory(path));
    else {
      assert(stat.isFile(), 'Regular package file required: ' + path);
      entries.push({path, bytes: stat.size, sha256: sha256(readFileSync(join(root, path)))});
    }
  }
  return entries;
}
export function checkPackage() {
  const manifestBytes = readFileSync(join(root, 'baseline/release-manifest.json'));
  assert.equal(sha256(manifestBytes), BASE_MANIFEST_SHA, 'D-01 manifest changed');
  const manifest = JSON.parse(manifestBytes), all = inventory();
  const protectedPaths = new Set([...manifest.entries.map(e => e.path), 'baseline/release-manifest.json']);
  for (const expected of manifest.entries) {
    const actual = all.find(e => e.path === expected.path);
    assert.deepEqual(actual, expected, 'Frozen D-01 bytes changed: ' + expected.path);
  }
  for (const entry of all) {
    assert(protectedPaths.has(entry.path) || owned(entry.path), 'Outside D-02 ownership: ' + entry.path);
    if (entry.path.startsWith('awe/') && entry.path.endsWith('.mjs')) {
      const source = readFileSync(join(root, entry.path), 'utf8');
      assert(!/['"]node:(?:net|tls|https?|http2|dns|dgram|child_process)['"]/.test(source), 'Host effect import: ' + entry.path);
    }
  }
  assert.equal(process.versions.node, '24.21.0', 'Exact installed D-01 Node required');
  return {status: 'PASS', base_sha: BASE_SHA, baseline_manifest_sha256: BASE_MANIFEST_SHA,
    protected_d01_files: manifest.entries.length, unchanged_d01_bytes: true,
    d02_source_files: all.filter(e => owned(e.path)).length, additional_dependencies: 0,
    boundary: 'D-02 additive scope check; frozen D-01 checker intentionally unchanged'};
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) console.log(JSON.stringify(checkPackage()));
