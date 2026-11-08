import assert from 'node:assert/strict';
import {readFileSync, readdirSync, lstatSync} from 'node:fs';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';

export const root = fileURLToPath(new URL('../../', import.meta.url));
export const sha = bytes => createHash('sha256').update(bytes).digest('hex');
export const BASE = '3abee561ae97428680a4fe5826b0f40ae676319a';
export const manifestPath = 'awe/integration/FILE-MANIFEST.json';
const rootDocs = ['INTEGRATION-CONTRACT.md', 'INTEGRATION-REPORT.md', 'INTEGRATION-GATES.md', 'INTEGRATION-CHANGE-REQUESTS.md'];
export function inventory(prefix = '') {
  const entries = [];
  for (const name of readdirSync(join(root, prefix)).sort()) {
    const path = (prefix ? prefix + '/' : '') + name;
    if (path === '.git' || path === 'tests/integration/evidence' || path === manifestPath) continue;
    const stat = lstatSync(join(root, path)); assert(!stat.isSymbolicLink(), 'No links: ' + path);
    if (stat.isDirectory()) entries.push(...inventory(path));
    else { assert(stat.isFile()); entries.push({path, bytes: stat.size, sha256: sha(readFileSync(join(root, path)))}); }
  }
  return entries;
}
export function checkPackage({frozen = true} = {}) {
  assert.equal(process.versions.node, '24.21.0');
  const bytes = readFileSync(join(root, 'baseline/release-manifest.json'));
  assert.equal(sha(bytes), 'ee21d139b231b56be77b2f68a3d81df0fdce3cdf8b0bd6c44fd24992e36b8467');
  const baseline = JSON.parse(bytes).entries, all = inventory(), byPath = new Map(all.map(e => [e.path, e]));
  assert.equal(baseline.length, 90);
  for (const entry of baseline) assert.deepEqual(byPath.get(entry.path), entry, 'D01 drift: ' + entry.path);
  const provenance = JSON.parse(readFileSync(join(root, 'awe/integration/provenance/source-before-copy.json')));
  for (const entry of provenance.entries) assert.deepEqual(byPath.get(entry.path),
    {path: entry.path, bytes: entry.bytes, sha256: entry.sha256}, 'Copied source drift: ' + entry.path);
  const originalPaths = new Set([...baseline.map(e => e.path), 'baseline/release-manifest.json']);
  for (const entry of all) {
    assert(originalPaths.has(entry.path) || entry.path.startsWith('baseline/evidence/')
      || /^(awe\/(policy|sandbox|state|events|project_factory|integration)\/|tests\/(security|state|integration)\/)/.test(entry.path)
      || rootDocs.includes(entry.path), 'Unapproved addition: ' + entry.path);
    // Imported inspect-plan is read-only design tooling, not a runtime/effect adapter.
    if (entry.path.startsWith('awe/') && entry.path.endsWith('.mjs') && entry.path !== 'awe/sandbox/inspect-plan.mjs') {
      const source = readFileSync(join(root, entry.path), 'utf8');
      assert(!/['"]node:(?:fs(?:\/promises)?|net|tls|http|https|http2|dns|dgram|child_process|worker_threads|vm|module)['"]/.test(source),
        'Host effect import: ' + entry.path);
      assert(!/\beval\s*\(|new\s+Function\s*\(|\bimport\s*\(/.test(source), 'Dynamic execution: ' + entry.path);
    }
  }
  if (frozen) assert.deepEqual(all, JSON.parse(readFileSync(join(root, manifestPath))).entries, 'Integration source drift; explicit review/freeze required');
  return {status: 'PASS', base_sha: BASE, frozen_d01_files: baseline.length, copied_files: provenance.entries.length,
    integration_source_files: all.length, dependencies: 0, scope: 'E0_LOCAL_ONLY'};
}
if (process.argv[1] === fileURLToPath(import.meta.url)) console.log(JSON.stringify(checkPackage()));
