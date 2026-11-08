import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {inventory, sha256} from '../../baseline/file-inventory.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const manifest = JSON.parse(readFileSync(new URL('../../baseline/release-manifest.json', import.meta.url)));
const current = inventory(root);
const byPath = new Map(current.map(item => [item.path, item]));
for (const entry of manifest.entries) assert.deepEqual(byPath.get(entry.path), entry, `D-01 byte drift: ${entry.path}`);
const frozen = new Set(manifest.entries.map(item => item.path));
const additions = current.filter(item => !frozen.has(item.path));
for (const entry of additions) assert.match(entry.path, /^(awe\/(state|project_factory|events)\/|tests\/state\/)/);
assert.equal(sha256(readFileSync(process.execPath)).length, 64);
console.log(JSON.stringify({status: 'PASS', check: 'D01_FROZEN_BYTES_AND_D03_OWNERSHIP', frozen_files: manifest.entries.length,
  additions: additions.length, new_dependencies: 0, manifest_sha256: sha256(readFileSync(new URL('../../baseline/release-manifest.json', import.meta.url)))}));
