import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {SCHEMA_DOCUMENT, CONTRACT_TYPES, digest, schemaDigest} from '../../contracts/index.mjs';
import {createDomainManifest, fixtureSummary} from '../../examples/fixtures.mjs';

test('portable standalone schema/catalog and domain manifests match authoritative contract source', () => {
  const read = relative => JSON.parse(readFileSync(new URL(relative, import.meta.url), 'utf8'));
  assert.deepEqual(read('../../contracts/v1/awe-e1.schema.json'), SCHEMA_DOCUMENT);
  const catalog = read('../../contracts/v1/catalog.json'); assert.equal(catalog.schema_document_digest, digest(SCHEMA_DOCUMENT)); assert.deepEqual(catalog.contracts.map(x => x.type), CONTRACT_TYPES);
  for (const entry of catalog.contracts) assert.equal(entry.schema_digest, schemaDigest(entry.type));
  assert.deepEqual(read('../../examples/career.manifest.json'), createDomainManifest('A')); assert.deepEqual(read('../../examples/product.manifest.json'), createDomainManifest('B'));
  assert.deepEqual(read('../../examples/contract-manifest.json').fixtures, ['A', 'B'].map(fixtureSummary));
});
test('manifest SHA-256 binds exact portable schema and fixture artifact bytes', () => {
  const text = readFileSync(new URL('../../examples/MANIFEST.sha256', import.meta.url), 'utf8');
  for (const line of text.trim().split('\n')) { const [hash, path] = line.split('  '); assert.match(path, /^(contracts\/v1|examples)\/[a-z0-9.-]+$/); const bytes = readFileSync(new URL('../../' + path, import.meta.url)); assert.equal(createHash('sha256').update(bytes).digest('hex'), hash); }
});
