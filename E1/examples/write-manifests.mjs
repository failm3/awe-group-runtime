import {mkdirSync, writeFileSync, readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {CONTRACT_VERSION, RELEASE, SCHEMA_DOCUMENT, CONTRACT_TYPES, schemaDigest, digest, capabilityRegistryDigest} from '../contracts/index.mjs';
import {createDomainManifest, fixtureCapabilities, fixtureSummary} from './fixtures.mjs';

// Explicit local artifact generation only; no I/O occurs on module import.
export function writeManifests() {
  const schemaPath = new URL('../contracts/v1/awe-e1.schema.json', import.meta.url);
  const catalogPath = new URL('../contracts/v1/catalog.json', import.meta.url);
  mkdirSync(new URL('../contracts/v1/', import.meta.url), {recursive: true});
  const write = (path, value) => writeFileSync(path, JSON.stringify(value, null, 2) + '\n', 'utf8');
  write(schemaPath, SCHEMA_DOCUMENT);
  write(catalogPath, {contract_version: CONTRACT_VERSION, release: RELEASE, schema_document_digest: digest(SCHEMA_DOCUMENT), contracts: CONTRACT_TYPES.map(type => ({type, local_ref: '#/$defs/' + type, schema_digest: schemaDigest(type)}))});
  const capabilities = fixtureCapabilities(), paths = [schemaPath, catalogPath];
  for (const [kind, filename] of [['A', 'career.manifest.json'], ['B', 'product.manifest.json']]) { const path = new URL(filename, import.meta.url); write(path, createDomainManifest(kind, capabilities)); paths.push(path); }
  const manifestPath = new URL('contract-manifest.json', import.meta.url);
  write(manifestPath, {release: RELEASE, contract_version: CONTRACT_VERSION, mode: 'OFFLINE_CONTRACT_PREFLIGHT_ONLY', schema_document_digest: digest(SCHEMA_DOCUMENT), capability_registry_digest: capabilityRegistryDigest(capabilities), node_required: '24.21.0', fixtures: ['A', 'B'].map(fixtureSummary), accepted: false, effects: 0, execution_authorized: false}); paths.push(manifestPath);
  const lines = paths.map(path => createHash('sha256').update(readFileSync(path)).digest('hex') + '  ' + decodeURIComponent(path.pathname).split('/E1/').at(-1));
  writeFileSync(new URL('MANIFEST.sha256', import.meta.url), lines.join('\n') + '\n', 'utf8');
  return lines;
}
if (process.argv[1] && import.meta.url === new URL('file:///' + process.argv[1].replaceAll('\\', '/')).href) process.stdout.write(writeManifests().join('\n') + '\n');
