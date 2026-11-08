import {CONTRACT_VERSION, RELEASE, digest, immutable, capabilityManifestDigest, validateCapabilityDescriptor, need} from '../contracts/index.mjs';

export const TEXT_INPUT_SCHEMA = immutable({type: 'object', properties: {pattern: {type: 'string', minLength: 1, maxLength: 128}, text: {type: 'string', maxLength: 8192}}, required: ['pattern', 'text'], additionalProperties: false});
export const TEXT_OUTPUT_SCHEMA = immutable({type: 'object', properties: {matches: {type: 'array', maxItems: 64, items: {type: 'string', maxLength: 256}}, count: {type: 'integer', minimum: 0, maximum: 64}}, required: ['matches', 'count'], additionalProperties: false});
export const TOOL_PROFILES = immutable({
  'ripgrep-stdin': {profile_id: 'ripgrep-stdin', catalog_id: 'Радар-0673', source_url: 'https://github.com/BurntSushi/ripgrep', version: '15.2.0', executor_type: 'script', capability_id: 'e1.tool.ripgrep-stdin', binary_roles: ['tool'], license: 'MIT', license_source: 'https://github.com/BurntSushi/ripgrep/blob/15.2.0/LICENSE-MIT', license_blob_sha: '3b0a5dc09c1e16357459ddc9182a50f360f3cdba', permissions: ['artifact.read', 'artifact.write'], platform: 'win32'},
  'ripgrep-all-stdin': {profile_id: 'ripgrep-all-stdin', catalog_id: 'Радар-0046', source_url: 'https://github.com/phiresky/ripgrep-all', version: '0.10.9', executor_type: 'program', capability_id: 'e1.tool.rga-stdin', binary_roles: ['tool', 'rg'], license: 'AGPL-3.0-or-later', license_source: 'https://github.com/phiresky/ripgrep-all/blob/v0.10.9/LICENSE.md', license_blob_sha: '5de3773c915716c167d3332c0ebd2b4a3a470888', permissions: ['artifact.read', 'artifact.write'], platform: 'win32'},
});
export const TOOL_QUALITY_SUITE = immutable({suite_id: 'e1.tooling.fixed-stdin/2', cases: [
  {input: {pattern: 'alpha', text: 'alpha\nbeta\nalpha beta\n'}, expected: {matches: ['alpha', 'alpha beta'], count: 2}},
  {input: {pattern: '--pre=literal', text: 'a\n--pre=literal\nz\n'}, expected: {matches: ['--pre=literal'], count: 1}},
  {input: {pattern: 'ABSENT', text: 'alpha\nbeta\n'}, expected: {matches: [], count: 0}},
  {input: {pattern: 'alpha', text: 'alpha\nALPHA\nAlpha\n'}, expected: {matches: ['alpha'], count: 1}},
]});
export const TOOL_QUALITY_SUITE_DIGEST = digest(TOOL_QUALITY_SUITE);
export function toolProfile(id) { const profile = TOOL_PROFILES[id]; need(profile, 'TOOL_PROFILE_UNKNOWN'); return profile; }
export function toolCapability(profileId, healthUntil) {
  const p = toolProfile(profileId), binding = (id, schema) => ({schema_id: id, version: '1.0.0', digest: digest(schema)});
  const descriptor = {ref: {contract_version: CONTRACT_VERSION, release: RELEASE, capability_id: p.capability_id, version: '1.0.0', manifest_digest: 'sha256:' + '0'.repeat(64), input_schema: binding('e1.tool.fixed-text.input', TEXT_INPUT_SCHEMA), output_schema: binding('e1.tool.fixed-text.output', TEXT_OUTPUT_SCHEMA)}, executor_kind: p.executor_type, permissions: p.permissions, data_classes: ['PUBLIC', 'PROJECT'], origins: ['OWNER', 'PROJECT'], effect_class: 'NONE', health_until: healthUntil, state: 'ACTIVE', max_attempts: 1, timeout_ms: 15000, min_cost_micros: '0', supports_reconcile: false, input_schema: TEXT_INPUT_SCHEMA, output_schema: TEXT_OUTPUT_SCHEMA};
  descriptor.ref.manifest_digest = capabilityManifestDigest(descriptor);
  return validateCapabilityDescriptor(descriptor);
}
