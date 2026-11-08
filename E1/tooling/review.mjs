import fs from 'node:fs';
import {createHash, createPublicKey, sign, verify} from 'node:crypto';
import {canonicalize, digest, immutable, need, utc} from '../contracts/index.mjs';
import {toolProfile, toolCapability, TEXT_INPUT_SCHEMA, TEXT_OUTPUT_SCHEMA, TOOL_QUALITY_SUITE, TOOL_QUALITY_SUITE_DIGEST} from './profiles.mjs';
import {filePin, binaryVersion, runFixedTextTool, verifyBinaryPins} from './local-execution.mjs';
import {CATALOG_PIN} from './catalog.mjs';

const probes = new WeakSet(), active = new WeakSet();
export const keyFingerprint = key => 'sha256:' + createHash('sha256').update((key?.type === 'public' ? key : createPublicKey(key)).export({type: 'spki', format: 'der'})).digest('hex');
export function probeInstalledTool({profile_id, catalog_record, binaries, distributionManifest, licenseFile, now = new Date().toISOString()}) {
  const p = toolProfile(profile_id); utc(now);
  need(catalog_record?.catalog_id === p.catalog_id && catalog_record.source_url === p.source_url && catalog_record.catalog_digest === 'sha256:' + CATALOG_PIN.sha256 && catalog_record.verified === 'CANDIDATE' && catalog_record.manual_review_required === true, 'TOOL_CATALOG_REVIEW_SOURCE');
  need(Object.keys(binaries).sort().join(',') === [...p.binary_roles].sort().join(','), 'TOOL_BINARY_ROLES');
  const distribution = JSON.parse(fs.readFileSync(distributionManifest, 'utf8'));
  need(distribution.version === p.version && distribution.homepage === p.source_url && distribution.license === p.license, 'TOOL_DISTRIBUTION_SOURCE');
  const licenseText = fs.readFileSync(licenseFile, 'utf8');
  need(p.license === 'MIT' ? /Permission is hereby granted/.test(licenseText) : /GNU AFFERO GENERAL PUBLIC LICENSE/.test(licenseText), 'TOOL_LICENSE_EVIDENCE');
  const normalizedLicense = Buffer.from(licenseText.replaceAll('\r\n', '\n'), 'utf8');
  const licenseBlob = createHash('sha1').update('blob ' + normalizedLicense.length + '\0').update(normalizedLicense).digest('hex');
  need(licenseBlob === p.license_blob_sha, 'TOOL_UPSTREAM_LICENSE_PIN');
  need(typeof distribution.architecture?.['64bit']?.url === 'string' && distribution.architecture['64bit'].url.startsWith(p.source_url + '/releases/download/') && /^[a-f0-9]{64}$/.test(distribution.architecture['64bit'].hash), 'TOOL_DISTRIBUTION_RELEASE');
  const binary_pins = p.binary_roles.map(role => ({role, ...filePin(binaries[role]), version: binaryVersion(binaries[role])}));
  const rgVersion = /^ripgrep 15\.2\.0(?: \(rev [a-f0-9]{7,40}\))?$/;
  need(profile_id === 'ripgrep-stdin' ? rgVersion.test(binary_pins.find(pin => pin.role === 'tool').version) : binary_pins.find(pin => pin.role === 'tool').version === 'ripgrep-all ' + p.version, 'TOOL_VERSION_MISMATCH');
  if (profile_id === 'ripgrep-all-stdin') need(rgVersion.test(binary_pins.find(pin => pin.role === 'rg').version), 'TOOL_DEPENDENCY_VERSION');
  const test_results = TOOL_QUALITY_SUITE.cases.map((test, index) => {
    const execution = runFixedTextTool({profile_id, binaries, pins: binary_pins, input: test.input});
    need(digest(execution.output) === digest(test.expected), 'TOOL_QUALITY_FAILED');
    return {case_id: 'literal_' + (index + 1), passed: true, execution_digest: digest(execution), input_digest: execution.input_digest, output_digest: execution.output_digest};
  });
  const result = immutable({schema: 'awe.e1.installed-tool-probe/1', profile_id, checked_at: now, binary_pins,
    catalog_ref: {catalog_id: p.catalog_id, source_url: p.source_url, raw_digest: catalog_record.raw_digest, catalog_digest: catalog_record.catalog_digest},
    distribution: {version: distribution.version, homepage: distribution.homepage, manifest_digest: filePin(distributionManifest).digest, archive_url: distribution.architecture['64bit'].url, archive_sha256: distribution.architecture['64bit'].hash, build_attestation: 'NOT_PROVEN'},
    license: {spdx: p.license, evidence_digest: filePin(licenseFile).digest, upstream_url: p.license_source, upstream_blob_sha: licenseBlob, match_normalization: 'CRLF_TO_LF'},
    quality: {suite_id: TOOL_QUALITY_SUITE.suite_id, suite_digest: TOOL_QUALITY_SUITE_DIGEST, tests: test_results.length, passed: test_results.length, score: 1000, scope: 'FOUR_SYNTHETIC_STDIN_CASES_ONLY', test_results},
    manual_topic_review: {resolved_for_profile_only: true, catalog_flag: catalog_record.source_flags, broader_claims_enabled: false},
    native_admission: 'NOT_RUN_HOST_REVIEW_ONLY', installation_performed: false, external_effects: 0});
  probes.add(result); return result;
}

/** A host review signature authorizes registry activation, never owner rights,
 * installation, E0 binding, a DB claim, or spending. */
export function signToolReview({probe, privateKey, issued_at, expires_at}) {
  need(probes.has(probe), 'TOOL_ACTUAL_PROBE_REQUIRED'); utc(issued_at); utc(expires_at);
  need(probe.checked_at <= issued_at && issued_at < expires_at && Date.parse(expires_at) - Date.parse(issued_at) <= 3600000, 'TOOL_REVIEW_EXPIRY');
  const p = toolProfile(probe.profile_id);
  const payload = immutable({schema: 'awe.e1.tool-review/1', profile_id: p.profile_id, source: probe.catalog_ref, distribution: probe.distribution, version: p.version, binary_pins: probe.binary_pins, license: probe.license,
    input_schema_digest: digest(TEXT_INPUT_SCHEMA), output_schema_digest: digest(TEXT_OUTPUT_SCHEMA), permissions: p.permissions, data_classes: ['PUBLIC', 'PROJECT'], origins: ['OWNER', 'PROJECT'], effect_class: 'NONE', platform: p.platform,
    quality: probe.quality, manual_topic_review: probe.manual_topic_review,
    cost: {basis: 'ACTUAL_API_DEBIT_MICROS', effective_actual_micros: 0, currency: 'USD', verified: true, infrastructure_cost: 'NOT_MEASURED'},
    issued_at, expires_at, key_id: keyFingerprint(privateKey), probe_digest: digest(probe), trust_scope: 'HOST_LOCAL_REVIEW_NOT_OWNER_OR_NATIVE_GRANT'});
  return immutable({payload, signature: sign(null, Buffer.from(canonicalize(payload)), privateKey).toString('base64')});
}

export function activateToolReview({review, trustedPublicKey, expectedKeyFingerprint, catalog_record, binaries, now = new Date().toISOString(), revoked = false}) {
  utc(now); const payload = review?.payload;
  need(payload?.schema === 'awe.e1.tool-review/1' && !revoked && payload.issued_at <= now && now < payload.expires_at, 'TOOL_REVIEW_INACTIVE');
  need(keyFingerprint(trustedPublicKey) === expectedKeyFingerprint && payload.key_id === expectedKeyFingerprint && verify(null, Buffer.from(canonicalize(payload)), trustedPublicKey, Buffer.from(review.signature, 'base64')), 'TOOL_REVIEW_SIGNATURE');
  const p = toolProfile(payload.profile_id);
  need(payload.version === p.version && payload.platform === process.platform && payload.source.catalog_id === p.catalog_id && payload.source.source_url === p.source_url && payload.source.raw_digest === catalog_record?.raw_digest && payload.source.catalog_digest === catalog_record?.catalog_digest, 'TOOL_REVIEW_SOURCE');
  need(payload.input_schema_digest === digest(TEXT_INPUT_SCHEMA) && payload.output_schema_digest === digest(TEXT_OUTPUT_SCHEMA) && digest(payload.permissions) === digest(p.permissions) && payload.effect_class === 'NONE', 'TOOL_REVIEW_SCHEMA');
  need(payload.quality.suite_digest === TOOL_QUALITY_SUITE_DIGEST && payload.quality.tests === TOOL_QUALITY_SUITE.cases.length && payload.quality.passed === TOOL_QUALITY_SUITE.cases.length && payload.quality.score === 1000 && payload.manual_topic_review.resolved_for_profile_only === true, 'TOOL_REVIEW_QUALITY');
  verifyBinaryPins(binaries, payload.binary_pins);
  const entry = immutable({schema: 'awe.e1.activated-tool/1', descriptor: toolCapability(payload.profile_id, payload.expires_at), review, review_digest: digest(review), profile_id: payload.profile_id,
    executor_type: p.executor_type, provides: ['text.literal-search'], installed: true, available: true, health_until: payload.expires_at, quality: payload.quality, cost: payload.cost, activation: 'HOST_REVIEWED_PINNED', native_dispatch_proven: false});
  active.add(entry); return entry;
}
export const isActivatedTool = entry => active.has(entry);
