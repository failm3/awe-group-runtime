import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {generateKeyPairSync} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {digest} from '../../contracts/index.mjs';
import {loadPinnedCatalogRepository} from '../../tooling/catalog.mjs';
import {probeInstalledTool, signToolReview, activateToolReview, keyFingerprint} from '../../tooling/review.mjs';
import {TOOL_QUALITY_SUITE_DIGEST} from '../../tooling/profiles.mjs';
import {chooseExecutor} from '../../tooling/policy.mjs';
import {runFixedTextTool} from '../../tooling/local-execution.mjs';
import {createToolDispatcher} from '../../tooling/dispatch.mjs';
import {createCodingMission} from '../../host/coding/mission.mjs';
import {authorityPorts} from '../../mission/authority.mjs';

const enabled = process.env.AWE_TOOLING_NATIVE === '1', options = {skip: !enabled, timeout: 20000};
test('real pinned catalog -> manual bounded review -> two installed utilities; no native A2 proof', options, async () => {
  assert.ok(process.env.AWE_TOOLING_CATALOG, 'host-only catalog path required');
  const catalog = loadPinnedCatalogRepository({filename: process.env.AWE_TOOLING_CATALOG, principal: {tenant_id: 'e1_tool_review', actor_id: 'host_reviewer'}, projectIds: ['e1_tool_review']});
  const home = os.homedir(), rgRoot = path.join(home, 'scoop/apps/ripgrep/current'), rgaRoot = path.join(home, 'scoop/apps/rga/current');
  const rgBinary = path.join(rgRoot, 'rg.exe'), key = generateKeyPairSync('ed25519');
  const now = new Date().toISOString(), expires_at = new Date(Date.now() + 1800000).toISOString(), entries = [], reviews = [], probes = [], binarySets = [];
  for (const [profile_id, catalog_id, root, exe, license] of [
    ['ripgrep-stdin', 'Радар-0673', rgRoot, 'rg.exe', 'LICENSE-MIT'],
    ['ripgrep-all-stdin', 'Радар-0046', rgaRoot, 'rga.exe', 'LICENSE.md'],
  ]) {
    const catalog_record = await catalog.getCatalogRecord('e1_tool_review', catalog_id), binaries = {tool: path.join(root, exe)};
    if (profile_id === 'ripgrep-all-stdin') binaries.rg = rgBinary;
    const probe = probeInstalledTool({profile_id, catalog_record, binaries, distributionManifest: path.join(root, 'scoop-manifest.json'), licenseFile: path.join(root, license), now});
    const review = signToolReview({probe, privateKey: key.privateKey, issued_at: now, expires_at});
    const args = {review, trustedPublicKey: key.publicKey, expectedKeyFingerprint: keyFingerprint(key.publicKey), catalog_record, binaries, now};
    const entry = activateToolReview(args); assert.equal(entry.installed, true); assert.equal(entry.native_dispatch_proven, false);
    const wrongKey = generateKeyPairSync('ed25519');
    assert.throws(() => activateToolReview({...args, trustedPublicKey: wrongKey.publicKey}), /TOOL_REVIEW_SIGNATURE/);
    assert.throws(() => activateToolReview({...args, revoked: true}), /TOOL_REVIEW_INACTIVE/);
    assert.throws(() => activateToolReview({...args, now: expires_at}), /TOOL_REVIEW_INACTIVE/);
    const altered = structuredClone(review); altered.payload.version = 'future';
    assert.throws(() => activateToolReview({...args, review: altered}), /TOOL_REVIEW_SIGNATURE/);
    assert.throws(() => activateToolReview({...args, catalog_record: {...catalog_record, raw_digest: 'sha256:' + '0'.repeat(64)}}), /TOOL_REVIEW_SOURCE/);
    assert.throws(() => runFixedTextTool({profile_id, binaries, pins: probe.binary_pins.map(pin => ({...pin, digest: 'sha256:' + '0'.repeat(64)})), input: {pattern: 'alpha', text: 'alpha\n'}}), /TOOL_BINARY_PIN_MISMATCH/);
    assert.throws(() => runFixedTextTool({profile_id, binaries, pins: probe.binary_pins, input: {pattern: 'alpha', text: 'alpha\n', command: 'unsafe'}}));
    entries.push(entry); reviews.push(review); probes.push(probe); binarySets.push(binaries);
  }
  const request = {capability_id: 'text.literal-search', quality_suite_digest: TOOL_QUALITY_SUITE_DIGEST, min_quality_score: 1000, max_cost_micros: 0, data_class: 'PROJECT', origin: 'PROJECT'};
  // Explicit test-only data grant. It is never presented as a native authority.
  const grant = {evidence: 'OFFLINE_POLICY_GRANT_FIXTURE_NOT_NATIVE', project_id: 'e1_tool_review', mission_id: 'fixture', revoked_at: null, issued_at: now, expires_at, allowed_capabilities: entries.map(entry => entry.descriptor.ref), permissions: ['artifact.read', 'artifact.write'], allowed_data_classes: ['PROJECT'], allowed_origins: ['PROJECT'], allowed_effect_classes: ['NONE'], budget_cap: {currency: 'NONE', amount_micros: '0'}};
  const choice = chooseExecutor({request, candidates: entries, grant, now}); assert.equal(choice.selected.executor_type, 'script');
  const programChoice = chooseExecutor({request, candidates: entries.map(entry => entry.executor_type === 'script' ? {...entry, available: false} : entry), grant, now}); assert.equal(programChoice.selected.executor_type, 'program');
  // Dispatcher fails before any executable when authenticating against a
  // missing/stale native claim; these ports are explicit test doubles.
  let binaryCalls = 0;
  const dispatcher = createToolDispatcher({lookup: () => entries[0], authenticate: () => ({role: 'EXECUTOR', principal_id: 'fixture_worker', project_id: grant.project_id}), coordinator: {project_id: grant.project_id, snapshot: async () => ({project: {project_id: grant.project_id}, tasks: [], leases: [], missions: []}), heartbeat: async () => ({status: 'RENEWED'})}, resolveGrant: () => ({...grant, allowed_principals: ['fixture_worker']}), binaryResolver: () => {binaryCalls++; return binarySets[0];}, clock: () => now});
  await assert.rejects(dispatcher.dispatch({context: {}, scope: {worker_id: 'fixture_worker', mission_id: 'fixture', task_id: 'fixture', fence: '1', plan_digest: 'sha256:' + '0'.repeat(64)}, choice, input: {pattern: 'alpha', text: 'alpha\n'}}), /TOOL_NATIVE_CLAIM_REQUIRED/); assert.equal(binaryCalls, 0);
  // Real installed executable + actual A1 context, but explicitly fake native
  // snapshot/heartbeat. This proves async guard behavior, not native admission.
  const guardRecords = [];
  for (const scenario of ['grant_revoke_during_resolver', 'review_revoke_during_resolver', 'expiry_during_resolver', 'short_execution_window', 'caller_mutation_frozen']) {
    const fixedInput = {pattern: 'alpha', text: 'alpha\nALPHA\n'}, base = createCodingMission({run_id: 'tool_guard_fixture', issue: {repository: {owner: 'fixture', name: 'fixture'}, issue_number: 1, title: 'Engineering fixture', body: 'No native tool task', digest: 'sha256:' + 'f'.repeat(64)}, rubric: {fixture: 'OFFLINE_TEST_DOUBLE'}, now});
    const spec = {...base.spec, requested_capabilities: [entries[0].descriptor.ref]}, originalGrant = {...base.grant, spec_digest: digest(spec), allowed_capabilities: [entries[0].descriptor.ref]};
    let activeGrant = originalGrant, activeEntry = entries[0], currentClock = now, launches = 0;
    const fakeScope = {mission_id: spec.mission_id, task_id: 'tool_fixture', worker_id: 'e1_worker', fence: 1, plan_digest: 'sha256:' + 'f'.repeat(64)};
    const deadline = new Date(Date.parse(now) + 60000).toISOString(), short = new Date(Date.parse(now) + 3500).toISOString();
    const fakeSnapshot = {project: {project_id: spec.project_id}, missions: [{mission_id: spec.mission_id, state: 'ACTIVE', grant_digest: digest(originalGrant), plan_digest: fakeScope.plan_digest, deadline, spec}], tasks: [{mission_id: spec.mission_id, task_id: fakeScope.task_id, is_current: true, state: 'RUNNING', producer_id: 'e1_worker', fence: 1, plan_digest: fakeScope.plan_digest, capability_id: entries[0].descriptor.ref.capability_id, capability_version: entries[0].descriptor.ref.version, deadline, document: {capability: entries[0].descriptor.ref, input: fixedInput, effect: {effect_class: 'NONE'}}}], leases: [{mission_id: spec.mission_id, task_id: fakeScope.task_id, held: false, worker_id: 'e1_worker', fence: 1, expires_at: scenario === 'short_execution_window' ? short : deadline, execution_deadline: scenario === 'short_execution_window' ? short : deadline}]};
    const guardChoice = chooseExecutor({request: {...request, data_class: 'PUBLIC', origin: 'OWNER'}, candidates: [entries[0]], grant: originalGrant, now});
    assert.equal(guardChoice.decision, 'SELECTED');
    const caller = {context: base.contexts.executor, scope: {...fakeScope}, choice: structuredClone(guardChoice), input: {...fixedInput}};
    const heartbeats = [];
    const guarded = createToolDispatcher({lookup: () => activeEntry, authenticate: c => authorityPorts(base.authority).verify(c), coordinator: {project_id: spec.project_id, snapshot: async () => fakeSnapshot, heartbeat: async args => { heartbeats.push(args); return {status: 'RENEWED'}; }}, resolveGrant: () => activeGrant, clock: () => currentClock, launchObserver: () => { launches++; }, binaryResolver: async () => {
      await Promise.resolve();
      if (scenario === 'grant_revoke_during_resolver') activeGrant = {...activeGrant, revoked_at: now};
      if (scenario === 'review_revoke_during_resolver') activeEntry = null;
      if (scenario === 'expiry_during_resolver') currentClock = expires_at;
      if (scenario === 'caller_mutation_frozen') { caller.scope.worker_id = 'other'; caller.input.text = 'beta\n'; caller.choice.selected.ref_digest = 'sha256:' + '0'.repeat(64); }
      return binarySets[0];
    }});
    if (scenario === 'caller_mutation_frozen') {
      const value = await guarded.dispatch(caller); assert.equal(launches, 1); assert.deepEqual(value.result.output, {matches: ['alpha'], count: 1}); assert.ok(heartbeats.every(h => h.worker_id === 'e1_worker' && h.lease_ms === 6000));
    } else {
      await assert.rejects(guarded.dispatch(caller)); assert.equal(launches, 0);
    }
    guardRecords.push({scenario, actual_executable_invocations: launches, native_ports: 'OFFLINE_TEST_DOUBLE', candidate_input_frozen: true});
  }
  const mcp = await catalog.getCatalogRecord('e1_tool_review', 'Радар-2476');
  assert.equal(mcp.verified, 'CANDIDATE');
  const mcpSearch = await catalog.search({project_id: 'e1_tool_review', need: 'MCP', capabilities: ['mcp.server'], text_filter: 'modelcontextprotocol/servers', mode: 'CANDIDATES'});
  assert.ok(mcpSearch.results.every(row => row.permitted === false && row.verified_state === 'CANDIDATE'));
  const report = {schema: 'awe.e1.tooling-native-review/1', status: 'PASS_BOUNDED_INSTALLED_TOOL_REVIEW', checked_at: now, catalog: catalog.source,
    actual_tool_probes: probes, signed_reviews: reviews, review_public_key: key.publicKey.export({format: 'pem', type: 'spki'}), review_key_fingerprint: keyFingerprint(key.publicKey),
    activated_refs: entries.map(entry => entry.descriptor.ref), choices: [{evidence: 'OFFLINE_POLICY_GRANT_FIXTURE_NOT_NATIVE', value: choice}, {evidence: 'OFFLINE_POLICY_GRANT_FIXTURE_NOT_NATIVE', value: programChoice}],
    denied_candidate: {catalog_id: mcp.catalog_id, source_url: mcp.source_url, verified: mcp.verified, installed: 'NOT_VERIFIED', dispatch: 'DENIED_NO_HOST_REVIEW'},
    async_prelaunch_guard_tests: guardRecords, actual_A2_tool_dispatch: 'NOT_RUN', AWE_model_calls: 0, paid_calls: 0, actual_API_cost_micros: 0, installation_performed: false, full_catalog_exported: false, unsafe_effects: 0,
    limitations: ['Source provenance is installed distribution/release metadata; reproducible upstream build attestation NOT_PROVEN', 'Trusted fixed-stdin adapters are not a hostile-code OS sandbox', 'Selection metadata tests do not prove model routing, native tool dispatch or dynamic agents']};
  const output = fileURLToPath(new URL('../../tooling/evidence/INSTALLED-TOOLS.json', import.meta.url)); fs.mkdirSync(path.dirname(output), {recursive: true}); fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
  assert.ok(!JSON.stringify(report).includes(home), 'no personal absolute path exported');
});
