import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {digest} from '../../contracts/index.mjs';
import {loadPinnedCatalogRepository} from '../../tooling/catalog.mjs';
import {chooseExecutor} from '../../tooling/policy.mjs';
import {createToolDispatcher} from '../../tooling/dispatch.mjs';
import {signToolReview} from '../../tooling/review.mjs';

const now = '2026-11-08T10:00:00.000Z', before = '2026-11-08T09:00:00.000Z', after = '2026-11-08T11:00:00.000Z', suite = 'sha256:' + '1'.repeat(64);
function fixtures() {
  const candidates = ['script', 'program', 'local_llm', 'cloud_llm'].map((executor_type, i) => ({ref: {capability_id: 'fixture.' + executor_type, manifest_digest: 'sha256:' + String(i).repeat(64)}, executor_type, provides: ['text.literal-search'], permissions: ['artifact.read'], effect_class: 'NONE', installed: true, available: true, health_until: after, quality: {suite_digest: suite, score: 1000, tests: 3, passed: 3}, cost: {basis: 'ACTUAL_API_DEBIT_MICROS', verified: true, currency: 'USD', effective_actual_micros: i}, data_classes: ['PROJECT'], origins: ['PROJECT'], evidence: 'OFFLINE_TEST_DOUBLE'}));
  const grant = {revoked_at: null, issued_at: before, expires_at: after, allowed_capabilities: candidates.map(c => c.ref), permissions: ['artifact.read'], allowed_data_classes: ['PROJECT'], allowed_origins: ['PROJECT'], allowed_effect_classes: ['NONE'], budget_cap: {currency: 'USD', amount_micros: '100'}};
  return {candidates, grant, request: {capability_id: 'text.literal-search', quality_suite_digest: suite, min_quality_score: 1000, max_cost_micros: 100, data_class: 'PROJECT', origin: 'PROJECT'}, now};
}
test('four executor types considered; cheapest proven deterministic script wins and cloud blocked', () => {
  const result = chooseExecutor(fixtures()); assert.equal(result.selected.executor_type, 'script'); assert.equal(result.dispatch_authorized, false);
  assert.ok(result.candidates.find(c => c.executor_type === 'cloud_llm').reasons.includes('CLOUD_FINANCIAL_BINDING_BLOCKED'));
});
test('program can be selected when script is unavailable; no hidden fallback dispatch', () => {
  const f = fixtures(); f.candidates[0].available = false;
  const result = chooseExecutor(f); assert.equal(result.selected.executor_type, 'program');
});
test('local LLM can be selected only with independently supplied eligible metadata; no model call', () => {
  const f = fixtures(); f.candidates[0].available = f.candidates[1].available = false;
  assert.equal(chooseExecutor(f).selected.executor_type, 'local_llm');
});
for (const [name, mutate] of [
  ['unknown price', f => f.candidates.forEach(c => c.cost.verified = false)],
  ['unknown quality', f => f.candidates.forEach(c => delete c.quality)],
  ['missing quality sample count', f => f.candidates.forEach(c => { delete c.quality.tests; delete c.quality.passed; })],
  ['stale health', f => f.candidates.forEach(c => c.health_until = before)],
  ['no grant', f => f.grant = null],
  ['revoked grant', f => f.grant.revoked_at = now],
  ['missing permissions', f => f.grant.permissions = []],
  ['ungranted refs', f => f.grant.allowed_capabilities = []],
  ['data rights', f => f.grant.allowed_data_classes = []],
  ['origin rights', f => f.grant.allowed_origins = []],
  ['effect rights', f => f.grant.allowed_effect_classes = []],
  ['cost cap', f => { f.request.max_cost_micros = 0; f.candidates.forEach(c => c.cost.effective_actual_micros = 1); }],
  ['grant budget cap', f => { f.grant.budget_cap.amount_micros = '0'; f.candidates.forEach(c => c.cost.effective_actual_micros = 1); }],
  ['unknown grant budget', f => delete f.grant.budget_cap],
]) test('policy denies ' + name, () => { const f = fixtures(); mutate(f); assert.equal(chooseExecutor(f).decision, 'BLOCKED'); });
test('catalog search uses old discovery/ranking but never promotes metadata to permitted runtime', async () => {
  const rows = [{id: 'Радар-0673', title: 'BurntSushi/ripgrep', url: 'https://github.com/BurntSushi/ripgrep', description: 'Literal code search', flags: 'manual_topic_review'}, {id: 'Радар-2476', title: 'modelcontextprotocol/servers', url: 'https://github.com/modelcontextprotocol/servers', description: 'MCP servers', flags: 'manual_topic_review'}];
  const raw = Buffer.from(JSON.stringify(rows)), folder = fs.mkdtempSync(path.join(os.tmpdir(), 'awe-catalog-fixture-')), filename = path.join(folder, 'catalog.json'); fs.writeFileSync(filename, raw);
  const config = {filename, principal: {tenant_id: 'fixture', actor_id: 'fixture'}, projectIds: ['fixture'], pin: {schema: 'OFFLINE_TEST_DOUBLE', records: rows.length, bytes: raw.length, sha256: createHash('sha256').update(raw).digest('hex')}, test_label: 'OFFLINE_TEST_DOUBLE'};
  try {
    const catalog = loadPinnedCatalogRepository(config), request = {project_id: 'fixture', need: 'coding', capabilities: ['code.develop'], text_filter: 'ripgrep', mode: 'CANDIDATES', limit: 5};
    const result = await catalog.search(request); assert.equal(result.results.length, 1); assert.equal(result.results[0].verified_state, 'CANDIDATE'); assert.equal(result.results[0].permitted, false); assert.equal(result.physical_decision, 'DENY');
    assert.equal((await catalog.search({...request, mode: 'VERIFIED'})).results.length, 0);
    assert.equal(catalog.source.lifecycle, 'OFFLINE_TEST_DOUBLE');
    await assert.rejects(catalog.search({...request, project_id: 'other'}));
    await assert.rejects(catalog.search({...request, text_filter: ''}));
    assert.throws(() => loadPinnedCatalogRepository({...config, test_label: null}));
    assert.throws(() => loadPinnedCatalogRepository({...config, pin: {...config.pin, sha256: '0'.repeat(64)}}));
  } finally { fs.unlinkSync(filename); fs.rmdirSync(folder); }
});
test('cannot sign a fabricated probe or instantiate dispatch without native host ports', () => {
  assert.throws(() => signToolReview({probe: {verified: true}}), /TOOL_ACTUAL_PROBE_REQUIRED/);
  assert.throws(() => createToolDispatcher({}), /TOOL_NATIVE_HOST_PORTS_REQUIRED/);
});
