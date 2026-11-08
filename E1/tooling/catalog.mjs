import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {createDiscovery, normalizeRequest, rankRecords} from '../../awe/tool_registry/discovery.mjs';
import {classify} from '../../awe/tool_registry/taxonomy.mjs';
import {digest as legacyDigest, urlKey} from '../../awe/tool_registry/common.mjs';
import {digest, immutable, need} from '../contracts/index.mjs';
import {TOOL_PROFILES} from './profiles.mjs';

export const CATALOG_PIN = immutable({schema: 'awe.e1.catalog-source/1', records: 4504, bytes: 5620443, sha256: '5a83c501b290b83a17f6ffaeb0fe9cae772e26be7a6a4c5cbcb948908fc76b56'});
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const clean = value => String(value ?? '').replace(/[\x00-\x1f\x7f<>]/g, '').slice(0, 160);
const profileFor = id => Object.values(TOOL_PROFILES).find(profile => profile.catalog_id === id);

/** Host-only filename, not a search/LLM argument. Reads the existing snapshot
 * once; never refreshes, installs, imports into E0, or exports raw records. */
export function loadPinnedCatalogRepository({filename, principal, projectIds, pin = CATALOG_PIN, test_label = null}) {
  need(typeof filename === 'string' && principal?.tenant_id && principal?.actor_id && Array.isArray(projectIds) && projectIds.length, 'TOOL_CATALOG_HOST_CONFIG');
  const test = digest(pin) !== digest(CATALOG_PIN);
  need(!test || test_label === 'OFFLINE_TEST_DOUBLE', 'TOOL_CATALOG_PIN_OVERRIDE_DENIED');
  let bytes;
  try {
    const stat = fs.lstatSync(filename); need(stat.isFile() && !stat.isSymbolicLink() && stat.size === pin.bytes && stat.size <= 6291456, 'TOOL_CATALOG_FILE');
    bytes = fs.readFileSync(filename); need(bytes.length === pin.bytes && sha(bytes) === pin.sha256, 'TOOL_CATALOG_PIN');
  } catch { throw Object.assign(Error('TOOL_CATALOG_SOURCE_UNAVAILABLE'), {code: 'TOOL_CATALOG_SOURCE_UNAVAILABLE'}); }
  const rows = JSON.parse(bytes.toString('utf8')); need(Array.isArray(rows) && rows.length === pin.records, 'TOOL_CATALOG_COUNT');
  const actor = immutable(principal), allowed = new Set(projectIds), byId = new Map();
  for (const row of rows) { need(row && typeof row.id === 'string' && typeof row.url === 'string' && !byId.has(row.id), 'TOOL_CATALOG_ROW'); byId.set(row.id, row); }
  const authorize = (project, who) => need(allowed.has(project) && digest(who) === digest(actor), 'TOOL_CATALOG_SCOPE');
  function project(row) {
    const key = urlKey(row.url), profile = profileFor(row.id);
    // Exact two reviewed targets receive a host-declared semantic alias only.
    // This never changes CANDIDATE verification/availability/permission state.
    const capabilities = [...new Set([...classify(row).capabilities, ...(profile ? ['code.develop'] : [])])];
    return {tool_id: 'tool_' + sha(key).slice(0, 40), catalog_id: row.id, title: clean(row.title || row.id), source_url: row.url, raw_digest: legacyDigest(row), catalog_digest: 'sha256:' + pin.sha256,
      source_flags: clean(row.flags), capabilities, version: 'UNKNOWN', revision: 1, verified: 'CANDIDATE', available: 'UNKNOWN', cost: {amount_micros: null, currency: null, basis: 'UNKNOWN'}, risk: 'UNKNOWN',
      hazards: classify(row).hazards, disabled: false, compromised: false, platform: [], permitted: false, manual_review_required: true};
  }
  const repository = Object.freeze({
    async search(request, who) {
      const r = normalizeRequest(request); authorize(r.project_id, who);
      // Bounded lazy classification, not another 4504-record classification run.
      // Require a narrowing term; the original catalog remains wholly metadata.
      need(typeof r.text_filter === 'string' && r.text_filter.trim().length >= 2, 'TOOL_CATALOG_NARROW_QUERY_REQUIRED');
      const term = r.text_filter.toLocaleLowerCase('en'), selected = [];
      for (const row of rows) if ([row.id, row.title, row.url].some(value => String(value).toLocaleLowerCase('en').includes(term))) {
        selected.push(project(row)); if (selected.length === 64) break;
      }
      return selected;
    },
    async get(projectId, toolId, who) { authorize(projectId, who); const raw = byId.get(toolId) || rows.find(row => 'tool_' + sha(urlKey(row.url)).slice(0, 40) === toolId); return raw ? immutable(project(raw)) : null; },
  });
  const discovery = createDiscovery({repository, principal: actor});
  return Object.freeze({source: immutable({...pin, full_catalog_exported: false, lifecycle: test ? 'OFFLINE_TEST_DOUBLE' : 'CANDIDATES_ONLY'}), repository,
    async search(request) {
      const r = normalizeRequest(request), result = await discovery.searchCapabilities({...r, mode: 'CANDIDATES'});
      // Explicitly preserve the caller's VERIFIED request: unreviewed catalog
      // metadata never satisfies it, regardless of inferred taxonomy labels.
      return immutable({...result, results: r.mode === 'VERIFIED' ? [] : result.results, verification: 'METADATA_ONLY', max_classified_rows: 64, authority: 'NONE'});
    },
    async getCatalogRecord(projectId, catalogId) { return repository.get(projectId, catalogId, actor); },
    rankReviewedMetadata(rowsToRank, request, now) { return rankRecords(rowsToRank, normalizeRequest(request), now); },
  });
}
