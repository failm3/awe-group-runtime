import {fields, result, need, id, integer, time, hashBytes, digest, canonicalize, copy, freeze, sourceFor,
  projectStamp, liveSubject} from './boundary.mjs';

// Derived, disposable E0 cache. D03 remains the sole canonical state writer.
export function createOfflineMemory({authority}) {
  const records = new Map(), versions = new Map(), deleted = new Set(), shares = new Map();
  const key = (p, r) => p + '/' + r;
  function current(view, projectId, recordId) {
    liveSubject(view, 'memory', projectId, recordId);
    const r = records.get(key(projectId, recordId));
    need(r && !deleted.has(key(projectId, recordId)) && r.status === 'VERIFIED'
      && r.expires_at > view.now, 'NOT_AVAILABLE');
    const p = authority.project(view, projectId);
    need(r.stamp === projectStamp(projectId, p), 'NOT_AVAILABLE');
    const s = sourceFor(view, {project_id: projectId, kind: 'MEMORY', subject_id: recordId, version: r.version,
      content_hash: r.content_hash, provenance: r.provenance});
    return {r, s};
  }
  const ingest = (token, text) => result(() => {
    const v = authority.check(token, 'memory.ingest');
    const x = fields(text, ['record_id', 'expected_version', 'text', 'expires_at', 'provenance']);
    id(x.record_id, 'mem'); integer(x.expected_version, 0, Number.MAX_SAFE_INTEGER - 1); time(x.expires_at);
    need(typeof x.text === 'string' && x.text.length > 0 && Buffer.byteLength(x.text) <= 16384);
    need(x.expires_at > v.now && Date.parse(x.expires_at) - Date.parse(v.now) <= 7 * 86400000);
    const k = key(v.project_id, x.record_id); liveSubject(v, 'memory', v.project_id, x.record_id);
    need(!deleted.has(k), 'NOT_AVAILABLE'); const old = records.get(k);
    need((old?.version ?? 0) === x.expected_version, 'VERSION_CONFLICT');
    const record = freeze({project_id: v.project_id, record_id: x.record_id, version: x.expected_version + 1,
      text: x.text, content_hash: hashBytes(Buffer.from(x.text)), expires_at: x.expires_at,
      provenance: copy(x.provenance), stamp: v.stamp, status: 'QUARANTINED', producer_id: v.actor_id,
      previous_hash: old ? digest(old) : null});
    // Unverified claims are stored as data only; no claim can self-promote.
    authority.finish(v, token, 'memory.ingest'); records.set(k, record); versions.set(k + '/' + record.version, record);
    return {record_id: record.record_id, version: record.version, status: record.status};
  });
  const verify = (token, text) => result(() => {
    const v = authority.check(token, 'memory.verify'); need(['OWNER', 'ARTIFACT_SERVICE'].includes(v.actor.role), 'DENIED');
    const x = fields(text, ['record_id', 'version']); id(x.record_id, 'mem'); integer(x.version, 1);
    const k = key(v.project_id, x.record_id), r = records.get(k); liveSubject(v, 'memory', v.project_id, x.record_id);
    need(r && r.version === x.version && r.status === 'QUARANTINED' && !deleted.has(k)
      && r.stamp === v.stamp && r.expires_at > v.now, 'NOT_AVAILABLE');
    const s = sourceFor(v, {project_id: v.project_id, kind: 'MEMORY', subject_id: r.record_id, version: r.version,
      content_hash: r.content_hash, provenance: r.provenance});
    need(s.producer_id === r.producer_id && r.expires_at <= s.expires_at, 'PROVENANCE_REJECTED');
    authority.finish(v, token, 'memory.verify'); records.set(k, freeze({...r, status: 'VERIFIED'}));
    return {record_id: r.record_id, version: r.version, status: 'VERIFIED'};
  });
  const tombstone = (token, text) => result(() => {
    const v = authority.check(token, 'memory.delete'); need(v.actor.role === 'OWNER', 'DENIED');
    const x = fields(text, ['record_id', 'expected_version']); id(x.record_id, 'mem'); integer(x.expected_version, 1);
    const k = key(v.project_id, x.record_id); need(records.get(k)?.version === x.expected_version, 'VERSION_CONFLICT');
    authority.finish(v, token, 'memory.delete'); deleted.add(k); return {status: 'TOMBSTONED'};
  });
  const promote = (token, text) => result(() => {
    const v = authority.check(token, 'memory.promote'); need(v.actor.role === 'OWNER', 'DENIED');
    const x = fields(text, ['promotion_id']); id(x.promotion_id, 'prom');
    const g = v.state.promotions?.[x.promotion_id];
    need(g?.source_project === v.project_id && g.target_project !== v.project_id, 'PROMOTION_REJECTED');
    const {r, s} = current(v, v.project_id, g.record_id); need(s.shareable === true, 'PROMOTION_REJECTED');
    validateShare(v, g, r); authority.finish(v, token, 'memory.promote');
    shares.set(x.promotion_id, digest(g)); return {status: 'PROMOTED', promotion_id: x.promotion_id};
  });
  function validateShare(v, g, r) {
    need(g.status === 'APPROVED' && g.version === r.version && g.content_hash === r.content_hash
      && g.provenance_hash === r.provenance.source_hash && g.expires_at > v.now && time(g.expires_at)
      && Array.isArray(g.reader_ids) && g.reader_ids.length > 0 && g.source_stamp === r.stamp
      && g.target_stamp === projectStamp(g.target_project, authority.project(v, g.target_project)), 'PROMOTION_REJECTED');
  }
  const search = (token, text) => result(() => {
    const v = authority.check(token, 'memory.read');
    const x = fields(text, ['query', 'limit']); integer(x.limit, 1, 20);
    need(typeof x.query === 'string' && Buffer.byteLength(x.query) <= 512);
    const terms = [...new Set(x.query.toLowerCase().match(/[\p{L}\p{N}_-]+/gu) ?? [])]; need(terms.length > 0 && terms.length <= 32);
    const allowed = [];
    // ACL/provenance/TTL/current version checks precede tokenization, ranking and output construction.
    // No shared corpus statistics, score, hidden count, cache, snippet or generative callback.
    for (const [k, r] of records) {
      if (r.project_id !== v.project_id) continue;
      try { const {s} = current(v, v.project_id, r.record_id); if (s.reader_ids.includes(v.actor_id)) allowed.push({k, r, origin: 'PROJECT'}); }
      catch { /* inaccessible and missing are indistinguishable */ }
    }
    if (v.actor.memberships[v.project_id].includes('memory.read_shared')) for (const [promotionId, grantHash] of shares) {
      const g = v.state.promotions?.[promotionId];
      if (g?.target_project !== v.project_id || !g.reader_ids?.includes(v.actor_id)) continue;
      try {
        need(digest(g) === grantHash); const {r, s} = current(v, g.source_project, g.record_id);
        need(s.shareable === true); validateShare(v, g, r);
        allowed.push({k: promotionId, r, origin: 'PROMOTED', promotion_id: promotionId});
      } catch { /* no stale/cross-project data reaches ranking */ }
    }
    const ranked = allowed.map(a => {
      const tokens = a.r.text.toLowerCase().match(/[\p{L}\p{N}_-]+/gu) ?? [];
      return {...a, score: terms.reduce((n, t) => n + tokens.filter(word => word === t).length, 0)};
    }).filter(a => a.score > 0).sort((a, b) => b.score - a.score || (a.k < b.k ? -1 : a.k > b.k ? 1 : 0));
    const hits = []; let outputBytes = 0;
    for (const a of ranked) {
      const hit = {record_id: a.r.record_id, version: a.r.version, text: a.r.text,
        content_hash: a.r.content_hash, provenance_hash: a.r.provenance.source_hash, origin: a.origin,
        promotion_id: a.promotion_id ?? null, usage: 'REFERENCE_DATA_ONLY'};
      const bytes = Buffer.byteLength(canonicalize(hit)); if (outputBytes + bytes > 49152 || hits.length === x.limit) break;
      hits.push(hit); outputBytes += bytes;
    }
    authority.finish(v, token, 'memory.read'); return {hits};
  });
  const history = (token, text) => result(() => {
    const v = authority.check(token, 'memory.audit'); need(v.actor.role === 'OWNER', 'DENIED');
    const x = fields(text, ['record_id']); id(x.record_id, 'mem');
    const {s} = current(v, v.project_id, x.record_id); need(s.reader_ids.includes(v.actor_id), 'NOT_AVAILABLE');
    const rows = [...versions.values()].filter(r => r.project_id === v.project_id && r.record_id === x.record_id)
      .sort((a, b) => a.version - b.version).map(r => ({version: r.version, content_hash: r.content_hash,
        previous_hash: r.previous_hash, provenance_hash: r.provenance.source_hash}));
    authority.finish(v, token, 'memory.audit'); return {versions: rows};
  });
  return Object.freeze({ingest, verify, tombstone, promote, search, history});
}
