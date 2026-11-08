import {createHash} from 'node:crypto';
import {canonicalize, digest} from '../../contracts/canonical.mjs';
import {parseIntent, copy, freeze, requireKeys} from '../policy/json.mjs';

export {canonicalize, digest, parseIntent, copy, freeze, requireKeys};
export const hashBytes = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
export const fail = code => { throw new Error(code); };
export function need(condition, code = 'INVALID_INPUT') { if (!condition) fail(code); }
export function id(value, prefix) {
  need(typeof value === 'string' && new RegExp('^' + prefix + '_[a-z0-9][a-z0-9_-]{0,63}$', 'u').test(value)
    && !value.includes('\n'), 'INVALID_ID');
  return value;
}
export function integer(value, min = 0, max = Number.MAX_SAFE_INTEGER) {
  need(Number.isSafeInteger(value) && !Object.is(value, -0) && value >= min && value <= max); return value;
}
export function time(value) {
  need(typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/u.test(value)
    && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value, 'INVALID_TIME');
  return value;
}
export function hash(value) { need(typeof value === 'string' && /^sha256:[a-f0-9]{64}$/u.test(value) && value.length === 71); return value; }
export function fields(text, keys) { const value = parseIntent(text); requireKeys(value, keys); return value; }
// Stable errors only: no paths, content, counts from hidden projects, or host exceptions.
const errors = new Set(['INVALID_INPUT', 'INVALID_ID', 'INVALID_TIME', 'DENIED', 'STATE_UNAVAILABLE', 'STATE_CHANGED',
  'NOT_AVAILABLE', 'VERSION_CONFLICT', 'PROVENANCE_REJECTED', 'PROMOTION_REJECTED', 'INTEGRITY_FAILURE',
  'UNSAFE_PATH', 'UNSAFE_ARCHIVE', 'UNSUPPORTED_ARCHIVE', 'STORAGE_FAILURE', 'QA_REJECTED', 'READBACK_REJECTED']);
export function result(fn) {
  try { return freeze({ok: true, value: copy(fn())}); }
  catch (error) { return freeze({ok: false, code: errors.has(error?.message) ? error.message : 'INVALID_INPUT'}); }
}
export const projectStamp = (projectId, project) => digest({project_id: projectId, revision: project.revision,
  spec: project.spec, epochs: project.epochs});
const roles = new Set(['OWNER', 'SUPERVISOR', 'EXECUTOR', 'EXAMINER', 'AUDITOR', 'ARTIFACT_SERVICE',
  'ROUTE_BROKER', 'STATE_SERVICE', 'CONTEXT_BUILDER', 'PROJECT_FACTORY']);
const permitted = (actor, projectId, permission) => actor?.active === true && roles.has(actor.role)
  && Array.isArray(actor.memberships?.[projectId]) && actor.memberships[projectId].every(p => typeof p === 'string')
  && actor.memberships[projectId].includes(permission);
const sourceDeadlines=new WeakMap();

// Host-only constructor/issuer. Never expose authority or readState to workers.
// This is an E0 instance-local API guard, not an identity issuer or canonical state writer.
export function createOfflineAuthority({readState, clock,advancingClock=false}) {
  need(typeof readState === 'function' && typeof clock === 'function');
  need(typeof advancingClock==='boolean');
  const sessions = new WeakMap(); let lastClock = null, lastRevision = -1, lastHash = null;
  const observedHeads = new Map(), observedProjects = new Map(), observedTombstones = new Set();
  const revokedSources = new Set(), revokedPromotions = new Set();
  function snapshot() {
    try {
      const raw = readState(); need(raw && typeof raw.then !== 'function', 'STATE_UNAVAILABLE');
      const state = freeze(copy(raw)), now = time(clock());
      requireKeys(state, ['schema_version', 'authority_revision', 'projects', 'actors', 'sources', 'promotions', 'tombstones', 'heads', 'qa_attestations']);
      requireKeys(state.tombstones, ['memory', 'artifacts']); requireKeys(state.heads, ['memory', 'artifacts']);
      need(Array.isArray(state.tombstones.memory) && Array.isArray(state.tombstones.artifacts), 'STATE_UNAVAILABLE');
      integer(state.authority_revision); need(state.schema_version === '1.0.0', 'STATE_UNAVAILABLE');
      const stateHash = digest(state);
      need(state.authority_revision >= lastRevision && (state.authority_revision !== lastRevision || lastHash === stateHash), 'STATE_UNAVAILABLE');
      need(lastClock === null || now >= lastClock, 'STATE_UNAVAILABLE');
      for (const namespace of ['memory', 'artifacts']) {
        for (const [key, old] of observedHeads) if (key.startsWith(namespace + ':')) {
          const head = state.heads[namespace][key.slice(namespace.length + 1)];
          need(head && head.version >= old.version && (head.version !== old.version || head.source_hash === old.source_hash), 'STATE_UNAVAILABLE');
        }
        for (const value of observedTombstones) if (value.startsWith(namespace + ':'))
          need(state.tombstones[namespace].includes(value.slice(namespace.length + 1)), 'STATE_UNAVAILABLE');
      }
      for (const [projectId, old] of observedProjects) {
        const p = state.projects[projectId];
        need(p && p.revision >= old.revision && p.spec.revision >= old.spec.revision
          && Object.keys(old.epochs).every(k => p.epochs[k] >= old.epochs[k])
          && (p.spec.spec_id !== old.spec.spec_id || p.spec.revision !== old.spec.revision || p.spec.content_hash === old.spec.content_hash), 'STATE_UNAVAILABLE');
      }
      for (const sourceId of revokedSources) need(!state.sources[sourceId] || state.sources[sourceId].status === 'REVOKED', 'STATE_UNAVAILABLE');
      for (const promotionId of revokedPromotions) need(!state.promotions[promotionId] || state.promotions[promotionId].status === 'REVOKED', 'STATE_UNAVAILABLE');
      // Instance-local monotonic observations only, not durable anti-rollback or a second state writer.
      for (const namespace of ['memory', 'artifacts']) {
        for (const [key, head] of Object.entries(state.heads[namespace])) {
          integer(head.version, 1); hash(head.source_hash); observedHeads.set(namespace + ':' + key, head);
        }
        for (const value of state.tombstones[namespace]) observedTombstones.add(namespace + ':' + value);
      }
      for (const [key, value] of Object.entries(state.projects)) observedProjects.set(key, value);
      for (const [key, value] of Object.entries(state.sources)) if (value.status === 'REVOKED') revokedSources.add(key);
      for (const [key, value] of Object.entries(state.promotions)) if (value.status === 'REVOKED') revokedPromotions.add(key);
      lastClock = now; lastRevision = state.authority_revision; lastHash = stateHash;
      return {state, now, state_hash: stateHash};
    } catch { fail('STATE_UNAVAILABLE'); }
  }
  function project(view, projectId) {
    const p = view.state.projects?.[projectId];
    need(p?.status === 'READY' && p.restore_pending === false && p.cancel_requested === false, 'DENIED');
    integer(p.revision); id(p.spec?.spec_id, 'spec'); integer(p.spec?.revision, 1); hash(p.spec?.content_hash);
    requireKeys(p.epochs, ['policy', 'auth', 'stop', 'owner']);
    for (const key of ['policy', 'auth', 'owner']) integer(p.epochs[key], 1);
    integer(p.epochs.stop); return p;
  }
  function actor(view, actorId, projectId, permission) {
    const a = view.state.actors?.[actorId];
    need(permitted(a, projectId, permission), 'DENIED');
    return a;
  }
  function openSession(actorId, projectId) {
    id(actorId, 'act'); id(projectId, 'prj'); const view = snapshot(), p = project(view, projectId);
    need(view.state.actors?.[actorId]?.active === true && roles.has(view.state.actors[actorId].role)
      && Array.isArray(view.state.actors[actorId].memberships?.[projectId]), 'DENIED');
    const token = Object.freeze({}); sessions.set(token, {actor_id: actorId, project_id: projectId,
      stamp: projectStamp(projectId, p)}); return token;
  }
  function check(token, permission) {
    const s = sessions.get(token); need(s, 'DENIED'); const view = snapshot();
    const p = project(view, s.project_id), a = actor(view, s.actor_id, s.project_id, permission);
    need(s.stamp === projectStamp(s.project_id, p), 'DENIED');
    return {...view, ...s, project: p, actor: a};
  }
  function finish(view, token, permission) {
    const current = check(token, permission);
    need(current.state_hash === view.state_hash && (advancingClock
      ? current.now>=view.now&&(sourceDeadlines.get(view.state)??'9999-12-31T23:59:59.999Z')>current.now
      : current.now===view.now), 'STATE_CHANGED');
  }
  return Object.freeze({openSession, check, finish, project, actor});
}

export function sourceFor(view, {project_id, kind, subject_id, version, content_hash, provenance}) {
  requireKeys(provenance, ['source_id', 'source_hash']); id(provenance.source_id, 'src'); hash(provenance.source_hash);
  const seen = new Set(); let visited = 0;
  function ancestor(ref, depth) {
    need(depth <= 8 && ++visited <= 64 && !seen.has(ref.source_id), 'PROVENANCE_REJECTED');
    seen.add(ref.source_id); const s = view.state.sources?.[ref.source_id];
    need(s && s.source_id === ref.source_id && digest(s) === ref.source_hash && s.status === 'VERIFIED' && s.project_id === project_id
      && ['MEMORY', 'ARTIFACT'].includes(s.kind) && s.expires_at > view.now && time(s.expires_at)
      && s.project_stamp === projectStamp(project_id, view.state.projects[project_id])
      && typeof s.shareable === 'boolean' && Array.isArray(s.reader_ids) && s.reader_ids.every(a => typeof a === 'string')
      && Array.isArray(s.parents) && s.parents.length <= 8, 'PROVENANCE_REJECTED');
    const deadline=sourceDeadlines.get(view.state);if(!deadline||s.expires_at<deadline)sourceDeadlines.set(view.state,s.expires_at);
    const namespace = s.kind === 'MEMORY' ? 'memory' : 'artifacts';
    const head = view.state.heads[namespace]?.[project_id + '/' + s.subject_id];
    need(head?.version === s.version && head.source_hash === ref.source_hash
      && !view.state.tombstones[namespace].includes(project_id + '/' + s.subject_id), 'PROVENANCE_REJECTED');
    const producer = view.state.actors?.[s.producer_id];
    need(permitted(producer, project_id, 'provenance.produce'), 'PROVENANCE_REJECTED');
    for (const parentRef of s.parents) {
      requireKeys(parentRef, ['source_id', 'source_hash']); const parent = ancestor(parentRef, depth + 1);
      need(s.reader_ids.every(a => parent.reader_ids.includes(a)) && (!s.shareable || parent.shareable), 'PROVENANCE_REJECTED');
    }
    seen.delete(ref.source_id); return s;
  }
  const s = ancestor(provenance, 0);
  need(s.kind === kind && s.subject_id === subject_id && s.version === version && s.content_hash === content_hash, 'PROVENANCE_REJECTED');
  return s;
}
export function liveSubject(view, kind, projectId, subjectId) {
  need(!view.state.tombstones?.[kind]?.includes(projectId + '/' + subjectId), 'NOT_AVAILABLE');
}
