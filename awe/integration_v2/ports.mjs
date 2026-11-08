import {digest, canonicalize} from '../../contracts/canonical.mjs';
import {bytesHash, requireThat as need, copy} from '../context/common.mjs';
export {digest, canonicalize, need, copy};

// There is precisely one accepted formula for each wire field. Never accept either hash interchangeably.
export function normalizeMemoryHit(hit) {
  need(hit && typeof hit.text === 'string' && hit.content_hash === bytesHash(Buffer.from(hit.text, 'utf8'))
    && hit.usage === 'REFERENCE_DATA_ONLY' && hit.origin === 'PROJECT', 'SOURCE_CORRUPT');
  return {id: hit.record_id, version: hit.version, text: hit.text, hash: digest(hit.text),
    raw_utf8_hash: hit.content_hash, provenance_hash: hit.provenance_hash};
}
const unwrap = result => { need(result?.ok === true && !result?.then, 'DEPENDENCY_UNAVAILABLE'); return result.value; };

// One factory per authenticated context principal/task. No worker actor, namespace or ACL input is reused.
export function createSourcePorts({readContext, authority, token, memory, artifacts, bindings}) {
  const descriptors = copy(bindings);
  need(descriptors.length <= 20 && new Set(descriptors.map(d => d.id)).size === descriptors.length, 'REQUEST_INVALID');
  const artifactRefs = new Map();
  function current(permission, query) {
    const state = readContext(); need(state && !state.then, 'DEPENDENCY_UNAVAILABLE');
    const v = authority.check(token, permission);
    need(state.status === 'RUNNING' && state.verified === true && state.restore_pending === false && v.project_id === state.project_id
      && v.actor_id === state.actor_id && v.project.epochs.auth === state.auth_epoch
      && v.project.epochs.policy === state.policy_epoch && digest(v.project.spec) === state.spec_ref, 'PERMISSION_REVOKED');
    need(query.project_id === state.project_id && query.auth_epoch === state.auth_epoch
      && (!Object.hasOwn(query, 'task_id') || query.task_id === state.task_id)
      && (!Object.hasOwn(query, 'role') || query.role === state.role)
      && (!Object.hasOwn(query, 'purpose') || query.purpose === state.purpose), 'SOURCE_DENIED');
    return {state, v};
  }
  function readDescriptor(d, query) {
    const {state, v} = current('memory.read', query);
    need(d.project_id === state.project_id, 'SOURCE_DENIED');
    const hits = unwrap(memory.search(token, JSON.stringify({query: d.query, limit: 20}))).hits;
    const hit = hits.find(h => h.record_id === d.id);
    need(hit, 'SOURCE_UNAVAILABLE');
    const record = normalizeMemoryHit(hit);
    need(record.version === d.version && record.provenance_hash === d.provenance_hash
      && record.raw_utf8_hash === d.raw_utf8_hash, 'SOURCE_STALE');
    authority.finish(v, token, 'memory.read');
    return {...record, project_id: state.project_id, acl_epoch: state.auth_epoch, classification: d.classification,
      current: true, deleted: false, priority: 0};
  }
  const meta = r => { const {text, ...rest} = r; return rest; };
  const memoryPort = Object.freeze({
    list(query) { current('memory.read', query); return descriptors.filter(d => d.project_id === query.project_id).flatMap(d => {
      try { return [meta(readDescriptor(d, query))]; } catch { return []; }
    }); },
    read(query) { const d = descriptors.find(d => d.id === query.id); need(d, 'SOURCE_UNAVAILABLE');
      const r = readDescriptor(d, query); need(query.version === r.version, 'SOURCE_STALE'); return r; },
    metadata(query) { const d = descriptors.find(d => d.id === query.id); if (!d) return null;
      // D05 metadata port has no epoch field: derive it only from the trusted current context.
      return meta(readDescriptor(d, {...query, auth_epoch: readContext().auth_epoch})); }
  });
  function readArtifact(binding, descriptor) {
    const {v: view} = current('artifact.read', binding);
    const head = view.state.heads.artifacts[view.project_id + '/' + descriptor.artifact.artifact_id];
    need(head?.version === descriptor.version && head.source_hash === descriptor.provenance_hash, 'ARTIFACT_UNAVAILABLE');
    const v = unwrap(artifacts.read(token, JSON.stringify({artifact_id: descriptor.artifact.artifact_id,
      version: descriptor.version, path: descriptor.path})));
    need(digest(v.artifact) === digest(descriptor.artifact) && v.version === descriptor.version && v.path === descriptor.path, 'ARTIFACT_UNAVAILABLE');
    const bytes = Buffer.from(v.bytes_base64, 'base64');
    need(bytes.toString('base64') === v.bytes_base64 && bytes.length === descriptor.bytes
      && bytesHash(bytes) === descriptor.raw_utf8_hash, 'ARTIFACT_UNAVAILABLE');
    authority.finish(view, token, 'artifact.read');
    return bytes;
  }
  return Object.freeze({memory: memoryPort,
    artifacts: Object.freeze({get(binding, ref) { const d = artifactRefs.get(ref); need(d, 'ARTIFACT_UNAVAILABLE'); return readArtifact(binding, d); }}),
    // Trusted host registers an exact D07 manifest + file/version/provenance reference, never a bare worker path.
    bindArtifact(descriptor) {
      const d = copy(descriptor), state = readContext();
      need(d.artifact.project_id === state.project_id && Number.isSafeInteger(d.version) && d.version > 0, 'ARTIFACT_UNAVAILABLE');
      const ref = digest({format: 'INT02_D07_FILE_V1', descriptor: d, project_id: state.project_id, task_id: state.task_id, actor_id: state.actor_id});
      readArtifact({project_id: state.project_id, task_id: state.task_id, auth_epoch: state.auth_epoch}, d);
      artifactRefs.set(ref, d); return ref;
    }
  });
}
