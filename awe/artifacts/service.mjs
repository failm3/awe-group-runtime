import {createHash} from 'node:crypto';
import {validateShape} from '../../contracts/schema-validator.mjs';
import {validate, createValidationContext} from '../../contracts/validate.mjs';
import {canonicalize, digest, hashBytes, fields, parseIntent, copy, freeze, result, need, id, integer,
  projectStamp, sourceFor, liveSubject} from '../memory/boundary.mjs';
import {safePathSet, safePath, decodeBase64, objectKey, regularBytes, immutableWrite} from './paths.mjs';
import {readStoredZip} from './zip.mjs';

const media = new Set(['application/json', 'text/plain', 'application/octet-stream']);
export function fileCatalogue(files) {
  safePathSet(files.map(f => f.path));
  need(files.every(f => Buffer.isBuffer(f.bytes) && f.bytes.length <= 32768 && media.has(f.media_type)));
  need(files.reduce((n, f) => n + f.bytes.length, 0) <= 49152);
  return files.map(f => ({path: f.path, content_hash: hashBytes(f.bytes), bytes: f.bytes.length, media_type: f.media_type}))
    .sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}
export const artifactPayloadHash = files => digest(fileCatalogue(files));

export function createOfflineArtifacts({authority, stores, readers,readCatalogue=null}) {
  need(Array.isArray(stores) && stores.length === 2 && stores[0] !== stores[1]
    && stores[0].storage_id !== stores[1].storage_id);
  need(Array.isArray(readers) && readers.length === 2 && readers[0].reader_id !== readers[1].reader_id
    && readers[0].store !== readers[1].store && readers[0].store.storage_id !== readers[1].store.storage_id
    && readers[0].mode === 'BUFFER' && readers[1].mode === 'CHUNKS');
  stores = Object.freeze([...stores]); readers = Object.freeze(readers.map(r => Object.freeze({...r})));
  const records = new Map(), histories = new Map(), deleted = new Set(), qa = new Map(), pending = new Map();
  let sequence = 0, cacheRevision = 0;
  function finish(v, token, permission, expected) {
    authority.finish(v, token, permission); need(cacheRevision === expected, 'STATE_CHANGED');
  }
  const key = (p, a) => p + '/' + a;
  function recordFor(v, artifactId, version) {
    id(artifactId, 'art'); integer(version, 1); liveSubject(v, 'artifacts', v.project_id, artifactId);
    const k = key(v.project_id, artifactId);
    if(!records.has(k)&&readCatalogue){
      const items=readCatalogue();need(Array.isArray(items)&&!items.then,'STATE_UNAVAILABLE');
      const item=items.find(x=>x.status==='PERSISTED'&&x.record.reference.project_id===v.project_id&&x.record.reference.artifact_id===artifactId&&x.record.version===version);
      need(item&&digest(item.record.manifest.provenance)===digest({source_id:item.source.source_id,source_hash:digest(item.source)}),'NOT_AVAILABLE');
      const restored=freeze(copy(item.record));verifyStore(stores[0],restored);verifyStore(stores[1],restored);
      records.set(k,restored);histories.set(k+'/'+version,restored);
    }
    const r = records.get(k);
    need(r && !deleted.has(k) && r.version === version && r.stamp === v.stamp, 'NOT_AVAILABLE');
    const source = sourceFor(v, {project_id: v.project_id, kind: 'ARTIFACT', subject_id: artifactId,
      version, content_hash: r.payload_hash, provenance: r.manifest.provenance});
    need(source.reader_ids.includes(v.actor_id), 'NOT_AVAILABLE');
    return r;
  }
  function verifyStore(store, r, mode = 'BUFFER') {
    const manifestBytes = regularBytes(store, objectKey(r.reference.project_id, r.reference.content_hash));
    need(hashBytes(manifestBytes) === r.reference.content_hash && manifestBytes.length === r.reference.bytes
      && manifestBytes.toString('utf8') === canonicalize(r.manifest), 'INTEGRITY_FAILURE');
    // Path B uses independent adapter reads plus incremental hashing, not writer's read/ack cache.
    for (const file of r.manifest.files) {
      const bytes = regularBytes(store, objectKey(r.reference.project_id, file.content_hash));
      let actual;
      if (mode === 'CHUNKS') {
        const hasher = createHash('sha256'); for (let i = 0; i < bytes.length; i += 7) hasher.update(bytes.subarray(i, i + 7));
        actual = 'sha256:' + hasher.digest('hex');
      } else actual = hashBytes(bytes);
      need(bytes.length === file.bytes && actual === file.content_hash, 'INTEGRITY_FAILURE');
    }
    return {manifest_hash: r.reference.content_hash, aggregate_hash: r.reference.aggregate_hash,
      file_count: r.manifest.files.length};
  }
  function putFiles(token, text, archive) {
    return result(() => {
      const v = authority.check(token, 'artifact.write');
      const localRevision = cacheRevision;
      const x = fields(text, ['artifact_id', 'expected_version', 'provenance', archive ? 'archive_base64' : 'files']);
      id(x.artifact_id, 'art'); integer(x.expected_version, 0, Number.MAX_SAFE_INTEGER - 1);
      let files;
      if (archive) files = readStoredZip(decodeBase64(x.archive_base64, 49152));
      else {
        need(Array.isArray(x.files) && x.files.length > 0 && x.files.length <= 64);
        files = x.files.map(f => { need(f && Object.keys(f).sort().join(',') === 'bytes_base64,media_type,path');
          return {path: f.path, bytes: decodeBase64(f.bytes_base64), media_type: f.media_type}; });
      }
      const catalogue = fileCatalogue(files), payloadHash = digest(catalogue), version = x.expected_version + 1;
      liveSubject(v, 'artifacts', v.project_id, x.artifact_id);
      const k = key(v.project_id, x.artifact_id); need(!deleted.has(k), 'NOT_AVAILABLE');
      if(!records.has(k)&&x.expected_version>0&&readCatalogue){
        const items=readCatalogue();need(Array.isArray(items)&&!items.then,'STATE_UNAVAILABLE');
        const previous=items.find(a=>a.status==='PERSISTED'&&a.record.reference.project_id===v.project_id&&a.record.reference.artifact_id===x.artifact_id&&a.record.version===x.expected_version);
        need(previous,'VERSION_CONFLICT');verifyStore(stores[0],previous.record);verifyStore(stores[1],previous.record);
        records.set(k,freeze(copy(previous.record)));histories.set(k+'/'+x.expected_version,freeze(copy(previous.record)));
      }
      need((records.get(k)?.version ?? 0) === x.expected_version, 'VERSION_CONFLICT');
      const source = sourceFor(v, {project_id: v.project_id, kind: 'ARTIFACT', subject_id: x.artifact_id,
        version, content_hash: payloadHash, provenance: x.provenance});
      need(source.producer_id === v.actor_id && source.reader_ids.includes(v.actor_id), 'PROVENANCE_REJECTED');
      const manifest = freeze({schema_version: '1.0.0', format: 'awe-artifact-manifest-v1', project_id: v.project_id,
        artifact_id: x.artifact_id, version, spec: v.project.spec, epochs: v.project.epochs,
        provenance: x.provenance, files: catalogue});
      const bytes = Buffer.from(canonicalize(manifest)), aggregateHash = hashBytes(bytes);
      const reference = freeze({project_id: v.project_id, artifact_id: x.artifact_id, content_hash: aggregateHash,
        bytes: bytes.length, media_type: 'application/json', aggregate_hash: aggregateHash});
      need(validateShape('artifact-ref', {schema_version: '1.0.0', contract: 'artifact-ref', artifact: reference}).length === 0);
      const r = freeze({manifest, reference, version, payload_hash: payloadHash, stamp: v.stamp, producer_id: v.actor_id,
        previous_manifest_hash: records.get(k)?.reference.content_hash ?? null});
      // Scoped immutable writes only. Failure leaves unreachable objects, never a live partial manifest.
      for (const store of stores) {
        for (const file of files) immutableWrite(store, objectKey(v.project_id, hashBytes(file.bytes)), file.bytes);
        immutableWrite(store, objectKey(v.project_id, aggregateHash), bytes); verifyStore(store, r);
      }
      finish(v, token, 'artifact.write', localRevision);
      need((records.get(k)?.version ?? 0) === x.expected_version && !deleted.has(k), 'VERSION_CONFLICT');
      records.set(k, r); histories.set(k + '/' + version, r); cacheRevision++;
      return {reference: {schema_version: '1.0.0', contract: 'artifact-ref', artifact: reference}, version,
        provenance_hash: manifest.provenance.source_hash};
    });
  }
  const put = (token, text) => putFiles(token, text, false), putZip = (token, text) => putFiles(token, text, true);
  const read = (token, text) => result(() => {
    const v = authority.check(token, 'artifact.read'), localRevision = cacheRevision;
    const x = fields(text, ['artifact_id', 'version', 'path']);
    safePath(x.path); const r = recordFor(v, x.artifact_id, x.version); verifyStore(stores[0], r);
    const f = r.manifest.files.find(f => f.path === x.path); need(f, 'NOT_AVAILABLE');
    const bytes = regularBytes(stores[0], objectKey(v.project_id, f.content_hash));
    need(bytes.length === f.bytes && hashBytes(bytes) === f.content_hash, 'INTEGRITY_FAILURE');
    finish(v, token, 'artifact.read', localRevision); return {artifact: r.reference, version: r.version, path: x.path, bytes_base64: bytes.toString('base64')};
  });
  const tombstone = (token, text) => result(() => {
    const v = authority.check(token, 'artifact.delete'), localRevision = cacheRevision; need(v.actor.role === 'OWNER', 'DENIED');
    const x = fields(text, ['artifact_id', 'expected_version']); id(x.artifact_id, 'art'); integer(x.expected_version, 1);
    const k = key(v.project_id, x.artifact_id); need(records.get(k)?.version === x.expected_version, 'VERSION_CONFLICT');
    finish(v, token, 'artifact.delete', localRevision); deleted.add(k); cacheRevision++; return {status: 'TOMBSTONED'};
  });
  const history = (token, text) => result(() => {
    const v = authority.check(token, 'artifact.audit'), localRevision = cacheRevision;
    need(v.actor.role === 'OWNER', 'DENIED'); const x = fields(text, ['artifact_id']); id(x.artifact_id, 'art');
    const head = records.get(key(v.project_id, x.artifact_id)); need(head, 'NOT_AVAILABLE'); recordFor(v, x.artifact_id, head.version);
    const rows = [...histories.values()].filter(r => r.manifest.project_id === v.project_id && r.reference.artifact_id === x.artifact_id)
      .sort((a, b) => a.version - b.version).map(r => ({version: r.version, artifact: r.reference,
        previous_manifest_hash: r.previous_manifest_hash, provenance_hash: r.manifest.provenance.source_hash}));
    finish(v, token, 'artifact.audit', localRevision); return {versions: rows};
  });
  function validateQa(v, r, evidence) {
    need(['EXAMINER', 'AUDITOR'].includes(evidence.actor?.role) && evidence.actor.identity_id !== r.producer_id
      && evidence.execution_status === 'EXECUTED' && evidence.verdict === 'PASS' && evidence.exit_code === 0
      && digest(evidence.artifact) === digest(r.reference), 'QA_REJECTED');
    const liveRunner = authority.actor(v, evidence.actor.identity_id, v.project_id, 'artifact.qa');
    need(liveRunner.role === evidence.actor.role, 'QA_REJECTED');
    const scope = v.project.qa_scope;
    need(scope && digest([...evidence.criterion_ids].sort()) === digest([...scope.required_criteria].sort()), 'QA_REJECTED');
    const principals = Object.fromEntries(Object.entries(v.state.actors).map(([actorId, a]) => [actorId,
      {role: a.role, projects: Object.keys(a.memberships)}]));
    const ctx = createValidationContext({now: v.now, authenticated_identity_id: evidence.actor.identity_id, principals,
      project_id: v.project_id, task_id: scope.task_id, operation: {id: scope.operation_id},
      epochs: v.project.epochs, spec: v.project.spec, revision: scope.revision,
      aggregate_hash: r.reference.aggregate_hash, artifact_hash: r.reference.content_hash,
      required_criteria: scope.required_criteria, attestations: v.state.qa_attestations});
    need(validate('qa-evidence', evidence, ctx).ok, 'QA_REJECTED');
    // Logs are actual current objects in this synthetic CAS, not unchecked placeholder refs.
    for (const ref of [evidence.stdout_ref, evidence.stderr_ref]) {
      const log = records.get(key(v.project_id, ref?.artifact_id)); need(log && digest(log.reference) === digest(ref), 'QA_REJECTED');
      recordFor(v, ref.artifact_id, log.version); verifyStore(stores[0], log);
    }
  }
  const pinQa = (token, text) => result(() => {
    const v = authority.check(token, 'artifact.qa'), localRevision = cacheRevision; need(['EXAMINER', 'AUDITOR'].includes(v.actor.role), 'DENIED');
    const x = fields(text, ['artifact_id', 'version', 'evidence']); const r = recordFor(v, x.artifact_id, x.version);
    need(x.evidence.actor?.identity_id === v.actor_id, 'QA_REJECTED'); verifyStore(stores[0], r); validateQa(v, r, x.evidence);
    const qaHash = digest(x.evidence); finish(v, token, 'artifact.qa', localRevision);
    qa.set(qaHash, freeze({artifact_id: x.artifact_id, version: x.version, stamp: v.stamp,
      provenance_hash: r.manifest.provenance.source_hash, evidence: x.evidence})); cacheRevision++;
    return {qa_hash: qaHash, version: r.version};
  });
  function pinned(v, artifactId, version, qaHash) {
    const r = recordFor(v, artifactId, version), q = qa.get(qaHash);
    need(q && q.artifact_id === artifactId && q.version === version && q.stamp === v.stamp
      && q.provenance_hash === r.manifest.provenance.source_hash, 'QA_REJECTED');
    validateQa(v, r, q.evidence); return r;
  }
  const requestReadback = (token, text) => result(() => {
    const v = authority.check(token, 'artifact.readback'), localRevision = cacheRevision;
    const x = fields(text, ['artifact_id', 'version', 'qa_hash']);
    const r = pinned(v, x.artifact_id, x.version, x.qa_hash); verifyStore(stores[0], r);
    const request = freeze({schema_version: '1.0.0', request_id: 'req_readback_' + (++sequence),
      artifact: r.reference, version: r.version, provenance_hash: r.manifest.provenance.source_hash,
      qa_hash: x.qa_hash, project_stamp: v.stamp, requester_id: v.actor_id,
      expires_at: new Date(Date.parse(v.now) + 60000).toISOString()});
    finish(v, token, 'artifact.readback', localRevision); pending.set(request.request_id, {request, used: false}); cacheRevision++; return request;
  });
  const completeReadback = (token, text) => result(() => {
    const v = authority.check(token, 'artifact.readback'); const x = fields(text, ['request_id']); id(x.request_id, 'req');
    const p = pending.get(x.request_id); need(p && !p.used && p.request.project_stamp === v.stamp
      && p.request.artifact.project_id === v.project_id && p.request.requester_id === v.actor_id
      && p.request.expires_at > v.now, 'READBACK_REJECTED');
    p.used = true; // one attempt, including failure; caller cannot replay arbitrary receipts.
    const localRevision = ++cacheRevision;
    const request = p.request, r = pinned(v, request.artifact.artifact_id, request.version, request.qa_hash);
    need(digest(r.reference) === digest(request.artifact) && r.manifest.provenance.source_hash === request.provenance_hash, 'READBACK_REJECTED');
    const receipts = readers.map(reader => {
      id(reader.reader_id, 'act'); need(reader.reader_id !== r.producer_id && reader.reader_id !== v.actor_id, 'READBACK_REJECTED');
      const actor = authority.actor(v, reader.reader_id, v.project_id, 'artifact.readback.verify');
      const readerView = {...v, actor_id: reader.reader_id, actor};
      recordFor(readerView, r.reference.artifact_id, r.version);
      need(reader.reader_id !== qa.get(request.qa_hash).evidence.actor.identity_id, 'READBACK_REJECTED');
      validateQa(readerView, r, qa.get(request.qa_hash).evidence);
      return {reader_id: reader.reader_id, storage_id: reader.store.storage_id, mode: reader.mode,
        request_hash: digest(request), ...verifyStore(reader.store, r, reader.mode)};
    });
    // Re-read current authority/ACL/attestation after all adapter calls. Never write D03/checkpoint/COMPLETE.
    finish(v, token, 'artifact.readback', localRevision);
    return {status: 'VERIFIED_E0_READBACK', request_hash: digest(request), artifact: r.reference,
      version: r.version, qa_hash: request.qa_hash, provenance_hash: request.provenance_hash, receipts,
      physical_effect_authority: false, independent_acceptance: false};
  });
  return Object.freeze({put, putZip, read, tombstone, history, pinQa, requestReadback, completeReadback});
}
