// Derived baseline TEST host scaffolding. Only the D07 store factory is injected.
import assert from 'node:assert/strict';
import {createOfflineAuthority, digest, copy, hashBytes, projectStamp} from '../../awe/memory/boundary.mjs';
import {createOfflineMemory} from '../../awe/memory/service.mjs';
import {createOfflineArtifacts, artifactPayloadHash} from '../../awe/artifacts/service.mjs';
import {objectKey} from '../../awe/artifacts/paths.mjs';
import {crc32} from '../../awe/artifacts/zip.mjs';

export const text = JSON.stringify;
export const must = r => { assert.equal(r.ok, true, JSON.stringify(r)); return r.value; };
export const denied = (r, code) => { assert.equal(r.ok, false, JSON.stringify(r)); if (code) assert.equal(r.code, code); return r; };
export const allPermissions = ['memory.ingest', 'memory.verify', 'memory.read', 'memory.read_shared', 'memory.promote', 'memory.delete', 'memory.audit',
  'artifact.write', 'artifact.read', 'artifact.delete', 'artifact.audit', 'artifact.qa', 'artifact.readback', 'artifact.readback.verify', 'provenance.produce'];

// All data and "filesystem" nodes are created here. No fs, network, personal data or Workspace reads.
export function syntheticStore(storageId) {
  const objects = new Map(), reads = [], writes = []; let fault = null;
  const port = Object.freeze({storage_id: storageId,
    putIfAbsent(key, bytes) {
      writes.push(key); if (fault?.write) return fault.write(key, bytes);
      if (objects.has(key)) return 'EXISTS'; objects.set(key, Buffer.from(bytes)); return 'CREATED';
    },
    read(key) {
      reads.push(key); const entry = {kind: 'file', reparse: false, link_count: 1, canonical_key: key, bytes: objects.has(key) ? Buffer.from(objects.get(key)) : null};
      return fault?.read ? fault.read(key, entry) : entry;
    }});
  return {port, reads, writes, fault(value) { fault = value; }, corrupt(key, bytes) { objects.set(key, Buffer.from(bytes)); },
    remove(key) { objects.delete(key); }, bytes(key) { return Buffer.from(objects.get(key)); }, keys() { return [...objects.keys()].sort(); }};
}

export function fixture({storeFactory=syntheticStore}={}) {
  let now = '2026-11-05T12:00:00.000Z', available = true;
  const project = suffix => ({status: 'READY', revision: 1, restore_pending: false, cancel_requested: false,
    epochs: {policy: 1, auth: 1, stop: 0, owner: 1},
    spec: {spec_id: 'spec_' + suffix, revision: 1, content_hash: digest({synthetic_spec: suffix})},
    qa_scope: {task_id: 'task_' + suffix, operation_id: 'op_' + suffix, revision: 1, required_criteria: ['M14', 'Q01']}});
  const actor = (role, permissions) => ({role, active: true,
    memberships: {prj_alpha: [...permissions], prj_beta: [...permissions]}});
  const world = {schema_version: '1.0.0', authority_revision: 0,
    projects: {prj_alpha: project('alpha'), prj_beta: project('beta')},
    actors: {act_owner: actor('OWNER', allPermissions),
      act_writer: actor('EXECUTOR', ['memory.ingest', 'memory.read', 'artifact.write', 'artifact.read', 'provenance.produce']),
      act_reader: actor('CONTEXT_BUILDER', ['memory.read', 'memory.read_shared', 'artifact.read']),
      act_hidden: actor('CONTEXT_BUILDER', ['memory.read', 'artifact.read']),
      act_verifier: actor('ARTIFACT_SERVICE', ['memory.verify', 'artifact.readback', 'artifact.read']),
      act_examiner: actor('EXAMINER', ['artifact.qa', 'artifact.read']),
      act_auditor: actor('AUDITOR', ['artifact.qa', 'artifact.read']),
      act_readback_a: actor('AUDITOR', ['artifact.readback.verify']),
      act_readback_b: actor('AUDITOR', ['artifact.readback.verify'])},
    sources: {}, promotions: {}, tombstones: {memory: [], artifacts: []}, heads: {memory: {}, artifacts: {}}, qa_attestations: {}};
  const bump = fn => { fn(world); world.authority_revision++; };
  const authority = createOfflineAuthority({readState: () => { if (!available) throw Error('synthetic port unavailable'); return world; }, clock: () => now});
  const memory = createOfflineMemory({authority}), primary = storeFactory('primary'), replica = storeFactory('replica');
  const readers = [{reader_id: 'act_readback_a', store: primary.port, mode: 'BUFFER'},
    {reader_id: 'act_readback_b', store: replica.port, mode: 'CHUNKS'}];
  const artifacts = createOfflineArtifacts({authority, stores: [primary.port, replica.port], readers});
  const session = (actorId = 'act_writer', projectId = 'prj_alpha') => authority.openSession(actorId, projectId);
  let sourceSequence = 0, runSequence = 0;
  function source({projectId = 'prj_alpha', subjectId, kind, version = 1, contentHash, producerId = 'act_writer', ...options}) {
    const sourceId = 'src_fixture_' + (++sourceSequence);
    const body = {source_id: sourceId, project_id: projectId, kind, subject_id: subjectId, version, content_hash: contentHash,
      project_stamp: projectStamp(projectId, world.projects[projectId]), producer_id: producerId,
      status: 'VERIFIED', expires_at: '2026-11-06T12:00:00.000Z', shareable: false, parents: [], reader_ids: Object.keys(world.actors), ...options};
    bump(w => { w.sources[sourceId] = copy(body);
      w.heads[kind === 'MEMORY' ? 'memory' : 'artifacts'][projectId + '/' + subjectId] = {version, source_hash: digest(body)}; });
    return {source_id: sourceId, source_hash: digest(body)};
  }
  function memoryInput(recordId = 'mem_note', value = 'synthetic shared lesson', options = {}) {
    const {projectId = 'prj_alpha', version = 1, ...sourceOptions} = options;
    const provenance = source({projectId, subjectId: recordId, kind: 'MEMORY', version,
      contentHash: hashBytes(Buffer.from(value)), ...sourceOptions});
    return {record_id: recordId, expected_version: version - 1, text: value, expires_at: '2026-11-05T18:00:00.000Z', provenance};
  }
  function stageMemory(recordId, value, options = {}) {
    const projectId = options.projectId ?? 'prj_alpha', input = memoryInput(recordId, value, options);
    must(memory.ingest(session('act_writer', projectId), text(input)));
    must(memory.verify(session('act_owner', projectId), text({record_id: input.record_id, version: input.expected_version + 1})));
    return input;
  }
  const files = (value = 'synthetic artifact') => [{path: 'site/index.txt', bytes: Buffer.from(value), media_type: 'text/plain'}];
  function artifactInput(artifactId = 'art_site', value = files(), options = {}) {
    const {projectId = 'prj_alpha', version = 1, ...sourceOptions} = options;
    const provenance = source({projectId, subjectId: artifactId, kind: 'ARTIFACT', version,
      contentHash: artifactPayloadHash(value), ...sourceOptions});
    return {artifact_id: artifactId, expected_version: version - 1, provenance,
      files: value.map(f => ({path: f.path, media_type: f.media_type, bytes_base64: f.bytes.toString('base64')}))};
  }
  function stageArtifact(artifactId, value, options = {}) {
    const input = artifactInput(artifactId, value, options);
    const out = must(artifacts.put(session('act_writer', options.projectId ?? 'prj_alpha'), text(input)));
    return {...out, input, files: value ?? files()};
  }
  function evidence(artifact, options = {}) {
    const projectId = artifact.reference.artifact.project_id;
    const runId = 'run_fixture_' + (++runSequence);
    const stdout = stageArtifact('art_stdout_' + runSequence, files('synthetic stdout'), {projectId});
    const stderr = stageArtifact('art_stderr_' + runSequence, files(''), {projectId});
    const p = world.projects[projectId];
    const dto = {schema_version: '1.0.0', contract: 'qa-evidence', request_id: 'req_fixture', correlation_id: 'corr_fixture', causation_id: null,
      actor: {identity_id: 'act_examiner', role: 'EXAMINER'},
      scope: {project_id: projectId, task_id: p.qa_scope.task_id, operation_id: p.qa_scope.operation_id},
      epochs: copy(p.epochs), spec: copy(p.spec), created_at: now, expected_revision: p.qa_scope.revision,
      criterion_ids: [...p.qa_scope.required_criteria], artifact: artifact.reference.artifact,
      profile_hash: digest({fixture: 'profile'}), test_code_hash: digest({fixture: 'test-code'}), input_hash: digest({fixture: 'input'}),
      runner: {identity_id: 'act_examiner', role: 'EXAMINER'}, run_id: runId, environment_version: 'SYNTHETIC_E0_ONLY',
      execution_status: 'EXECUTED', verdict: 'PASS', exit_code: 0,
      stdout_ref: stdout.reference.artifact, stderr_ref: stderr.reference.artifact, producer_attestation: null, reason: null, ...options};
    const body = copy(dto); delete body.producer_attestation;
    dto.producer_attestation = digest({synthetic_receipt: runId});
    bump(w => { w.qa_attestations[runId] = {attestation: dto.producer_attestation, body_hash: digest(body)}; });
    return dto;
  }
  function qaReady(artifact = stageArtifact()) {
    const dto = evidence(artifact), pinned = must(artifacts.pinQa(session('act_examiner', artifact.reference.artifact.project_id),
      text({artifact_id: artifact.reference.artifact.artifact_id, version: artifact.version, evidence: dto})));
    return {artifact, dto, pinned};
  }
  function readback(ready = qaReady(), actorId = 'act_owner') {
    const token = session(actorId, ready.artifact.reference.artifact.project_id);
    const request = must(artifacts.requestReadback(token, text({artifact_id: ready.artifact.reference.artifact.artifact_id,
      version: ready.artifact.version, qa_hash: ready.pinned.qa_hash})));
    return {ready, token, request, complete: () => artifacts.completeReadback(token, text({request_id: request.request_id}))};
  }
  function promotion(input, target = 'prj_beta') {
    const promotionId = 'prom_fixture'; const origin = world.sources[input.provenance.source_id]?.project_id ?? 'prj_alpha';
    const grant = {status: 'APPROVED', source_project: origin, target_project: target, record_id: input.record_id,
      version: input.expected_version + 1, content_hash: hashBytes(Buffer.from(input.text)), provenance_hash: input.provenance.source_hash,
      source_stamp: projectStamp(origin, world.projects[origin]), target_stamp: projectStamp(target, world.projects[target]),
      reader_ids: ['act_reader'], expires_at: '2026-11-05T17:00:00.000Z'};
    bump(w => { w.promotions[promotionId] = grant; });
    return {promotion_id: promotionId};
  }
  return {world, authority, memory, artifacts, primary, replica, readers, bump, session, source, memoryInput, stageMemory,
    files, artifactInput, stageArtifact, evidence, qaReady, readback, promotion,
    setClock(value) { now = value; }, unavailable() { available = false; },
    fileKey: (artifact, index = 0) => objectKey(artifact.reference.artifact.project_id, hashBytes(artifact.files[index].bytes))};
}

// Constructs real ZIP bytes in memory, including central/local headers and CRCs.
export function zip(entries, options = {}) {
  const local = [], central = []; let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.path), data = Buffer.from(entry.value ?? 'synthetic zip file'), crc = crc32(data);
    const l = Buffer.alloc(30); l.writeUInt32LE(0x04034b50); l.writeUInt16LE(20, 4);
    l.writeUInt16LE(entry.flags ?? 0, 6); l.writeUInt16LE(entry.method ?? 0, 8);
    l.writeUInt32LE(crc, 14); l.writeUInt32LE(data.length, 18); l.writeUInt32LE(data.length, 22); l.writeUInt16LE(name.length, 26);
    const c = Buffer.alloc(46); c.writeUInt32LE(0x02014b50); c.writeUInt16LE(0x0314, 4); c.writeUInt16LE(20, 6);
    c.writeUInt16LE(entry.flags ?? 0, 8); c.writeUInt16LE(entry.method ?? 0, 10); c.writeUInt32LE(crc, 16);
    c.writeUInt32LE(data.length, 20); c.writeUInt32LE(data.length, 24); c.writeUInt16LE(name.length, 28);
    c.writeUInt32LE(entry.attr ?? 0x81a40000, 38); c.writeUInt32LE(offset, 42);
    local.push(l, name, data); central.push(c, name); offset += l.length + name.length + data.length;
  }
  const directory = Buffer.concat(central), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  const bytes = Buffer.concat([...local, directory, end]); if (options.mutate) options.mutate(bytes); return bytes;
}
