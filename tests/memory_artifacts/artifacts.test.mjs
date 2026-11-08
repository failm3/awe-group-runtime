import test from 'node:test';
import assert from 'node:assert/strict';
import {validateShape} from '../../contracts/schema-validator.mjs';
import {digest, hashBytes, canonicalize} from '../../awe/memory/boundary.mjs';
import {objectKey, safePath, safePathSet} from '../../awe/artifacts/paths.mjs';
import {readStoredZip} from '../../awe/artifacts/zip.mjs';
import {fixture, text, must, denied, zip} from './fixtures.mjs';

const read = (f, a, project = a.reference.artifact.project_id) => f.artifacts.read(f.session('act_reader', project),
  text({artifact_id: a.reference.artifact.artifact_id, version: a.version, path: a.files[0].path}));

test('A01 immutable scoped CAS, exact canonical aggregate and valid unchanged D01 DTO', () => {
  const f = fixture(), a = f.stageArtifact(), ref = a.reference.artifact;
  assert.deepEqual(validateShape('artifact-ref', a.reference), []);
  const raw = f.primary.bytes(objectKey('prj_alpha', ref.content_hash));
  const manifest = JSON.parse(raw); assert.equal(raw.toString(), canonicalize(manifest)); assert.equal(hashBytes(raw), ref.aggregate_hash);
  assert.equal(manifest.files[0].content_hash, hashBytes(a.files[0].bytes)); assert.equal(manifest.version, 1);
  assert.equal(Buffer.from(must(read(f, a)).bytes_base64, 'base64').toString(), a.files[0].bytes.toString());
  assert(f.primary.keys().every(key => key.startsWith('prj_alpha/objects/')));
  assert.deepEqual(f.primary.keys(), f.replica.keys());
  for (const k of f.primary.keys()) assert.deepEqual(f.primary.bytes(k), f.replica.bytes(k));
});
test('A02 dedup within project, independent namespaces across projects, no cross-project reads', () => {
  const f = fixture(), a = f.stageArtifact(); const before = f.primary.reads.length;
  denied(read(f, a, 'prj_beta'), 'NOT_AVAILABLE'); assert.equal(f.primary.reads.length, before);
  const b = f.stageArtifact('art_site', f.files(), {projectId: 'prj_beta'});
  assert.notEqual(a.reference.artifact.content_hash, b.reference.artifact.content_hash);
  assert(f.primary.keys().some(k => k.startsWith('prj_beta/objects/')));
  assert.equal(must(read(f, b)).bytes_base64, must(read(f, a)).bytes_base64);
});
test('A03 exact manifest includes file names/media/bytes, spec, version and provenance', () => {
  const f = fixture(), a = f.stageArtifact(), old = a.reference.artifact.content_hash;
  const b = f.stageArtifact('art_site', f.files('new revision'), {version: 2});
  assert.notEqual(old, b.reference.artifact.content_hash); denied(read(f, a), 'NOT_AVAILABLE');
  assert.equal(f.primary.bytes(objectKey('prj_alpha', old)).length, a.reference.artifact.bytes);
  denied(f.artifacts.put(f.session(), text(a.input)), 'VERSION_CONFLICT');
});
for (const target of ['file', 'manifest', 'replica_file', 'replica_manifest', 'missing_replica'])
  test('A04 altered after QA rejected on readback: ' + target, () => {
    const f = fixture(), pending = f.readback(), a = pending.ready.artifact;
    const store = target.startsWith('replica') || target === 'missing_replica' ? f.replica : f.primary;
    const k = target.includes('manifest') ? objectKey('prj_alpha', a.reference.artifact.content_hash) : f.fileKey(a);
    if (target === 'missing_replica') store.remove(k); else store.corrupt(k, Buffer.from('altered after QA'));
    denied(pending.complete(), 'INTEGRITY_FAILURE'); denied(pending.complete(), 'READBACK_REJECTED');
  });
test('A05 altered primary data is rejected by direct read and QA pin', () => {
  const f = fixture(), a = f.stageArtifact(), dto = f.evidence(a); f.primary.corrupt(f.fileKey(a), Buffer.from('tamper'));
  denied(read(f, a), 'INTEGRITY_FAILURE');
  denied(f.artifacts.pinQa(f.session('act_examiner'), text({artifact_id: 'art_site', version: 1, evidence: dto})), 'INTEGRITY_FAILURE');
});
for (const node of ['symlink', 'junction', 'reparse', 'hardlink', 'redirect', 'directory'])
  test('A06 synthetic filesystem refuses links/junctions/reparse and path redirection: ' + node, () => {
    const f = fixture(), a = f.stageArtifact();
    f.primary.fault({read: (k, e) => ({...e,
      ...(node === 'symlink' || node === 'junction' || node === 'directory' ? {kind: node} : {}),
      ...(node === 'reparse' ? {reparse: true} : {}), ...(node === 'hardlink' ? {link_count: 2} : {}),
      ...(node === 'redirect' ? {canonical_key: 'prj_beta/objects/fake'} : {})})});
    denied(read(f, a), 'INTEGRITY_FAILURE');
  });
for (const path of ['../escape', 'a/../escape', '/absolute', 'C:/drive', 'C:drive', '\\server\\share',
  'folder\\file', 'file:stream', 'a//b', './file', 'a/./b', 'CON', 'aux.txt', 'com1.txt', 'lpt9',
  'trailing.', 'trailing ', 'a/%2e%2e/b', '%252e%252e/file', 'a\u0000b', 'а.txt', 'a/'.repeat(13) + 'b'])
  test('A07 rejects unsafe portable path: ' + JSON.stringify(path), () => {
    assert.throws(() => safePath(path), /UNSAFE_PATH/);
    const f = fixture(), x = f.artifactInput(); x.files[0].path = path;
    denied(f.artifacts.put(f.session(), text(x)), 'UNSAFE_PATH'); assert.equal(f.primary.writes.length, 0);
  });
for (const paths of [['a.txt', 'A.TXT'], ['a', 'a/b.txt'], ['a/b', 'A']])
  test('A08 rejects archive/file namespace collision ' + paths.join(','), () => assert.throws(() => safePathSet(paths), /UNSAFE_PATH/));
test('A09 valid real stored ZIP is parsed in memory and committed as regular CAS files', () => {
  const f = fixture(), archive = zip([{path: 'dist/index.txt', value: 'synthetic zip payload'}]);
  const files = readStoredZip(archive), input = f.artifactInput('art_zip', files);
  delete input.files; input.archive_base64 = archive.toString('base64');
  const a = must(f.artifacts.putZip(f.session(), text(input)));
  assert.deepEqual(validateShape('artifact-ref', a.reference), []);
  const value = must(f.artifacts.read(f.session('act_reader'), text({artifact_id: 'art_zip', version: 1, path: 'dist/index.txt'})));
  assert.equal(Buffer.from(value.bytes_base64, 'base64').toString(), 'synthetic zip payload');
});
for (const entry of [{path: '../escape'}, {path: 'a\\b'}, {path: 'C:/escape'}, {path: 'link', attr: 0xa1ff0000},
  {path: 'junction', attr: 0x81a40400}, {path: 'dir/', attr: 0x41ed0010}, {path: 'device', attr: 0x21b60000},
  {path: 'encrypted', flags: 1}, {path: 'descriptor', flags: 8}, {path: 'compressed', method: 8}])
  test('A10 unsafe archive entry is rejected before writes ' + text(entry), () => {
    const f = fixture(), input = f.artifactInput(); delete input.files; input.archive_base64 = zip([entry]).toString('base64');
    denied(f.artifacts.putZip(f.session(), text(input))); assert.equal(f.primary.writes.length, 0);
  });
for (const corruption of ['crc', 'local_name', 'size', 'disk', 'offset', 'truncated', 'zip64', 'trailing', 'overlap', 'duplicate', 'case_collision'])
  test('A11 malformed ZIP layout/CRC/size/overlap rejected ' + corruption, () => {
    let b = zip([{path: 'a.txt'}]); const e = b.length - 22, c = b.readUInt32LE(e + 16);
    if (corruption === 'crc') b[35] ^= 1;
    if (corruption === 'local_name') b[30] = 0x62;
    if (corruption === 'size') b.writeUInt32LE(0xffffffff, c + 24);
    if (corruption === 'disk') b.writeUInt16LE(1, e + 4);
    if (corruption === 'offset') b.writeUInt32LE(1, c + 42);
    if (corruption === 'zip64') b.writeUInt16LE(45, c + 6);
    if (corruption === 'truncated') b = b.subarray(0, -5);
    if (corruption === 'trailing') b = Buffer.concat([b, Buffer.from('tail')]);
    if (corruption === 'duplicate' || corruption === 'case_collision') b = zip([{path: 'a.txt'}, {path: corruption === 'duplicate' ? 'a.txt' : 'A.TXT'}]);
    if (corruption === 'overlap') { b = zip([{path: 'a.txt'}, {path: 'b.txt'}]); const start = b.readUInt32LE(b.length - 6); b.writeUInt32LE(0, start + 51 + 42); }
    assert.throws(() => readStoredZip(b), /UNSAFE_|UNSUPPORTED_/);
  });
for (const failure of ['throw', 'false_ack', 'async_ack', 'collision', 'lost_manifest'])
  test('A12 storage failure leaves no live partial artifact ' + failure, () => {
    const f = fixture(), input = f.artifactInput();
    if (failure === 'throw') f.replica.fault({write: () => { throw Error('private synthetic host error'); }});
    if (failure === 'false_ack') f.replica.fault({write: () => 'BAD'});
    if (failure === 'async_ack') f.replica.fault({write: () => Promise.resolve('CREATED')});
    if (failure === 'collision') f.replica.corrupt(objectKey('prj_alpha', hashBytes(f.files()[0].bytes)), Buffer.from('collision'));
    if (failure === 'lost_manifest') f.replica.fault({read: (k, e) => k.endsWith(hashBytes(f.files()[0].bytes).slice(7)) ? e : {...e, bytes: null}});
    const r = denied(f.artifacts.put(f.session(), text(input))); assert(!text(r).includes('private synthetic'));
    denied(f.artifacts.read(f.session('act_reader'), text({artifact_id: 'art_site', version: 1, path: 'site/index.txt'})), 'NOT_AVAILABLE');
  });
test('A13 unavailable/expired/revoked provenance prevents artifact output and QA', () => {
  const f = fixture(), a = f.stageArtifact(); f.bump(w => { w.sources[a.input.provenance.source_id].status = 'REVOKED'; });
  denied(read(f, a), 'PROVENANCE_REJECTED');
  const g = fixture(), b = g.stageArtifact(); g.setClock('2026-11-06T12:00:00.000Z'); denied(read(g, b), 'PROVENANCE_REJECTED');
});
test('A14 forged provenance or reader ACL denies before storage reads/writes', () => {
  const f = fixture(), input = f.artifactInput(); input.provenance.source_hash = digest({forged: true});
  denied(f.artifacts.put(f.session(), text(input)), 'PROVENANCE_REJECTED'); assert.equal(f.primary.writes.length, 0);
  const g = fixture(), a = g.stageArtifact('art_private', g.files(), {reader_ids: ['act_writer']}); const n = g.primary.reads.length;
  denied(read(g, a), 'NOT_AVAILABLE'); assert.equal(g.primary.reads.length, n);
});
test('A15 tombstone invalidates reads, pinned QA, readback and resurrection', () => {
  const f = fixture(), rb = f.readback(), a = rb.ready.artifact;
  must(f.artifacts.tombstone(f.session('act_owner'), text({artifact_id: 'art_site', expected_version: 1})));
  denied(read(f, a), 'NOT_AVAILABLE'); denied(rb.complete(), 'NOT_AVAILABLE');
  denied(f.artifacts.put(f.session(), text(f.artifactInput('art_site', f.files('new'), {version: 2}))), 'NOT_AVAILABLE');
});
test('A16 current state tombstone denies and does not modify the object bytes', () => {
  const f = fixture(), a = f.stageArtifact(), old = f.primary.keys().map(k => hashBytes(f.primary.bytes(k)));
  f.bump(w => { w.tombstones.artifacts.push('prj_alpha/art_site'); }); denied(read(f, a), 'NOT_AVAILABLE');
  assert.deepEqual(f.primary.keys().map(k => hashBytes(f.primary.bytes(k))), old);
});
for (const malformed of ['@@==', 'YQ', 'YQ===', 'YR==', 'data:text/plain;base64,YQ=='])
  test('A17 noncanonical base64 rejected ' + malformed, () => {
    const f = fixture(), input = f.artifactInput(); input.files[0].bytes_base64 = malformed;
    denied(f.artifacts.put(f.session(), text(input)), 'INVALID_INPUT'); assert.equal(f.primary.writes.length, 0);
  });
test('A18 output is immutable and changing caller inputs cannot mutate stored versions', () => {
  const f = fixture(), a = f.stageArtifact(); assert(Object.isFrozen(a.reference.artifact));
  a.input.files[0].bytes_base64 = Buffer.from('modified').toString('base64');
  assert.equal(Buffer.from(must(read(f, a)).bytes_base64, 'base64').toString(), 'synthetic artifact');
});
