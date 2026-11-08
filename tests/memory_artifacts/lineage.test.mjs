import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture, must, denied, text} from './fixtures.mjs';
import {digest, hashBytes} from '../../awe/memory/boundary.mjs';

const query = f => f.memory.search(f.session('act_reader'), text({query: 'lesson', limit: 20}));
test('L01 complete verified lineage permits ingestion; revoked ancestor invalidates descendants', () => {
  const f = fixture(), parent = f.source({subjectId: 'mem_parent', kind: 'MEMORY', contentHash: hashBytes(Buffer.from('parent')), shareable: true});
  f.stageMemory('mem_child', 'lesson derived', {parents: [parent], shareable: true}); assert.equal(must(query(f)).hits.length, 1);
  f.bump(w => { w.sources[parent.source_id].status = 'REVOKED'; }); assert.deepEqual(must(query(f)).hits, []);
});
for (const poison of ['cross_project', 'expired', 'reader_widening', 'share_widening', 'missing', 'stale_head', 'tombstone', 'deep'])
  test('L02 poisoned provenance ancestor never verifies: ' + poison, () => {
    const f = fixture(); let parent = f.source({subjectId: 'mem_parent', kind: 'MEMORY', contentHash: digest({parent: true}),
      projectId: poison === 'cross_project' ? 'prj_beta' : 'prj_alpha',
      reader_ids: poison === 'reader_widening' ? ['act_writer'] : Object.keys(f.world.actors), shareable: poison !== 'share_widening',
      expires_at: poison === 'expired' ? '2026-11-05T11:00:00.000Z' : '2026-11-06T12:00:00.000Z'});
    if (poison === 'missing') parent = {source_id: 'src_missing', source_hash: digest({missing: true})};
    if (poison === 'stale_head') f.bump(w => { w.heads.memory['prj_alpha/mem_parent'].version++; });
    if (poison === 'tombstone') f.bump(w => { w.tombstones.memory.push('prj_alpha/mem_parent'); });
    if (poison === 'deep') for (let i = 0; i < 9; i++) parent = f.source({subjectId: 'mem_parent_' + i, kind: 'MEMORY',
      contentHash: digest({i}), shareable: true, parents: [parent]});
    const x = f.memoryInput('mem_child', 'lesson derived', {parents: [parent], shareable: true});
    must(f.memory.ingest(f.session(), text(x)));
    denied(f.memory.verify(f.session('act_owner'), text({record_id: 'mem_child', version: 1})), 'PROVENANCE_REJECTED');
    assert.deepEqual(must(query(f)).hits, []);
  });
test('L03 state port is the canonical version selector; a stale local copy cannot be used', () => {
  const f = fixture(); f.stageMemory('mem_note', 'lesson v1');
  f.memoryInput('mem_note', 'lesson v2', {version: 2}); assert.deepEqual(must(query(f)).hits, []);
  const g = fixture(), a = g.stageArtifact(); g.artifactInput('art_site', g.files('v2'), {version: 2});
  denied(g.artifacts.read(g.session('act_reader'), text({artifact_id: 'art_site', version: 1, path: a.files[0].path})), 'PROVENANCE_REJECTED');
});
test('L04 version metadata preserves immutable content/provenance chain and requires audit permission', () => {
  const f = fixture(), first = f.stageMemory('mem_note', 'lesson v1'); f.stageMemory('mem_note', 'lesson v2', {version: 2});
  const history = must(f.memory.history(f.session('act_owner'), text({record_id: 'mem_note'})));
  assert.deepEqual(history.versions.map(v => v.version), [1, 2]);
  assert.equal(history.versions[0].provenance_hash, first.provenance.source_hash);
  assert(history.versions[1].previous_hash.startsWith('sha256:')); assert(!text(history).includes('lesson'));
  denied(f.memory.history(f.session('act_reader'), text({record_id: 'mem_note'})), 'DENIED');
});
test('L05 incomplete state snapshot cannot silently omit tombstones or canonical heads', () => {
  for (const field of ['tombstones', 'heads', 'sources', 'promotions', 'qa_attestations']) {
    const f = fixture(), token = f.session('act_reader'); f.bump(w => { delete w[field]; });
    denied(f.memory.search(token, text({query: 'lesson', limit: 1})), 'STATE_UNAVAILABLE');
  }
});
test('L06 independent readers need current per-object ACL, not just project membership', () => {
  const f = fixture(), a = f.stageArtifact('art_private', f.files(), {reader_ids: Object.keys(f.world.actors).filter(a => a !== 'act_readback_b')});
  const rb = f.readback(f.qaReady(a)); denied(rb.complete(), 'NOT_AVAILABLE');
});
test('L07 reentrant local tombstone during adapter read cannot return stale bytes or readback PASS', () => {
  for (const readback of [false, true]) {
    const f = fixture(), rb = readback ? f.readback() : null, a = rb?.ready.artifact ?? f.stageArtifact();
    const owner = f.session('act_owner'); let once = false;
    const store = readback ? f.replica : f.primary;
    store.fault({read: (k, e) => { if (!once) { once = true;
      must(f.artifacts.tombstone(owner, text({artifact_id: 'art_site', expected_version: 1}))); } return e; }});
    denied(readback ? rb.complete() : f.artifacts.read(f.session('act_reader'), text({artifact_id: 'art_site', version: 1, path: a.files[0].path})), 'STATE_CHANGED');
  }
});
test('L08 every file, including secondary manifest entries, is read back independently', () => {
  const f = fixture(), files = [...f.files(), {path: 'site/second.txt', bytes: Buffer.from('second synthetic file'), media_type: 'text/plain'}];
  const a = f.stageArtifact('art_site', files), rb = f.readback(f.qaReady(a)); f.replica.corrupt(f.fileKey(a, 1), Buffer.from('tampered second'));
  denied(rb.complete(), 'INTEGRITY_FAILURE');
});
test('L09 artifact history retains exact earlier manifests, with no worker history privilege', () => {
  const f = fixture(), a = f.stageArtifact(); f.stageArtifact('art_site', f.files('v2'), {version: 2});
  const rows = must(f.artifacts.history(f.session('act_owner'), text({artifact_id: 'art_site'}))).versions;
  assert.deepEqual(rows.map(r => r.version), [1, 2]); assert.deepEqual(rows[0].artifact, a.reference.artifact);
  assert.equal(rows[1].previous_manifest_hash, rows[0].artifact.content_hash);
  denied(f.artifacts.history(f.session(), text({artifact_id: 'art_site'})), 'DENIED');
});
test('L10 retrieval has a bounded output budget and deterministic ranking of visible records', () => {
  const f = fixture(); for (let i = 0; i < 5; i++) f.stageMemory('mem_large_' + i, 'lesson ' + 'synthetic '.repeat(1600));
  const r = must(query(f)); assert(r.hits.length > 0 && r.hits.length < 5); assert(Buffer.byteLength(text(r)) < 65536);
  assert.deepEqual(must(query(f)), r);
});
test('L11 increasing authority revision cannot roll back an observed canonical version head', () => {
  const f = fixture(); f.stageMemory('mem_note', 'lesson v1');
  const oldHead = {...f.world.heads.memory['prj_alpha/mem_note']}; f.stageMemory('mem_note', 'lesson v2', {version: 2});
  must(query(f)); const token = f.session('act_reader'); f.bump(w => { w.heads.memory['prj_alpha/mem_note'] = oldHead; });
  denied(f.memory.search(token, text({query: 'lesson', limit: 20})), 'STATE_UNAVAILABLE');
});
test('L12 observed authority tombstone cannot be removed to resurrect a record', () => {
  const f = fixture(); f.stageMemory('mem_note', 'lesson');
  f.bump(w => { w.tombstones.memory.push('prj_alpha/mem_note'); }); assert.deepEqual(must(query(f)).hits, []);
  const token = f.session('act_reader'); f.bump(w => { w.tombstones.memory = []; });
  denied(f.memory.search(token, text({query: 'lesson', limit: 20})), 'STATE_UNAVAILABLE');
});
test('L13 observed source revocation cannot be reversed under a newer authority revision', () => {
  const f = fixture(), x = f.stageMemory('mem_note', 'lesson');
  f.bump(w => { w.sources[x.provenance.source_id].status = 'REVOKED'; }); assert.deepEqual(must(query(f)).hits, []);
  const token = f.session('act_reader'); f.bump(w => { w.sources[x.provenance.source_id].status = 'VERIFIED'; });
  denied(f.memory.search(token, text({query: 'lesson', limit: 20})), 'STATE_UNAVAILABLE');
});
test('L14 malformed string ACL or unknown D01 role cannot gain permission through includes()', () => {
  for (const change of ['reader_acl_string', 'reader_role', 'producer_acl_string']) {
    const f = fixture(); f.stageMemory('mem_note', 'lesson'); const token = f.session('act_reader');
    f.bump(w => {
      if (change === 'reader_acl_string') w.actors.act_reader.memberships.prj_alpha = 'memory.read';
      if (change === 'reader_role') w.actors.act_reader.role = 'FORGED_ROLE';
      if (change === 'producer_acl_string') w.actors.act_writer.memberships.prj_alpha = 'provenance.produce';
    });
    const r = f.memory.search(token, text({query: 'lesson', limit: 20}));
    if (change === 'producer_acl_string') assert.deepEqual(must(r).hits, []); else denied(r, 'DENIED');
  }
  const f = fixture(), parent = f.source({subjectId: 'mem_parent', kind: 'MEMORY', contentHash: digest({parent: true}), shareable: 'false'});
  const input = f.memoryInput('mem_child', 'lesson', {parents: [parent], shareable: true});
  must(f.memory.ingest(f.session(), text(input)));
  denied(f.memory.verify(f.session('act_owner'), text({record_id: 'mem_child', version: 1})), 'PROVENANCE_REJECTED');
});
