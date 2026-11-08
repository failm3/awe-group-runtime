import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture, must, denied, text} from './fixtures.mjs';
import {digest, copy} from '../../awe/memory/boundary.mjs';
import {createOfflineArtifacts} from '../../awe/artifacts/service.mjs';

test('R01 two distinct readers/stores independently reread full manifest and all files', () => {
  const f = fixture(), rb = f.readback(), primaryReads = f.primary.reads.length, replicaReads = f.replica.reads.length;
  const r = must(rb.complete()); assert.equal(r.status, 'VERIFIED_E0_READBACK'); assert.equal(r.independent_acceptance, false);
  assert.equal(r.physical_effect_authority, false); assert.equal(r.receipts.length, 2);
  assert.notEqual(r.receipts[0].reader_id, r.receipts[1].reader_id); assert.notEqual(r.receipts[0].storage_id, r.receipts[1].storage_id);
  assert.deepEqual(r.receipts.map(r => r.mode), ['BUFFER', 'CHUNKS']);
  assert(f.primary.reads.length > primaryReads && f.replica.reads.length > replicaReads);
  assert(r.receipts.every(r => r.request_hash === digest(rb.request) && r.aggregate_hash === rb.request.artifact.aggregate_hash));
  denied(rb.complete(), 'READBACK_REJECTED');
});
test('R02 no QA means no readback request; worker cannot submit PASS or forged receipts', () => {
  const f = fixture(), a = f.stageArtifact();
  denied(f.artifacts.requestReadback(f.session('act_owner'), text({artifact_id: 'art_site', version: 1, qa_hash: digest({fake: true})})), 'QA_REJECTED');
  denied(f.artifacts.pinQa(f.session(), text({artifact_id: 'art_site', version: 1, evidence: {verdict: 'PASS'}})), 'DENIED');
  const rb = f.readback(f.qaReady(a));
  denied(f.artifacts.completeReadback(rb.token, text({request_id: rb.request.request_id, receipts: [{status: 'PASS'}]})), 'INVALID_INPUT');
  must(rb.complete());
});
for (const change of ['hash', 'aggregate', 'bytes', 'artifact_id', 'project', 'spec', 'epoch', 'revision', 'provenance',
  'not_run', 'exit', 'criteria_missing', 'criteria_extra', 'no_stdout', 'forged_stdout', 'runner', 'attestation', 'scope', 'producer'])
  test('R03 QA exact version/hash/revision/provenance/attestation rejects ' + change, () => {
    const f = fixture(), a = f.stageArtifact(), dto = copy(f.evidence(a));
    if (change === 'hash') dto.artifact.content_hash = digest({fake: true});
    if (change === 'aggregate') dto.artifact.aggregate_hash = digest({fake: true});
    if (change === 'bytes') dto.artifact.bytes++; if (change === 'artifact_id') dto.artifact.artifact_id = 'art_wrong';
    if (change === 'project') dto.artifact.project_id = 'prj_beta'; if (change === 'spec') dto.spec.revision++;
    if (change === 'epoch') dto.epochs.stop++; if (change === 'revision') dto.expected_revision++;
    if (change === 'provenance') f.bump(w => { w.sources[a.input.provenance.source_id].producer_id = 'act_unknown'; });
    if (change === 'not_run') dto.execution_status = 'NOT_RUN'; if (change === 'exit') dto.exit_code = 1;
    if (change === 'criteria_missing') dto.criterion_ids = ['Q01']; if (change === 'criteria_extra') dto.criterion_ids.push('M15');
    if (change === 'no_stdout') dto.stdout_ref = null; if (change === 'forged_stdout') dto.stdout_ref.content_hash = digest({fake_log: true});
    if (change === 'runner') dto.runner.identity_id = 'act_auditor'; if (change === 'attestation') dto.producer_attestation = digest({fake: true});
    if (change === 'scope') dto.scope.operation_id = 'op_wrong';
    if (change === 'producer') { dto.actor = {identity_id: 'act_writer', role: 'EXECUTOR'}; dto.runner = dto.actor; }
    denied(f.artifacts.pinQa(f.session('act_examiner'), text({artifact_id: 'art_site', version: 1, evidence: dto})));
  });
test('R04 version upgrade after pinned QA cannot reuse prior approval/readback', () => {
  const f = fixture(), rb = f.readback(); f.stageArtifact('art_site', f.files('v2'), {version: 2});
  denied(rb.complete(), 'NOT_AVAILABLE');
  denied(f.artifacts.requestReadback(f.session('act_owner'), text({artifact_id: 'art_site', version: 2, qa_hash: rb.ready.pinned.qa_hash})), 'QA_REJECTED');
});
for (const invalidation of ['source', 'qa_receipt', 'runner', 'reader_a', 'reader_b', 'reader_acl', 'membership', 'expired', 'qa_log'])
  test('R05 live revalidation at readback boundary: ' + invalidation, () => {
    const f = fixture(), rb = f.readback();
    if (invalidation === 'source') f.bump(w => { w.sources[rb.ready.artifact.input.provenance.source_id].status = 'REVOKED'; });
    if (invalidation === 'qa_receipt') f.bump(w => { delete w.qa_attestations[rb.ready.dto.run_id]; });
    if (invalidation === 'runner') f.bump(w => { w.actors.act_examiner.active = false; });
    if (invalidation === 'reader_a') f.bump(w => { w.actors.act_readback_a.active = false; });
    if (invalidation === 'reader_b') f.bump(w => { w.actors.act_readback_b.active = false; });
    if (invalidation === 'reader_acl') f.bump(w => { w.actors.act_readback_b.memberships.prj_alpha = []; });
    if (invalidation === 'membership') f.bump(w => { w.actors.act_owner.memberships.prj_alpha = []; });
    if (invalidation === 'expired') f.setClock('2026-11-05T12:01:00.000Z');
    if (invalidation === 'qa_log') f.bump(w => { w.tombstones.artifacts.push('prj_alpha/' + rb.ready.dto.stdout_ref.artifact_id); });
    denied(rb.complete());
  });
for (const change of ['epochs', 'spec', 'restore', 'unavailable', 'state_hash', 'clock'])
  test('R06 state changes during adapter reads fail final barrier: ' + change, () => {
    const f = fixture(), rb = f.readback(); let changed = false;
    f.replica.fault({read: (key, entry) => {
      if (!changed) { changed = true;
        if (change === 'unavailable') f.unavailable();
        else if (change === 'clock') f.setClock('2026-11-05T12:01:00.000Z');
        else f.bump(w => { const p = w.projects.prj_alpha;
          if (change === 'epochs') p.epochs.auth++; if (change === 'spec') p.spec.revision++;
          if (change === 'restore') p.restore_pending = true; });
      } return entry;
    }});
    denied(rb.complete());
  });
test('R07 requests are bound to instance, requester, project, expiry and one use', () => {
  const f = fixture(), rb = f.readback(), g = fixture();
  denied(g.artifacts.completeReadback(g.session('act_owner'), text({request_id: rb.request.request_id})), 'READBACK_REJECTED');
  denied(f.artifacts.completeReadback(f.session('act_owner', 'prj_beta'), text({request_id: rb.request.request_id})), 'READBACK_REJECTED');
  denied(f.artifacts.completeReadback(f.session('act_verifier'), text({request_id: rb.request.request_id})), 'READBACK_REJECTED');
  must(rb.complete());
});
test('R08 missing/corrupt secondary path fails even when primary ACK and hashes pass', () => {
  const f = fixture(), rb = f.readback(); f.replica.fault({read: () => { throw Error('synthetic missing path'); }});
  denied(rb.complete(), 'INTEGRITY_FAILURE');
});
test('R09 no aliasing two readback paths or producer-as-reader is accepted', () => {
  const f = fixture(); assert.throws(() => createOfflineArtifacts({authority: f.authority, stores: [f.primary.port, f.primary.port], readers: f.readers}));
  assert.throws(() => createOfflineArtifacts({authority: f.authority, stores: [f.primary.port, f.replica.port],
    readers: [f.readers[0], {...f.readers[1], store: f.primary.port}]}));
});
test('R10 D07 creates no canonical state transition or accepted QA receipt', () => {
  const f = fixture(), rb = f.readback(), before = copy(f.world); must(rb.complete());
  assert.deepEqual(f.world, before); assert.equal(f.world.projects.prj_alpha.status, 'READY');
});
