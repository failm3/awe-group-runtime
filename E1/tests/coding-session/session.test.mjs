import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {inspectRepairPrior, openRepairSession} from '../../host/coding/repair-session.mjs';

// Static published evidence is used to construct a clearly labelled fake
// snapshot. This is not a fresh native QA/PG readback or AWE execution test.
const bytes = fs.readFileSync(new URL('../../coding/evidence/g1_normalize_01.json', import.meta.url));
const report = JSON.parse(bytes), witness = JSON.parse(fs.readFileSync(new URL('../../qa-coding/evidence/FAIL-g1_normalize_01.json', import.meta.url)));
function fixture() {
  return {report: structuredClone(report), witness: structuredClone(witness), report_sha256: createHash('sha256').update(bytes).digest('hex'),
    snapshot: {fixture: 'STATIC_EVIDENCE_OFFLINE_TEST_DOUBLE', project: {project_id: report.fixture.spec.project_id, quota_used: 1, spent: 0, reserved: 0}, tasks: [{...structuredClone(report.native_task), state: 'FAILED'}], attempts: structuredClone(report.native_attempts)},
    events: [{mission_id: report.fixture.spec.mission_id, task_id: 'code_r01', kind: 'QA_FAIL', body: {evaluator_id: 'e1_qa', result_hash: witness.result_hash}}]};
}
test('static prior binding keeps all 13 original fields and only public failure, never hidden oracle', () => {
  const result = inspectRepairPrior(fixture());
  assert.equal(Object.keys(result.prior).length, 13); assert.equal(result.prior.head_sha, witness.head_sha);
  assert.equal(result.prior.attempt_id, witness.native_attempt.attempt_id); assert.equal(result.prior.task_id, 'code_r01');
  assert.equal(result.failedPublicTest.input_origin, 'ORIGINAL_PUBLIC_EXAMPLE_ONLY'); assert.match(result.failedPublicTest.stderr, /SyntaxError/);
  assert.equal(Object.hasOwn(result.failedPublicTest, 'probes'), false); assert.equal(Object.hasOwn(result.failedPublicTest, 'expected'), false);
});
for (const [name, mutate] of [
  ['report bytes mismatch', f => f.report_sha256 = '0'.repeat(64)],
  ['witness success substitution', f => f.witness.verdict = 'PASS'],
  ['prior native not failed', f => f.snapshot.tasks[0].state = 'WAIT_QA'],
  ['quota reset', f => f.snapshot.project.quota_used = 0],
  ['second old attempt', f => f.snapshot.attempts.push(structuredClone(f.snapshot.attempts[0]))],
  ['unknown old attempt', f => f.snapshot.attempts[0].state = 'OUTCOME_UNKNOWN'],
  ['wrong fence', f => f.snapshot.tasks[0].fence++],
  ['wrong QA principal', f => f.events[0].body.evaluator_id = 'e1_worker'],
  ['QA PASS added', f => f.events.push({...f.events[0], kind: 'QA_PASS'})],
  ['scope hash changed', f => f.witness.result_hash = 'sha256:' + '0'.repeat(64)],
]) test('prior adoption rejects ' + name, () => { const f = fixture(); mutate(f); assert.throws(() => inspectRepairPrior(f)); });
test('invalid session config is rejected before any filesystem/native/model setup', async () => {
  await assert.rejects(openRepairSession({}), /REPAIR_SESSION_CONFIG/);
});
