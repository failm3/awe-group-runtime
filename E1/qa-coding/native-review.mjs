import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {digest} from '../contracts/index.mjs';
import {MODEL_POLICY} from '../broker/schemas.mjs';
import {PATCH_PROPOSAL_SCHEMA_DIGEST} from '../executors/coding/contracts.mjs';
import {PROGRAM_PROFILE_DIGEST} from '../host/program-runner/profiles.mjs';
import {BRIEF_SHA256, ORACLE_COMMITMENT, QA_CHECKS} from './commitments.mjs';
import {sha256} from './tree-proof.mjs';

const briefBytes = readFileSync(new URL('./public-brief.json', import.meta.url));
assert.equal(sha256(briefBytes), 'sha256:' + BRIEF_SHA256);
const brief = JSON.parse(briefBytes);
export const rubric = Object.freeze({checks: QA_CHECKS, brief_sha256: BRIEF_SHA256, oracle_commitment: ORACLE_COMMITMENT, test_profile_digest: PROGRAM_PROFILE_DIGEST});

export function inspectNative(snapshot, binding, state) {
  assert.ok(['WAIT_QA', 'ACCEPTED'].includes(state));
  assert.equal(binding.task_id, 'code_r01');
  const tasks = snapshot.tasks.filter(row => row.mission_id === binding.mission_id && row.is_current);
  assert.equal(tasks.length, 1);
  const [task] = tasks;
  assert.equal(task.task_id, binding.task_id);
  assert.equal(task.state, state);
  assert.equal(task.plan_digest, binding.plan_digest);
  assert.equal(task.result_hash, binding.result_hash);
  assert.equal(digest(task.result), binding.result_hash);
  assert.equal(task.document.capability.capability_id, 'e1.coding.patch');
  assert.equal(task.document.capability.output_schema.digest, PATCH_PROPOSAL_SCHEMA_DIGEST);
  assert.equal(task.document.qa.rubric_id, 'e1.coding.g1.rubric');
  assert.equal(task.document.qa.rubric_digest, digest(rubric));
  assert.deepEqual(task.document.qa.required_checks, QA_CHECKS);
  assert.equal(task.document.input.instruction, brief.body);
  const result = task.result, proposal = result.output;
  assert.equal(result.output_schema_digest, PATCH_PROPOSAL_SCHEMA_DIGEST);
  assert.equal(result.artifact_digest, digest(proposal));
  assert.equal(result.evidence.product_status, 'PENDING_INDEPENDENT_QA');
  const artifact = result.evidence.coding_artifact;
  const {accepted, artifact_digest, ...artifactBody} = artifact;
  assert.equal(accepted, false);
  assert.equal(artifact_digest, digest(artifactBody));
  assert.equal(artifact.contract_version, 'awe.e1.coding-artifact/2');
  assert.equal(artifact.profile, 'LIVE_SCOPED_HOST');
  assert.equal(artifact.rubric_digest, digest(rubric));
  assert.equal(artifact.producer_id, task.producer_id);
  assert.notEqual(artifact.producer_id, 'e1_qa');
  assert.deepEqual(artifact.repository, {owner:'failm3',name:'awe-group-runtime'});
  assert.equal(artifact.issue_number, 8);
  const issue = {repository: artifact.repository, issue_number: artifact.issue_number, title: brief.title, body: brief.body};
  assert.equal(artifact.issue_digest, digest(issue));
  assert.deepEqual(task.document.origin.source_digests, [artifact.issue_digest]);
  assert.ok(artifact.tests.length > 0);
  for (const test of artifact.tests) {
    assert.equal(test.exit_code, 0);
    assert.equal(test.sandbox_enforced, true);
    assert.equal(test.network, 'DENY');
    assert.equal(test.profile_digest, PROGRAM_PROFILE_DIGEST);
    assert.equal(test.tested_head_sha, artifact.head_sha);
    assert.equal(test.tested_tree_sha, artifact.tree_sha);
    assert.ok(typeof test.invocation_id === 'string' && test.invocation_id.length > 0);
  }
  assert.equal(new Set(artifact.tests.map(test => test.invocation_id)).size, artifact.tests.length);
  const attempts = snapshot.attempts.filter(row => row.mission_id === binding.mission_id);
  assert.equal(attempts.length, 1);
  const [attempt] = attempts;
  assert.equal(attempt.task_id, binding.task_id);
  assert.equal(attempt.worker_id, artifact.producer_id);
  assert.equal(String(attempt.fence), String(task.fence));
  assert.equal(attempt.state, 'CONFIRMED');
  assert.equal(attempt.route_id, MODEL_POLICY.route_id);
  assert.equal(attempt.usage.model, MODEL_POLICY.model);
  assert.equal(attempt.usage.digest, MODEL_POLICY.digest);
  assert.equal(attempt.usage.wire_attempts, 1);
  assert.ok([attempt.usage.input_tokens, attempt.usage.output_tokens].every(v => Number.isSafeInteger(v) && v > 0));
  assert.ok([0,'0'].includes(attempt.actual_cost) && [0,'0'].includes(attempt.reserved));
  assert.ok([0,'0'].includes(snapshot.project.spent) && [0,'0'].includes(snapshot.project.reserved));
  assert.ok([1,'1'].includes(snapshot.project.quota_used));
  assert.equal(snapshot.intents.length, 0);
  assert.equal(snapshot.cloud_attempts.length, 0);
  const model = result.evidence.model_receipt;
  const nativeReceipt = model.native_receipt ?? model;
  const {response, native_attempt, scope} = nativeReceipt;
  assert.equal(response.evidence_level, 'LIVE_LOCAL_MODEL');
  assert.equal(response.accounting_status, 'CONFIRMED');
  assert.equal(response.decision, 'PROPOSED');
  assert.equal(response.wire_attempts, 1);
  assert.equal(response.request_hash, attempt.request_hash);
  assert.equal(digest(response.usage), digest(attempt.usage));
  assert.equal(digest(response.output), digest(proposal));
  assert.equal(digest(native_attempt), digest(attempt));
  for (const key of ['mission_id','task_id','attempt_id','logical_request_id','worker_id','fence']) {
    assert.equal(String(scope[key]), String(attempt[key]));
    assert.equal(String(artifact.attempt_scope[key]), String(attempt[key]));
  }
  const modelEnvelope = {proposal:response.output, accounting_status:'CONFIRMED', wire_attempts:1,
    route_id:attempt.route_id, attempt_id:attempt.attempt_id, actual_cost_micros:0, usage:response.usage, model:response.model,
    evidence_level:'LIVE_SCOPED_HOST', native_receipt:nativeReceipt, host_binding_digest:digest(nativeReceipt)};
  assert.equal(digest(modelEnvelope), artifact.model_receipt_digest);
  return {artifact, proposal, attempt, task};
}
