import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {digest} from '../contracts/index.mjs';
import {MODEL_POLICY} from '../broker/schemas.mjs';
import {inspectCommittedTrees} from '../qa-coding/git-readback.mjs';
import {sha256,verifyTrees} from '../qa-coding/tree-proof.mjs';
import {BRIEF_SHA256,ORACLE_COMMITMENT} from '../qa-coding/commitments.mjs';
import {PROGRAM_PROFILE_DIGEST} from '../host/program-runner/profiles.mjs';

const root=fileURLToPath(new URL('../../',import.meta.url));
export const PRIOR_FAILURE_FILE_SHA256='9a1e111715fed478f26b937c90b2de1faadc3903dc3fdf2db24274d615844618';
export function priorRecord(){
  const bytes=readFileSync(new URL('../qa-coding/evidence/FAIL-g1_normalize_01.json',import.meta.url));
  assert.equal(sha256(bytes),'sha256:'+PRIOR_FAILURE_FILE_SHA256);
  return JSON.parse(bytes);
}
export const QA_CHECKS=Object.freeze(['schema','sources','scope','product']);
export function repairRubric(prior=priorRecord()){
  return {checks:QA_CHECKS, brief_sha256:BRIEF_SHA256,oracle_commitment:ORACLE_COMMITMENT,
    test_profile_digest:PROGRAM_PROFILE_DIGEST,prior_result_hash:prior.result_hash,prior_attempt_id:prior.native_attempt.attempt_id,aggregate_model_limit:4};
}
function zero(n){return n===0||n==='0';}
export function checkedLocalAttempt(attempt){
  assert.equal(attempt.state,'CONFIRMED');
  assert.equal(attempt.route_id,MODEL_POLICY.route_id);
  assert.equal(attempt.usage.model,MODEL_POLICY.model);
  assert.equal(attempt.usage.digest,MODEL_POLICY.digest);
  assert.equal(attempt.usage.wire_attempts,1);
  assert.ok([attempt.usage.input_tokens,attempt.usage.output_tokens].every(x=>Number.isSafeInteger(x)&&x>0));
  assert.ok(zero(attempt.reserved)&&zero(attempt.actual_cost));
  assert.match(attempt.request_hash,/^sha256:[a-f0-9]{64}$/);
}
export function checkPriorNative(snapshot,events,prior=priorRecord()){
  assert.equal(snapshot.project.project_id,prior.project_id);
  assert.equal(Number(snapshot.project.quota_cap),1);
  assert.equal(Number(snapshot.project.quota_used),1);
  assert.ok(zero(snapshot.project.reserved)&&zero(snapshot.project.spent));
  assert.equal(snapshot.attempts.length,1);
  const [a]=snapshot.attempts;checkedLocalAttempt(a);
  for (const k of ['attempt_id','logical_request_id','request_hash']) assert.equal(a[k],prior.native_attempt[k]);
  assert.equal(a.project_id,prior.project_id);assert.equal(a.mission_id,prior.mission_id);assert.equal(a.task_id,prior.task_id);
  const tasks=snapshot.tasks.filter(t=>t.mission_id===prior.mission_id&&t.is_current);
  assert.equal(tasks.length,1);const [t]=tasks;
  assert.equal(t.task_id,prior.task_id);assert.equal(t.state,'FAILED');assert.equal(a.worker_id,t.producer_id);assert.equal(String(a.fence),String(t.fence));
  assert.equal(t.plan_digest,prior.plan_digest);assert.equal(t.result_hash,prior.result_hash);assert.equal(digest(t.result),prior.result_hash);
  const artifact=t.result.evidence.coding_artifact;
  assert.equal(t.result.evidence.product_status,'PRODUCER_TEST_FAILED');assert.equal(artifact.artifact_digest,prior.artifact_digest);
  assert.equal(artifact.head_sha,prior.head_sha);assert.equal(artifact.tree_sha,prior.tree_sha);assert.equal(artifact.base_sha,prior.base_sha);
  const verdicts=events.filter(e=>e.mission_id===prior.mission_id&&e.task_id===prior.task_id&&['QA_PASS','QA_FAIL'].includes(e.kind));
  assert.equal(verdicts.length,1);assert.equal(verdicts[0].kind,'QA_FAIL');assert.equal(verdicts[0].body.evaluator_id,'e1_qa');
  assert.equal(verdicts[0].body.result_hash,t.result_hash);assert.notEqual(verdicts[0].body.evaluator_id,t.producer_id);
  assert.equal(snapshot.intents.length,0); assert.equal(snapshot.cloud_attempts.length,0);
  return {prior,t,artifact};
}
export function readOriginalTrees(prior,task,artifact) {
  const bytes=readFileSync(path.join(root,'E1','coding','evidence',prior.run_id+'.json'));
  assert.equal(sha256(bytes),prior.report_sha256);
  const wt=JSON.parse(bytes).outcome.worktree_id;
  assert.match(wt,/^wt_[a-f0-9]{32}$/);
  const runRoot=path.join(root,'.private','coding-'+prior.run_id);
  const trees=inspectCommittedTrees({repository_root:path.join(runRoot,'repository'),worktree_root:path.join(runRoot,'worktrees',wt), branch:artifact.branch,base_sha:prior.base_sha,head_sha:prior.head_sha});
  assert.equal(trees.final.tree_sha,prior.tree_sha);
  verifyTrees(trees,task.result.output,artifact);
  return trees;
}
export function checkAggregate(snapshot,mission_id,prior=priorRecord()){
  assert.notEqual(snapshot.project.project_id,prior.project_id);
  assert.equal(Number(snapshot.project.quota_cap),3);
  assert.equal(Number(snapshot.project.quota_used),snapshot.attempts.length);
  assert.ok(zero(snapshot.project.reserved)&&zero(snapshot.project.spent));
  assert.equal(snapshot.intents.length,0);assert.equal(snapshot.cloud_attempts.length,0);
  assert.ok(snapshot.attempts.length<=3);
  const ids=new Set(),requests=new Set([prior.native_attempt.logical_request_id]),attemptIds=new Set([prior.native_attempt.attempt_id]);
  for(const a of snapshot.attempts){
    checkedLocalAttempt(a);assert.equal(a.project_id,snapshot.project.project_id);assert.equal(a.mission_id,mission_id);
    assert.ok(['head_plan','code_r02','code_r03'].includes(a.task_id));assert.ok(!ids.has(a.task_id));
    assert.ok(!requests.has(a.logical_request_id)&&!attemptIds.has(a.attempt_id));
    ids.add(a.task_id);requests.add(a.logical_request_id);attemptIds.add(a.attempt_id);
  }
  return {prior_wires:1,head_wires:Number(ids.has('head_plan')),repair_wires:Number(ids.has('code_r02'))+Number(ids.has('code_r03')),
    total_wires:1+snapshot.attempts.length,total_cap:4,remaining:3-snapshot.attempts.length};
}
