// Failure-only G1 reconciliation. Positively identified failure can never produce QA PASS.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {randomUUID} from 'node:crypto';
import {createPsqlSession,createCoordinator} from '../coordinator/index.mjs';
import {digest} from '../contracts/index.mjs';
import {MODEL_POLICY} from '../broker/schemas.mjs';
import {PATCH_PROPOSAL_SCHEMA_DIGEST} from '../executors/coding/contracts.mjs';
import {runProgram} from '../host/program-runner/runner.mjs';
import {PROGRAM_PROFILE_DIGEST} from '../host/program-runner/profiles.mjs';
import {rubric} from './native-review.mjs';
import {evaluateComponent,verifyProgramReceipt} from './oracle.mjs';
import {sha256,verifyTrees} from './tree-proof.mjs';
import {inspectCommittedTrees} from './git-readback.mjs';

const root=fileURLToPath(new URL('../../',import.meta.url));
const runId='g1_normalize_01';
const reportFile=path.join(root,'E1','coding','evidence',runId+'.json');
const knownHash='sha256:8ff06c08d5cd59359039da1c1d6dae00c89cbac972e9769952315b092b7eae79';
const load=file=>JSON.parse(fs.readFileSync(file,'utf8'));

async function verifyFailure(descriptor) {
  assert.equal(path.resolve(descriptor),path.join(root,'.private','e1-resource.json'));
  const report=load(reportFile);
  assert.equal(report.run_id,runId);
  assert.equal(report.status,'BLOCKED_OR_REPAIR');
  assert.equal(report.outcome.decision,'REPAIR');
  assert.equal(report.outcome.reason,'CODING_FIXED_TEST_FAILED');
  assert.equal(report.native_task.result_hash,knownHash);
  assert.match(report.outcome.worktree_id,/^wt_[a-f0-9]{32}$/);
  const project_id=report.fixture.spec.project_id, mission_id=report.fixture.spec.mission_id,task_id='code_r01';
  const db=await createPsqlSession(load(descriptor),{role:'qa'});
  try {
    const client=createCoordinator({db,project_id});
    const s=await client.snapshot(), tasks=s.tasks.filter(t=>t.is_current && t.mission_id===mission_id);
    assert.equal(tasks.length,1);
    const [task]=tasks, result=task.result, a=result.evidence.coding_artifact, model=result.evidence.model_receipt;
    assert.equal(task.task_id,task_id); assert.equal(task.project_id,project_id);
    assert.ok(['WAIT_QA','FAILED'].includes(task.state));
    assert.equal(task.plan_digest,digest(report.fixture.plan));
    assert.equal(digest(result),knownHash);assert.equal(task.result_hash,knownHash);
    assert.equal(task.document.capability.capability_id,'e1.coding.patch');
    assert.equal(result.output_schema_digest,PATCH_PROPOSAL_SCHEMA_DIGEST);
    assert.equal(result.artifact_digest,digest(result.output));assert.equal(result.evidence.product_status,'PRODUCER_TEST_FAILED');
    assert.equal(task.document.qa.rubric_digest,digest(rubric));
    const {artifact_digest,accepted,...frozen}=a;
    assert.equal(accepted,false);assert.equal(digest(frozen),artifact_digest);assert.equal(a.profile,'LIVE_SCOPED_HOST');
    assert.equal(a.issue_number,8);assert.equal(a.rubric_digest,digest(rubric));assert.equal(a.producer_id,task.producer_id);
    assert.notEqual(task.producer_id,'e1_qa');assert.equal(a.model_receipt_digest,digest(model));
    assert.equal(a.issue_digest,report.issue.digest);assert.deepEqual(task.document.origin.source_digests,[a.issue_digest]);
    const attempts=s.attempts.filter(row=>row.mission_id===mission_id);
    assert.equal(attempts.length,1); const [attempt]=attempts;
    assert.equal(attempt.task_id,task_id);assert.equal(attempt.state,'CONFIRMED');assert.equal(attempt.route_id,MODEL_POLICY.route_id);
    assert.ok([0,'0'].includes(attempt.actual_cost)&&[0,'0'].includes(attempt.reserved));
    assert.equal(attempt.usage.wire_attempts,1);assert.equal(attempt.usage.model,MODEL_POLICY.model);
    assert.equal(attempt.usage.digest,MODEL_POLICY.digest);
    assert.ok([attempt.usage.input_tokens,attempt.usage.output_tokens].every(n=>Number.isSafeInteger(n)&&n>0));
    assert.equal(digest(model.native_receipt.native_attempt),digest(attempt));
    assert.equal(model.native_receipt.response.evidence_level,'LIVE_LOCAL_MODEL');
    assert.equal(model.native_receipt.response.request_hash,attempt.request_hash);
    assert.equal(digest(model.proposal),digest(result.output));
    assert.equal(digest(model.native_receipt.response.output),digest(result.output));
    assert.equal(s.intents.length,0);assert.equal(s.cloud_attempts.length,0);assert.equal(Number(s.project.quota_used),1);
    assert.equal(Number(s.project.reserved),0);assert.equal(Number(s.project.spent),0);

    const runRoot=path.join(root,'.private','coding-'+runId);
    const trees=inspectCommittedTrees({repository_root:path.join(runRoot,'repository'),worktree_root:path.join(runRoot,'worktrees',report.outcome.worktree_id),branch:a.branch,base_sha:a.base_sha,head_sha:a.head_sha});
    verifyTrees(trees,result.output,a);assert.equal(trees.final.tree_sha,a.tree_sha);assert.equal(a.tests.length,1);
    const producer=a.tests[0], files=trees.final.files.map(({path,content_utf8})=>({path,content_utf8}));
    const request={files,stdin:'{"id":" Z9 ","kind":" Open ","n":4}\n',entrypoint:'cli.py',binding:{tested_head_sha:a.head_sha,tested_tree_sha:a.tree_sha,invocation_id:producer.invocation_id}};
    assert.equal(producer.exit_code,1); verifyProgramReceipt(producer.program_receipt,request,PROGRAM_PROFILE_DIGEST);
    assert.notEqual(producer.program_receipt.exit_code,0);
    assert.match(producer.program_receipt.stderr,/SyntaxError/);
    request.binding={...request.binding,invocation_id:'failed_qa_'+randomUUID()};
    const replay=await runProgram(request);
    verifyProgramReceipt(replay,request,PROGRAM_PROFILE_DIGEST);
    assert.notEqual(replay.exit_code,0);
    assert.match(replay.stderr,/SyntaxError/);
    const tests=await evaluateComponent({trees,runProgram,profileDigest:PROGRAM_PROFILE_DIGEST});
    assert.equal(tests.verdict,'FAIL');
    assert.equal(tests.probes.find(p=>p.label==='cli').passed,false);
    const binding={mission_id,task_id,plan_digest:task.plan_digest,result_hash:knownHash};
    if(task.state==='WAIT_QA'){
      const checks=[{check_id:'schema',passed:true},{check_id:'sources',passed:false},{check_id:'scope',passed:true}];
      const classified=await client.qaEvaluate({...binding,evaluator_id:'e1_qa',verdict:'FAIL',checks});
      assert.equal(classified.status,'FAILED');
    }
    const fresh=await client.snapshot(), events=await client.events();
    const finalTask=fresh.tasks.find(r=>r.is_current&&r.task_id===task_id&&r.mission_id===mission_id);
    assert.equal(finalTask.state,'FAILED');assert.equal(finalTask.result_hash,knownHash);
    assert.equal(fresh.attempts.filter(r=>r.mission_id===mission_id).length,1);
    assert.equal(Number(fresh.project.quota_used),1);
    const fail=events.filter(e=>e.mission_id===mission_id&&e.task_id===task_id&&e.kind==='QA_FAIL');
    assert.equal(fail.length,1);assert.equal(fail[0].body.evaluator_id,'e1_qa');assert.equal(fail[0].body.result_hash,knownHash);
    assert.equal(events.filter(e=>e.mission_id===mission_id&&e.task_id===task_id&&e.kind==='QA_PASS').length,0);
    const nativeMission=fresh.missions.find(m=>m.mission_id===mission_id);
    assert.notEqual(nativeMission.state,'COMPLETE');
    const output={schema:'awe.g1.independent-negative-cold-review/1',observed_at:new Date().toISOString(),
      verdict:'FAIL',reason:'CLI_SYNTAX_ERROR_REPRODUCED',run_id:runId,...binding,qa_pid:process.pid,qa_role:'awe_e1_qa',project_id,
      task_state:finalTask.state,mission_state:nativeMission.state,qa_fail_events:1,qa_pass_events:0,
      report_sha256:sha256(fs.readFileSync(reportFile)),oracle_commitment:tests.oracle_commitment,
      artifact_digest,base_sha:a.base_sha,head_sha:a.head_sha,tree_sha:a.tree_sha,issue_digest:a.issue_digest,
      committed_files:trees.final.files.map(({path,blob_sha,digest})=>({path,blob_sha,digest})),compared_raw_git:true,
      original_receipt_digest:producer.program_receipt.receipt_digest,replay_receipt_digest:replay.receipt_digest,
      replay_exit_code:replay.exit_code,replay_error:'SyntaxError',probes:tests.probes,
      native_attempt:{attempt_id:attempt.attempt_id,logical_request_id:attempt.logical_request_id,route:attempt.route_id,request_hash:attempt.request_hash,state:attempt.state,usage:attempt.usage,actual_cost:attempt.actual_cost,reserved:attempt.reserved,quota:attempt.quota_units},
      new_model_calls:0,cloud_calls:0,external_effects:0,candidate_changes:0,owner_accepted:false};
    const outputFile=path.join(root,'E1','qa-coding','evidence','FAIL-'+runId+'.json');
    fs.mkdirSync(path.dirname(outputFile),{recursive:true});
    if(fs.existsSync(outputFile)){
      const prior=load(outputFile);
      assert.equal(prior.verdict,'FAIL');assert.equal(prior.result_hash,knownHash);
      assert.equal(prior.head_sha,a.head_sha);assert.equal(prior.known_attempt?.attempt_id??prior.native_attempt.attempt_id,attempt.attempt_id);
    } else fs.writeFileSync(outputFile,JSON.stringify(output,null,2)+'\n',{flag:'wx'});
    return {verdict:'FAIL',run_id:runId,task_state:finalTask.state,mission_state:nativeMission.state,qa_fail_events:1,reason:output.reason,
      probes:tests.probes.map(p=>({label:p.label,passed:p.passed})),new_model_calls:0,new_paid_calls:0,external_effects:0};
  } finally {await db.close();}
}
if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {assert.equal(process.argv.length,4);assert.equal(process.argv[2],runId);console.log(JSON.stringify(await verifyFailure(process.argv[3])));}
  catch(error){console.error(JSON.stringify({status:'QA_RECONCILIATION_BLOCKED',code:error.code??'FAIL_INSPECTION_ERROR',check:error.stack?.match(/([a-z-]+\.mjs):(\d+):\d+/)?.slice(1).join(':')}));process.exitCode=1;}
}
