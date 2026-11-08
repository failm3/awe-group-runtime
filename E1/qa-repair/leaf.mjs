import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
import {createAuthorityClient} from '../coordinator/authority-server.mjs';
import {digest} from '../contracts/index.mjs';
import {runProgram} from '../host/program-runner/runner.mjs';
import {PROGRAM_PROFILE_DIGEST} from '../host/program-runner/profiles.mjs';
import {inspectCommittedTrees} from '../qa-coding/git-readback.mjs';
import {ORACLE_COMMITMENT} from '../qa-coding/commitments.mjs';
import {evaluateComponent} from '../qa-coding/oracle.mjs';
import {checkAggregate,checkPriorNative,priorRecord,readOriginalTrees,QA_CHECKS,repairRubric} from './prior.mjs';
import {checkNativeTask,checkStageAttempt,checkHeadReceipt,inspectHead,checkCode,checkedProduct,checkRepairTree,reconcileVote} from './bindings.mjs';

function previousCandidate(snapshot,task,prior){
  if(task.task_id==='code_r02') return prior.head_sha;
  assert.equal(task.task_id,'code_r03');
  const history=[...snapshot.tasks,...(snapshot.task_history??[]).map(r=>r.body)];
  const priorRound=history.find(r=>r.mission_id===task.mission_id&&r.task_id==='code_r02'&&r.state==='FAILED'&&r.result_hash&&digest(r.result)===r.result_hash);
  assert.ok(priorRound,'missing previous failed code result');
  return priorRound.result.evidence.coding_artifact.head_sha;
}

async function replayCode({snapshot,code,prior,priorTask,priorArtifact,git}){
  const attempt=checkStageAttempt(snapshot,code), {a,output,producerPass}=checkCode(code,attempt,prior);
  assert.equal(a.base_sha,previousCandidate(snapshot,code,prior));
  const original=readOriginalTrees(prior,priorTask,priorArtifact);
  const repaired=inspectCommittedTrees({...git,branch:a.branch,base_sha:a.base_sha,head_sha:a.head_sha});
  checkRepairTree(repaired,output,a);
  if(code.task_id==='code_r02')assert.equal(repaired.base.tree_sha,original.final.tree_sha);
  const tested=await evaluateComponent({trees:{base:original.base,final:repaired.final},runProgram,profileDigest:PROGRAM_PROFILE_DIGEST});
  const passed=producerPass&&tested.verdict==='PASS';
  return {passed,tested,attempt,artifact:a,source_digests:repaired.final.files.map(({path,digest,blob_sha})=>({path,digest,blob_sha}))};
}

export async function evaluateStage(options) {
  const {url,token,prior_reader}=options;
  assert.ok(prior_reader?.url&&prior_reader.token);
  const priorClient=createAuthorityClient(prior_reader),client=createAuthorityClient({url,token});
  return evaluateReaders(client,priorClient,options);
}

export async function evaluateReaders(client,priorClient,{binding,git,outerrow,outer,read_only=false}) {
  const [snapshot,events,priorSnapshot,priorEvents]=await Promise.all([client.snapshot(),client.events({}),priorClient.snapshot(),priorClient.events({})]);
  const {prior,t:priorTask,artifact:priorArtifact}=checkPriorNative(priorSnapshot,priorEvents);
  const counts=checkAggregate(snapshot,binding.mission_id,prior);
  const row=outerrow??outer;
  // Parent-provided summary is corroborated with actual scoped native attempt/grant state.
  assert.ok(row?.binding&&row.counters,'missing coding run store snapshot');
  assert.equal(row.binding.mission_id,binding.mission_id);assert.equal(row.binding.project_id,snapshot.project.project_id);
  assert.equal(row.binding.oracle_digest,ORACLE_COMMITMENT);assert.equal(row.binding.brief_digest,prior.issue_digest);
  assert.equal(row.binding.original_base_sha,prior.head_sha);
  assert.equal(row.binding.prior_attempt_refs.length,1);
  const ref=row.binding.prior_attempt_refs[0];
  for(const k of ['project_id','mission_id','task_id','result_hash','head_sha','tree_sha','artifact_digest','plan_digest'])assert.equal(ref[k],prior[k]);
  for(const k of ['attempt_id','logical_request_id','request_hash'])assert.equal(ref[k],prior.native_attempt[k]);
  assert.equal(String(ref.fence),String(priorTask.fence));assert.equal(ref.worker_id,priorTask.producer_id);
  assert.equal(Number(row.counters.total),counts.total_wires);assert.equal(Number(row.counters.head),counts.head_wires);assert.equal(Number(row.counters.code),1+counts.repair_wires);
  assert.equal(row.counters.hold,false);
  const mission=snapshot.missions.find(m=>m.mission_id===binding.mission_id);
  assert.ok(mission&&mission.project_id===snapshot.project.project_id);
  assert.equal(mission.grant_digest,row.binding.root_grant_digest);
  assert.equal(row.binding_digest,digest(row.binding));
  const task=checkNativeTask(snapshot,binding,prior);
  let passed,detail={},artifactDigest=task.result.artifact_digest,codeHead,codeTree;
  if(task.task_id==='head_plan'){
    const attempt=checkStageAttempt(snapshot,task);
    checkHeadReceipt(task,attempt);
    passed=inspectHead(task.result.output);
    detail={kind:'BOUNDED_HEAD_DECISION',decision:task.result.output.decision,attempt_id:attempt.attempt_id,product_accepted:false};
  }else{
    const isProduct=task.task_id==='product_gate';
    const code=isProduct?snapshot.tasks.find(t=>t.mission_id===task.mission_id&&t.is_current&&t.result_hash===task.result.output.code_result_hash):task;
    assert.ok(code&&['code_r02','code_r03'].includes(code.task_id));
    if(isProduct){
      assert.equal(snapshot.attempts.filter(a=>a.task_id===task.task_id).length,0);
      checkedProduct(task.result.output,code,events,prior);
    }
    const replay=await replayCode({snapshot,code,prior,priorTask,priorArtifact,git});
    passed=replay.passed;
    codeHead=replay.artifact.head_sha;codeTree=replay.artifact.tree_sha;
    if(!isProduct)artifactDigest=replay.artifact.artifact_digest;
    detail={kind:isProduct?'FINAL_COMPONENT':'CODING_CANDIDATE',attempt_id:replay.attempt.attempt_id,
      code_result_hash:code.result_hash,head_sha:codeHead,tree_sha:codeTree,source_digests:replay.source_digests,probes:replay.tested.probes};
  }
  const verdict=passed?'PASS':'FAIL';
  const checks=QA_CHECKS.map(check_id=>({check_id,passed:check_id==='product'?passed:true,...(check_id==='product'&&codeHead?{oracle_digest:ORACLE_COMMITMENT,head_sha:codeHead,tree_sha:codeTree}:{})}));
  const voteMode=reconcileVote(task,events,verdict);
  if(read_only)assert.equal(voteMode,'RECONCILED');
  const value=voteMode==='SUBMIT'?await client.qaEvaluate({...binding,verdict,checks}):{status:task.state};
  assert.equal(value.status,passed?'ACCEPTED':'FAILED');
  const qa={verdict,checks,artifact_digest:artifactDigest,rubric_digest:digest(repairRubric(prior)),producer_id:task.producer_id,evaluator_id:'e1_qa',accepted:false};
  return {type:'EVALUATED',pid:process.pid,value,qa,evaluation:{verdict,checks,...detail},receipt:{schema:'awe.qa-repair.stage/1',
    ...binding,verdict,product_accepted:task.task_id==='product_gate'&&passed,checked_phase:row.phase,checkpoint_revision:row.revision,prior_result_hash:prior.result_hash,
    counts,oracle_commitment:ORACLE_COMMITMENT,vote:voteMode,...detail,external_effects:0}};
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  process.once('message',async message=>{
    try {process.send?.(await evaluateStage(message));}
    catch(e){process.send?.({type:'ERROR',pid:process.pid,code:'QA_REPAIR_STAGE_BLOCKED',check:e.stack?.split('\n').find(l=>l.includes('/qa-repair/')||l.includes('\\qa-repair\\'))?.match(/([a-z-]+\.mjs):(\d+):\d+/)?.slice(1).join(':')??'unknown'});}
  });
  process.on('disconnect',()=>process.exit(0));process.send?.({type:'QA_READY',pid:process.pid});
}
