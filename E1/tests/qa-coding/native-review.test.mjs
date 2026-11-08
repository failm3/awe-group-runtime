import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {digest} from '../../contracts/index.mjs';
import {MODEL_POLICY} from '../../broker/schemas.mjs';
import {PATCH_PROPOSAL_SCHEMA_DIGEST,freezeCodingArtifact} from '../../executors/coding/contracts.mjs';
import {PROGRAM_PROFILE_DIGEST} from '../../host/program-runner/profiles.mjs';
import {inspectNative,rubric} from '../../qa-coding/native-review.mjs';

function fixture(){
  // Synthetic accounting shape only. No candidate algorithm or successful runtime claim.
  const brief=JSON.parse(readFileSync(new URL('../../qa-coding/public-brief.json',import.meta.url),'utf8'));
  const mission_id='mission_qa_synthetic', task_id='code_r01', worker_id='fixture_producer';
  const scope={mission_id,task_id,worker_id,fence:9,attempt_id:'attempt_test',logical_request_id:'logical_test'};
  const usage={model:MODEL_POLICY.model,digest:MODEL_POLICY.digest,wire_attempts:1,input_tokens:1,output_tokens:1};
  const attempt={...scope,state:'CONFIRMED',usage,actual_cost:0,reserved:0,route_id:MODEL_POLICY.route_id,request_hash:digest('synthetic request')};
  const proposal={base_sha:'a'.repeat(40),summary:'fixture',changes:[{path:'cli.py',before_digest:digest('base'),after_text:'# inert'}]};
  const response={evidence_level:'LIVE_LOCAL_MODEL',accounting_status:'CONFIRMED',decision:'PROPOSED',wire_attempts:1,model:{id:MODEL_POLICY.model,digest:MODEL_POLICY.digest},request_hash:attempt.request_hash,usage,output:proposal};
  const inner={response,native_attempt:structuredClone(attempt),context_digest:digest('synthetic context'),scope};
  const envelope={proposal,accounting_status:'CONFIRMED',wire_attempts:1,route_id:attempt.route_id,attempt_id:attempt.attempt_id,actual_cost_micros:0,usage,model:response.model,evidence_level:'LIVE_SCOPED_HOST',native_receipt:inner,host_binding_digest:digest(inner)};
  const repository={owner:'failm3',name:'awe-group-runtime'},issue_number=8;
  const issue_digest=digest({repository,issue_number,title:brief.title,body:brief.body});
  const artifact=freezeCodingArtifact({contract_version:'awe.e1.coding-artifact/2',profile:'LIVE_SCOPED_HOST',repository,issue_number,issue_digest,rubric_digest:digest(rubric),producer_id:worker_id,base_sha:proposal.base_sha,head_sha:'b'.repeat(40),tree_sha:'c'.repeat(40),attempt_scope:scope,model_receipt_digest:digest(envelope),tests:[{exit_code:0,sandbox_enforced:true,network:'DENY',profile_digest:PROGRAM_PROFILE_DIGEST,tested_head_sha:'b'.repeat(40),tested_tree_sha:'c'.repeat(40),invocation_id:'offline_case'}]});
  const result={output_schema_digest:PATCH_PROPOSAL_SCHEMA_DIGEST,output:proposal,artifact_digest:digest(proposal),evidence:{coding_artifact:artifact,model_receipt:inner,product_status:'PENDING_INDEPENDENT_QA'}};
  const binding={mission_id,task_id,plan_digest:digest('plan'),result_hash:digest(result)};
  const document={input:{instruction:brief.body},capability:{capability_id:'e1.coding.patch',output_schema:{digest:PATCH_PROPOSAL_SCHEMA_DIGEST}},qa:{rubric_id:'e1.coding.g1.rubric',rubric_digest:digest(rubric),required_checks:[...rubric.checks]},origin:{source_digests:[issue_digest]}};
  const task={...binding,state:'WAIT_QA',fence:9,producer_id:worker_id,is_current:true,result,document};
  return {snapshot:{tasks:[task],attempts:[attempt],project:{spent:0,reserved:0,quota_used:1},intents:[],cloud_attempts:[]},binding};
}
test('independent native-shape inspector accepts consistent simulated rows',()=>{
 const {snapshot,binding}=fixture();
 assert.equal(inspectNative(snapshot,binding,'WAIT_QA').attempt.attempt_id,'attempt_test');
});
for(const [name,mutate] of [
 ['wrong QA stage',s=>s.tasks[0].state='RUNNING'],['wrong fence',s=>s.attempts[0].fence=10],['UNKNOWN model',s=>s.attempts[0].state='OUTCOME_UNKNOWN'],
 ['extra attempt',s=>s.attempts.push(structuredClone(s.attempts[0]))],['wrong rubric',s=>s.tasks[0].document.qa.rubric_digest=digest('foreign')],
 ['cold artifact substitution',s=>s.tasks[0].result.output.summary='changed'],['paid drift',s=>s.project.spent=1],
 ['unexpected effect',s=>s.intents.push({})],['different producer',s=>s.tasks[0].producer_id='e1_qa'],
]){
 test('native-shape inspector rejects '+name,()=>{
   const {snapshot,binding}=fixture();mutate(snapshot);
   assert.throws(()=>inspectNative(snapshot,binding,'WAIT_QA'));
 });
}
