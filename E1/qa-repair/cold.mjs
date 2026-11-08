import assert from 'node:assert/strict';
import {digest} from '../contracts/index.mjs';
import {PATCH_PROPOSAL_SCHEMA_DIGEST} from '../executors/coding/contracts.mjs';
import {ORACLE_COMMITMENT} from '../qa-coding/commitments.mjs';
import {evaluateReaders} from './leaf.mjs';
import {checkHeadReceipt,inspectHead,checkStageAttempt} from './bindings.mjs';
import {priorRecord,repairRubric} from './prior.mjs';

export async function verifyRepairCold({client,priorClient,store,run_id,git,prior_qa_pid}){
  assert.ok(Number.isSafeInteger(prior_qa_pid)&&prior_qa_pid!==process.pid);
  const row=await store.read(run_id), binding=row.binding, p=priorRecord();
  assert.equal(row.phase,'RESULT_READY');assert.equal(row.stored_phase,'RESULT_READY');
  assert.equal(binding.run_id,run_id);assert.equal(binding.oracle_digest,ORACLE_COMMITMENT);
  const [snapshot,events]=await Promise.all([client.snapshot(),client.events({})]);
  const mission=snapshot.missions.find(m=>m.mission_id===binding.mission_id);assert.equal(mission.state,'COMPLETE');
  const tasks=snapshot.tasks.filter(t=>t.mission_id===binding.mission_id&&t.is_current);
  const product=tasks.find(t=>t.task_id==='product_gate');assert.ok(product);
  const code=tasks.find(t=>['code_r02','code_r03'].includes(t.task_id)&&t.result_hash===product.result?.output?.code_result_hash);
  assert.ok(code);assert.equal(code.state,'ACCEPTED');assert.equal(product.state,'ACCEPTED');
  assert.equal(code.document.capability.output_schema.digest,PATCH_PROPOSAL_SCHEMA_DIGEST);
  assert.equal(row.state.refs.code_result_hash,code.result_hash);assert.equal(row.state.refs.product_result_hash,product.result_hash);
  assert.equal(row.state.refs.candidate_head_sha,product.result.output.head_sha);
  assert.equal(row.state.refs.candidate_tree_sha,product.result.output.tree_sha);
  assert.equal(row.state.refs.product_pass,true);
  const archived=snapshot.task_history.map(r=>r.body);
  const head=[...tasks,...archived].find(t=>t.task_id==='head_plan'&&t.mission_id===mission.mission_id&&t.state==='ACCEPTED');
  assert.ok(head);assert.equal(digest(head.result),head.result_hash);assert.equal(head.result.artifact_digest,digest(head.result.output));
  assert.equal(head.document.qa.rubric_digest,digest(repairRubric(p)));
  assert.equal(head.document.capability.capability_id,'e1.head.coding');
  const ha=checkStageAttempt(snapshot,head);checkHeadReceipt(head,ha);assert.ok(inspectHead(head.result.output));
  assert.equal(head.result.output.decision,'REPAIR');
  const hv=events.filter(e=>e.mission_id===head.mission_id&&e.task_id===head.task_id&&e.kind==='QA_PASS'&&e.body.result_hash===head.result_hash);
  assert.equal(hv.length,1);assert.equal(hv[0].body.evaluator_id,'e1_qa');
  assert.ok(code.document.input.instruction.includes(head.result.output.focus));
  const codeAttempts=snapshot.attempts.filter(a=>['code_r02','code_r03'].includes(a.task_id)).length;
  assert.ok(codeAttempts<=head.result.output.max_code_attempts);
  const productReview=await evaluateReaders(client,priorClient,{outerrow:row,git,read_only:true,
    binding:{mission_id:mission.mission_id,task_id:product.task_id,plan_digest:product.plan_digest,result_hash:product.result_hash}});
  assert.equal(productReview.qa.verdict,'PASS');assert.equal(productReview.receipt.vote,'RECONCILED');
  return {schema:'awe.qa-repair.cold-product/1',status:'PASS',claim:'REPAIRED_TWO_FILE_PRODUCT',
    project_id:binding.project_id,mission_id:binding.mission_id,run_id,inspector_pid:process.pid,prior_qa_pid,
    native_store_phase:row.phase,native_store_revision:row.revision,binding_digest:row.binding_digest,source_digest:binding.source_digest,
    prior_result_hash:p.result_hash,prior_attempt_id:p.native_attempt.attempt_id,prior_verdict:'FAIL',
    original_base_sha:p.base_sha,prior_failed_head:p.head_sha,head_decision_hash:head.result_hash,head_attempt_id:ha.attempt_id,
    final_head_sha:product.result.output.head_sha,final_tree_sha:product.result.output.tree_sha,code_result_hash:code.result_hash,product_result_hash:product.result_hash,
    native_usage:snapshot.attempts.map(a=>({task_id:a.task_id,attempt_id:a.attempt_id,request_hash:a.request_hash,state:a.state,usage:a.usage,actual_cost:a.actual_cost})),
    aggregate:productReview.receipt.counts,read_only_product_replay:productReview.receipt,full_three_file_G2:'NOT_PROVEN',
    dynamic_roles:'NOT_TESTED',new_model_calls:0,cloud_calls:0,external_effects:0,owner_accepted:false};
}
