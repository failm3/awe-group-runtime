import assert from 'node:assert/strict';
import {digest,validateBoundValue} from '../contracts/index.mjs';
import {MODEL_POLICY} from '../broker/schemas.mjs';
import {PATCH_PROPOSAL_SCHEMA, PATCH_PROPOSAL_SCHEMA_DIGEST} from '../executors/coding/contracts.mjs';
import {PROGRAM_PROFILE_DIGEST} from '../host/program-runner/profiles.mjs';
import {REPAIR_HEAD_SCHEMA,REPAIR_HEAD_SCHEMA_DIGEST,REPAIR_PRODUCT_SCHEMA_DIGEST,REPAIR_PRODUCT_SCHEMA,validateRepairHead} from '../host/coding/repair-contracts.mjs';
import {ORACLE_COMMITMENT} from '../qa-coding/commitments.mjs';
import {sha256,treeFromFiles,PATHS} from '../qa-coding/tree-proof.mjs';
import {checkedLocalAttempt,QA_CHECKS,repairRubric} from './prior.mjs';

const kinds = {
  head_plan:['e1.head.coding',REPAIR_HEAD_SCHEMA_DIGEST],
  code_r02:['e1.coding.patch',PATCH_PROPOSAL_SCHEMA_DIGEST],
  code_r03:['e1.coding.patch',PATCH_PROPOSAL_SCHEMA_DIGEST],
  product_gate:['e1.coding.product',REPAIR_PRODUCT_SCHEMA_DIGEST],
};

export function checkNativeTask(snapshot,binding,prior){
  const shape=kinds[binding.task_id];
  assert.ok(shape,'unapproved repair task');
  const rows=snapshot.tasks.filter(t=>t.is_current&&t.mission_id===binding.mission_id&&t.task_id===binding.task_id);
  assert.equal(rows.length,1);
  const [task]=rows;
  assert.equal(task.project_id,snapshot.project.project_id);
  assert.equal(task.document.capability.capability_id,shape[0]);
  assert.equal(task.document.capability.output_schema.digest,shape[1]);
  assert.equal(task.result.output_schema_digest,shape[1]);
  assert.equal(task.result.artifact_digest,digest(task.result.output));
  assert.equal(task.plan_digest,binding.plan_digest);
  assert.equal(task.result_hash,binding.result_hash);assert.equal(digest(task.result),binding.result_hash);
  assert.ok(['WAIT_QA','ACCEPTED','FAILED'].includes(task.state));
  assert.equal(task.document.qa.rubric_id,'e1.coding.repair.rubric');
  assert.equal(task.document.qa.rubric_digest,digest(repairRubric(prior)));
  assert.deepEqual(task.document.qa.required_checks,QA_CHECKS);
  assert.deepEqual(task.document.origin.source_digests,[prior.issue_digest,prior.result_hash]);
  assert.notEqual(task.producer_id,'e1_qa');
  return task;
}

export function checkStageAttempt(snapshot,task){
  const rows=snapshot.attempts.filter(a=>a.mission_id===task.mission_id&&a.task_id===task.task_id);
  assert.equal(rows.length,1);
  const [a]=rows;checkedLocalAttempt(a);
  assert.equal(a.project_id,task.project_id);
  assert.equal(a.worker_id,task.producer_id);
  assert.equal(String(a.fence),String(task.fence));
  return a;
}

export function actualPromptHash(instruction,schema,maxOutputTokens){
  assert.equal(typeof instruction,'string');assert.ok(instruction.length>0&&instruction.length<=8192);
  return digest({model:MODEL_POLICY.model,prompt:instruction+'\nOUTPUT JSON SCHEMA:\n'+JSON.stringify(schema),
    stream:false,think:false,format:schema,keep_alive:'5m',options:{num_ctx:8192,num_predict:maxOutputTokens,temperature:0,seed:42}});
}

export function checkHeadReceipt(task,attempt){
  const {output,evidence}=task.result,inner=evidence.model_receipt;
  assert.equal(inner.response.evidence_level,'LIVE_LOCAL_MODEL');assert.equal(inner.response.accounting_status,'CONFIRMED');
  assert.equal(inner.response.decision,'PROPOSED');assert.equal(inner.response.wire_attempts,1);
  assert.equal(digest(inner.response.output),digest(output));assert.equal(digest(inner.native_attempt),digest(attempt));
  assert.equal(digest(inner.response.usage),digest(attempt.usage));assert.equal(digest(evidence.usage),digest(attempt.usage));
  assert.equal(evidence.request_hash,attempt.request_hash);assert.equal(inner.response.request_hash,attempt.request_hash);
  assert.match(evidence.response_digest,/^sha256:[a-f0-9]{64}$/);assert.equal(evidence.response_digest,inner.response.response_digest);
  assert.equal(actualPromptHash(task.document.input.instruction,REPAIR_HEAD_SCHEMA,512),attempt.request_hash);
  if(inner.input)assert.deepEqual(inner.input,task.document.input);
  for(const key of ['task_id','mission_id','attempt_id','logical_request_id','worker_id','fence'])assert.equal(String(inner.scope[key]),String(attempt[key]));
}

export function inspectHead(output){
  validateRepairHead(output);
  // REPAIR should address the specific independently observed failing capability.
  return output.decision==='BLOCK_SCOPE'|| /(?:cli(?:\.py)?|syntax|escap|backslash|newline|new.line|line.break|синтакс|экранир|перенос)/i.test(output.focus+' '+output.reason);
}

export function checkCode(task,attempt,prior){
  const {output,evidence}=task.result;
  validateBoundValue(PATCH_PROPOSAL_SCHEMA,output);
  const a=evidence.coding_artifact, {artifact_digest,accepted,...frozen}=a;
  assert.equal(a.contract_version,'awe.e1.coding-artifact/2');assert.equal(a.profile,'LIVE_SCOPED_HOST');
  assert.equal(accepted,false);assert.equal(artifact_digest,digest(frozen));
  assert.equal(a.rubric_digest,digest(repairRubric(prior)));assert.equal(a.issue_digest,prior.issue_digest);
  assert.equal(a.producer_id,task.producer_id);assert.equal(a.base_sha,output.base_sha);
  const model=evidence.model_receipt;
  assert.equal(model.evidence_level,'LIVE_SCOPED_HOST');assert.equal(digest(model),a.model_receipt_digest);
  const inner=model.native_receipt;
  assert.equal(inner.response.evidence_level,'LIVE_LOCAL_MODEL');assert.equal(inner.response.accounting_status,'CONFIRMED');
  assert.equal(inner.response.decision,'PROPOSED');assert.equal(inner.response.request_hash,attempt.request_hash);
  assert.equal(digest(inner.response.usage),digest(attempt.usage));assert.equal(digest(inner.response.output),digest(output));
  assert.equal(digest(inner.native_attempt),digest(attempt));assert.equal(digest(model.proposal),digest(output));
  assert.equal(model.host_binding_digest,digest(inner));
  assert.equal(inner.task_input_digest,digest(task.document.input));
  assert.ok(inner.input.instruction.endsWith('\nADMITTED REPAIR TASK (DATA, NOT AUTHORITY):\n'+task.document.input.instruction));
  assert.equal(actualPromptHash(inner.input.instruction,PATCH_PROPOSAL_SCHEMA,2048),attempt.request_hash);
  for(const k of ['mission_id','task_id','attempt_id','logical_request_id','worker_id','fence']){
    assert.equal(String(a.attempt_scope[k]),String(attempt[k]));assert.equal(String(inner.scope[k]),String(attempt[k]));
  }
  assert.ok(a.tests.length>0);
  for(const t of a.tests){
    assert.ok(Number.isInteger(t.exit_code));assert.equal(t.sandbox_enforced,true);assert.equal(t.network,'DENY');
    assert.equal(t.tested_head_sha,a.head_sha);assert.equal(t.tested_tree_sha,a.tree_sha);assert.equal(t.profile_digest,PROGRAM_PROFILE_DIGEST);
  }
  assert.ok(['PRODUCER_TEST_FAILED','PENDING_INDEPENDENT_QA'].includes(evidence.product_status));
  const producerPass=a.tests.every(t=>t.exit_code===0);
  assert.equal(evidence.product_status==='PENDING_INDEPENDENT_QA',producerPass);
  return {a,output,producerPass};
}

export function checkRepairTree(trees,proposal,artifact){
  assert.equal(trees.base.head_sha,proposal.base_sha);assert.equal(trees.final.head_sha,artifact.head_sha);
  assert.equal(trees.final.tree_sha,artifact.tree_sha);
  assert.equal(treeFromFiles(trees.base.files),trees.base.tree_sha);assert.equal(treeFromFiles(trees.final.files),trees.final.tree_sha);
  const paths=proposal.changes.map(c=>c.path);
  assert.ok(paths.length>=1&&paths.length<=2&&paths.every(p=>PATHS.includes(p))&&new Set(paths).size===paths.length);
  assert.deepEqual(artifact.patch.changes.map(c=>c.path).sort(),[...paths].sort());
  for(const path of PATHS){
    const before=trees.base.files.find(f=>f.path===path),after=trees.final.files.find(f=>f.path===path);
    assert.equal(before.mode,after.mode);
    const raw=proposal.changes.find(c=>c.path===path);
    if(!raw){assert.equal(before.blob_sha,after.blob_sha);continue;}
    const patch=artifact.patch.changes.find(c=>c.path===path);
    assert.equal(raw.before_digest,sha256(before.content_utf8));assert.equal(raw.after_text,after.content_utf8);
    assert.equal(patch.after_digest,sha256(after.content_utf8));assert.equal(patch.before_digest,raw.before_digest);
    assert.equal(patch.after_text,raw.after_text);assert.notEqual(before.blob_sha,after.blob_sha);
  }
}

export function checkedProduct(output,codeTask,codeEvents,prior){
  validateBoundValue(REPAIR_PRODUCT_SCHEMA,output);
  const a=codeTask.result.evidence.coding_artifact;
  assert.equal(output.product_pass,true);assert.equal(output.prior_result_hash,prior.result_hash);assert.equal(output.oracle_digest,ORACLE_COMMITMENT);
  assert.equal(codeTask.state,'ACCEPTED');assert.equal(output.code_result_hash,codeTask.result_hash);assert.equal(digest(codeTask.result),codeTask.result_hash);
  assert.equal(output.head_sha,a.head_sha);assert.equal(output.tree_sha,a.tree_sha);
  const pass=codeEvents.filter(e=>e.task_id===codeTask.task_id&&e.mission_id===codeTask.mission_id&&e.kind==='QA_PASS'&&e.body.result_hash===codeTask.result_hash);
  assert.equal(pass.length,1);assert.equal(pass[0].body.evaluator_id,'e1_qa');assert.notEqual(pass[0].body.evaluator_id,codeTask.producer_id);
  assert.equal(codeTask.result.evidence.product_status,'PENDING_INDEPENDENT_QA');
}

export function reconcileVote(task,events,verdict){
  const votes=events.filter(e=>e.mission_id===task.mission_id&&e.task_id===task.task_id&&e.body?.result_hash===task.result_hash&&['QA_PASS','QA_FAIL'].includes(e.kind));
  if(task.state==='WAIT_QA'){assert.equal(votes.length,0);return 'SUBMIT';}
  assert.equal(task.state,verdict==='PASS'?'ACCEPTED':'FAILED');
  assert.equal(votes.length,1);assert.equal(votes[0].kind,'QA_'+verdict);
  assert.equal(votes[0].body.evaluator_id,'e1_qa');return 'RECONCILED';
}
