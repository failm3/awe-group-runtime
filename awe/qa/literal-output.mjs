import {bytesHash,digest,need,POLICY} from './common.mjs';
import {runnerHash} from '../qa_profiles/runner.mjs';
import {LITERAL_DIALECT,compileLiteralGoal} from '../integration_v4/literal-contract.mjs';
export {LITERAL_DIALECT};
export const isDynamicRequirements=r=>['OWNER02_TEXT_STATS_V1',LITERAL_DIALECT].includes(r?.kind);
const criteria=['ARTIFACT','REQUIREMENTS','FUNCTIONAL','RECEIPTS','CHAIN','CITATIONS','ISOLATION'];
// Authoritative fixed D08 inspector. Trusted store supplies readback and receipts;
// text and QA02 opinions are data. No worker-provided verdict is imported.
export function evaluateLiteral({bytes,reference,requirements:r,evidence:e,operations,pin}){
 const findings=[],trace=[];let verdict='QA_PASS';
 const check=(v,code,criterion)=>{trace.push({criterion,path:code,ok:Boolean(v)});if(!v)findings.push({code,severity:'ERROR',criterion,trace:{path:code}});};
 try{
  const spec=r.immutable_spec;need(spec?.dialect===LITERAL_DIALECT&&Buffer.isBuffer(bytes)&&bytes.length<=4096,'LITERAL_INPUT_REQUIRED');
  const sealed=compileLiteralGoal({goal:e.original_user_goal,filename:spec.input.path,text:spec.input.text});
  check(digest(sealed.spec)===digest(spec)&&digest(spec)===pin.spec.content_hash&&digest(e.current_spec)===digest(pin.spec)&&digest(r.spec)===digest(pin.spec),'LITERAL_IMMUTABLE_SPEC','REQUIREMENTS');
  check(r.project_id===reference.project_id&&r.task_id===reference.task_id&&reference.path===spec.input.path&&reference.version>0&&reference.bytes===bytes.length&&reference.file_hash===bytesHash(bytes),'LITERAL_EXACT_REFERENCE','ARTIFACT');
  check(new TextDecoder('utf-8',{fatal:true}).decode(bytes)===spec.input.text&&bytes.equals(Buffer.from(spec.input.text)),'LITERAL_EXACT_UTF8_BYTES','FUNCTIONAL');
  check(r.original_user_goal_hash===sealed.spec.original_user_goal_hash,'LITERAL_ORIGINAL_GOAL','REQUIREMENTS');
  check(digest(e.dynamic_plan)===r.dynamic_plan_hash&&digest(e.dynamic_plan)===sealed.plan_hash&&digest(e.node)===r.node_hash&&digest(e.exact_handoff)===r.exact_handoff_hash&&e.dynamic_plan.nodes.some(n=>digest(n)===r.node_hash)&&e.exact_handoff.project_id===r.project_id&&e.exact_handoff.task_id===r.task_id&&e.exact_handoff.plan_hash===r.dynamic_plan_hash&&digest(e.exact_handoff.spec)===digest(pin.spec)&&e.exact_handoff.payload_hash===digest(spec.input),'LITERAL_PLAN_HANDOFF','CHAIN');
  check(digest(r.criterion_requirement_mapping)===digest(spec.criterion_requirement_mapping),'LITERAL_CRITERIA','REQUIREMENTS');
  const receipt=e.d03_receipt,op=operations.find(o=>o.scope.operation_id===receipt?.scope?.operation_id);
  check(receipt?.full_output_bytes===reference.artifact?.bytes&&receipt.truncated===false&&digest(receipt.output)===digest(reference.artifact),'LITERAL_MANIFEST_RECEIPT_BYTES','RECEIPTS');
  check(op?.status==='CONFIRMED'&&!op.retained_reservation&&op.effect_class==='IDEMPOTENT_WRITE'&&op.binding.payload_hash===digest(spec.input)&&digest(op.receipt)===digest(receipt)&&receipt.outcome==='CONFIRMED'&&receipt.scope.project_id===r.project_id&&receipt.scope.task_id===r.task_id&&receipt.payload_hash===digest(spec.input)&&digest(receipt.spec)===digest(pin.spec)&&digest(receipt.epochs)===digest(pin.epochs),'LITERAL_D03_RECEIPT','RECEIPTS');
  const a=e.d09_attempt_ack,output={path:spec.input.path,bytes:bytes.length,sha256:bytesHash(bytes)};
  check(a?.local_profile==='E0_LOCAL_REVIEWED_ONLY'&&a.committed===true&&a.status==='SUCCEEDED'&&a.accounting_status==='SETTLED'&&a.actual_micros==='0'&&a.local_execution_authorized===true&&a.lineage_enforced===true&&a.physical_decision==='DENY'&&a.dispatch_authorized===false&&a.project_id===r.project_id&&a.task_id===r.task_id&&a.operation_id===receipt.scope.operation_id&&a.attempt_id===e.execution.attempt_id&&a.local_binding===e.execution.binding&&a.dynamic_plan_hash===r.dynamic_plan_hash&&a.payload_hash===digest(spec.input)&&a.output_hash===digest(output)&&a.spec_hash===digest(pin.spec)&&digest(a.epochs)===digest(pin.epochs),'LITERAL_REAL_D09_RECEIPT','RECEIPTS');
  check(digest(e.d07_reference)===digest(reference)&&e.independent_readback.reader_id!==e.producer_id&&e.independent_readback.version===reference.version&&e.independent_readback.file_hash===reference.file_hash&&e.independent_readback.provenance_hash===reference.provenance_hash&&e.independent_readback.bytes_hash===bytesHash(bytes)&&e.independent_readback.project_id===r.project_id&&e.independent_readback.task_id===r.task_id,'LITERAL_INDEPENDENT_READBACK','ARTIFACT');
  need(e.logs.length===2&&e.log_authorities.length===2,'LITERAL_REAL_LOGS');
  check(e.qa02_runner_hash===runnerHash()&&new Set(e.logs.map(l=>l.reader_id)).size===2&&new Set(e.log_authorities.map(l=>l.subject)).size===2,'LITERAL_INDEPENDENCE','ISOLATION');
  for(const role of ['independent','auditor']){
   const l=e.logs.find(l=>l.role===role),a=e.log_authorities.find(a=>a.role===role);need(l&&a,'LITERAL_LOG_MISSING');
   const b=Buffer.from(l.bytes_base64,'base64'),log=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b));
   check(a.active===true&&a.valid_until>e.now&&a.subject!==e.producer_subject&&a.id===l.identity_id&&a.generation===l.generation&&l.reader_id!==e.producer_id&&l.reader_id!==l.identity_id&&l.reference.project_id===r.project_id&&l.reference.task_id===r.task_id&&l.reference.file_hash===bytesHash(b)&&l.readback_hash===bytesHash(b)&&l.reference.provenance_hash===l.readback_provenance_hash,'LITERAL_LOG_PROVENANCE','ISOLATION');
   check(log.version==='qa02/1'&&log.role===role&&log.execution_status==='EXECUTED'&&log.verdict==='PASS'&&digest(log.scope)===digest(pin.scope)&&digest(log.spec)===digest(pin.spec)&&digest(log.artifact)===digest(reference)&&log.test_code_hash===e.qa02_runner_hash&&log.rows.length===spec.criterion_requirement_mapping.length&&new Set(log.rows.map(x=>x.criterion_id)).size===log.rows.length,'LITERAL_LOG_BINDING','CHAIN');
   for(const m of spec.criterion_requirement_mapping){const row=log.rows.find(x=>x.criterion_id===m.criterion_id);check(row?.requirement_id===m.requirement_id&&row.status==='PASS'&&row.artifact_sha256===reference.file_hash&&digest(row.expected)===digest(m.check)&&digest(row.actual)===digest(m.check.kind==='exact-text'?spec.input.text:bytesHash(bytes)),'LITERAL_LOG_ASSERTION','FUNCTIONAL');}
   if(role==='auditor')check(log.examiner_hash===e.examiner_report_hash&&log.mutations.length>=2&&log.mutations.every(m=>m.detected===true&&m.artifact_sha256!==reference.file_hash),'LITERAL_MUTATION_SENSITIVITY','CHAIN');
  }
  check(pin.state==='QA_PENDING'&&!pin.cancel_requested&&!pin.restore_pending&&e.completion.work==='WORK_COMPLETED'&&e.completion.accepted===false&&e.completion.physical_decision==='DENY','LITERAL_CURRENT_STATE','ISOLATION');
 }catch{verdict='QA_INCONCLUSIVE';findings.push({code:'LITERAL_MISSING_TRUSTED_EVIDENCE',severity:'BLOCKER',criterion:'ARTIFACT',trace:{path:'$'}});}
 if(verdict==='QA_PASS'&&findings.length)verdict='QA_FAIL';
 return {verdict,policy_version:POLICY+':'+LITERAL_DIALECT,artifact_hash:bytesHash(bytes),findings,trace,criteria:criteria.map(id=>({id,status:verdict==='QA_INCONCLUSIVE'?'INCONCLUSIVE':findings.some(f=>f.criterion===id)?'FAIL':'PASS'}))};
}
