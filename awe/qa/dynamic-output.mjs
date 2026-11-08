import {bytesHash,canonicalize,digest,need,POLICY} from './common.mjs';
import {runnerHash} from '../qa_profiles/runner.mjs';
export const DYNAMIC_DIALECT='OWNER02_TEXT_STATS_V1';
export const DYNAMIC_CRITERIA=['ARTIFACT','REQUIREMENTS','FUNCTIONAL','RECEIPTS','CHAIN','CITATIONS','ISOLATION'];
// Bounded, data-only dialect. D08 computes the function independently of QA02.
// The evidence argument MUST come from the trusted D08 store/reader, never the
// worker's bundle. QA02 opinions alone cannot satisfy receipt or log readback.
export function evaluateDynamic({bytes,reference,requirements:r,evidence:e,operations,pin}){
 const findings=[],trace=[];
 const check=(v,code,criterion)=>{trace.push({criterion,path:code,ok:Boolean(v)});if(!v)findings.push({code,severity:'ERROR',criterion,trace:{path:code}});};
 try{
  need(Buffer.isBuffer(bytes)&&bytes.length<=32768,'DYNAMIC_ARTIFACT_SIZE');
  const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),o=JSON.parse(text),spec=r.immutable_spec;
  check(canonicalize(o)===text&&bytesHash(bytes)===reference.file_hash&&bytes.length===reference.bytes&&o.contract===DYNAMIC_DIALECT,'DYNAMIC_EXACT_ARTIFACT','ARTIFACT');
  check(r.project_id===reference.project_id&&r.task_id===reference.task_id&&digest(r.spec)===digest(pin.spec)&&digest(e.current_spec)===digest(pin.spec)&&digest(spec)===pin.spec.content_hash&&spec.dialect===DYNAMIC_DIALECT&&typeof spec.input.text==='string'&&Buffer.byteLength(spec.input.text)<=4096,'DYNAMIC_SPEC','REQUIREMENTS');
  check(bytesHash(Buffer.from(e.original_user_goal))===r.original_user_goal_hash&&spec.original_user_goal_hash===r.original_user_goal_hash&&o.original_user_goal_hash===r.original_user_goal_hash,'DYNAMIC_ORIGINAL_GOAL','REQUIREMENTS');
  check(digest(e.dynamic_plan)===r.dynamic_plan_hash&&digest(e.node)===r.node_hash&&digest(e.exact_handoff)===r.exact_handoff_hash&&e.dynamic_plan.nodes.some(n=>digest(n)===r.node_hash)&&e.exact_handoff.project_id===r.project_id&&e.exact_handoff.task_id===r.task_id&&e.exact_handoff.plan_hash===r.dynamic_plan_hash&&e.exact_handoff.node_hash===r.node_hash&&digest(e.exact_handoff.spec)===digest(pin.spec)&&o.dynamic_plan_hash===r.dynamic_plan_hash&&o.node_hash===r.node_hash&&o.exact_handoff_hash===r.exact_handoff_hash,'DYNAMIC_HANDOFF','CHAIN');
  const input=spec.input.text,expected={utf8_bytes:Buffer.byteLength(input),code_points:[...input].length,lines:input.split('\n').length,sha256:bytesHash(Buffer.from(input))};
  check(digest(o.output)===digest(expected),'DYNAMIC_FUNCTIONAL_RECOMPUTED','FUNCTIONAL');
  const mapping=['utf8_bytes','code_points','lines','sha256'].map((field,i)=>({criterion_id:'Q0'+(i+1),requirement_id:'req_'+field,field}));
  check(digest(r.criterion_requirement_mapping)===digest(mapping)&&digest(spec.criterion_requirement_mapping)===digest(mapping),'DYNAMIC_CRITERIA_MAPPING','REQUIREMENTS');
  const receipt=e.d03_receipt,op=operations.find(x=>x.scope.operation_id===receipt?.scope?.operation_id);
  check(op?.status==='CONFIRMED'&&!op.retained_reservation&&op.binding.payload_hash===digest(spec.input)&&receipt.payload_hash===digest(spec.input)&&digest(op.receipt)===digest(receipt)&&receipt.outcome==='CONFIRMED'&&receipt.scope.project_id===r.project_id&&receipt.scope.task_id===r.task_id&&digest(receipt.spec)===digest(pin.spec)&&digest(receipt.epochs)===digest(pin.epochs),'DYNAMIC_D03_RECEIPT','RECEIPTS');
  const a=e.d09_attempt_ack;
  check(a?.local_profile==='E0_LOCAL_REVIEWED_ONLY'&&a.committed===true&&a.status==='SUCCEEDED'&&a.local_execution_authorized===true&&a.lineage_enforced===true&&a.physical_decision==='DENY'&&a.dispatch_authorized===false&&a.project_id===r.project_id&&a.task_id===r.task_id&&a.operation_id===receipt.scope.operation_id&&a.attempt_id===e.execution.attempt_id&&a.local_binding===e.execution.binding&&a.dynamic_plan_hash===r.dynamic_plan_hash&&a.payload_hash===digest(spec.input)&&a.output_hash===digest(o.output)&&a.spec_hash===digest(pin.spec)&&digest(a.epochs)===digest(pin.epochs),'DYNAMIC_D09_ACK','RECEIPTS');
  check(digest(e.d07_reference)===digest(reference)&&e.independent_readback.reader_id!==e.producer_id&&e.independent_readback.project_id===r.project_id&&e.independent_readback.task_id===r.task_id&&e.independent_readback.version===reference.version&&e.independent_readback.file_hash===reference.file_hash&&e.independent_readback.provenance_hash===reference.provenance_hash&&e.independent_readback.bytes_hash===bytesHash(bytes),'DYNAMIC_SCOPED_READBACK','ARTIFACT');
  need(Array.isArray(e.logs)&&e.logs.length===2&&e.log_authorities.length===2,'DYNAMIC_LOGS_REQUIRED');
  check(e.qa02_runner_hash===runnerHash(),'DYNAMIC_RUNNER_PIN','ISOLATION');
  check(new Set(e.logs.map(x=>x.reader_id)).size===2,'DYNAMIC_LOG_READERS','ISOLATION');
  for(const role of ['independent','auditor']){
   const l=e.logs.find(x=>x.role===role),authority=e.log_authorities.find(x=>x.role===role);
   need(l&&authority,'DYNAMIC_LOG_MISSING');const logBytes=Buffer.from(l.bytes_base64,'base64'),log=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(logBytes));
   check(authority.active===true&&authority.valid_until>e.now&&authority.generation===l.generation&&authority.id===l.identity_id&&authority.subject!==e.producer_subject&&l.reader_id!==l.identity_id&&l.reference.project_id===r.project_id&&l.reference.task_id===r.task_id&&l.reference.version>0&&l.reference.file_hash===bytesHash(logBytes)&&l.readback_hash===bytesHash(logBytes)&&l.reference.provenance_hash===l.readback_provenance_hash&&canonicalize(log)===logBytes.toString('utf8'),'DYNAMIC_LOG_PROVENANCE','ISOLATION');
   check(log.version==='qa02/1'&&log.role===role&&log.execution_status==='EXECUTED'&&log.verdict==='PASS'&&digest(log.scope)===digest(pin.scope)&&digest(log.spec)===digest(pin.spec)&&digest(log.artifact)===digest(reference)&&log.test_code_hash===e.qa02_runner_hash&&log.rows.length===mapping.length&&new Set(log.rows.map(x=>x.criterion_id)).size===mapping.length,'DYNAMIC_LOG_BINDING','CHAIN');
   for(const m of mapping){const row=log.rows.find(x=>x.criterion_id===m.criterion_id);check(row?.requirement_id===m.requirement_id&&row.status==='PASS'&&row.artifact_sha256===reference.file_hash&&digest(row.expected)===digest({kind:'json-field',path:['output',m.field],expected:expected[m.field]})&&digest(row.actual)===digest(expected[m.field]),'DYNAMIC_LOG_ASSERTION','FUNCTIONAL');}
   if(role==='auditor')check(log.mutations.length>0&&log.mutations.every(x=>x.detected===true)&&log.examiner_hash===e.examiner_report_hash,'DYNAMIC_AUDITOR_MUTATIONS','CHAIN');
  }
  check(new Set(e.log_authorities.map(x=>x.subject)).size===2&&!pin.cancel_requested&&!pin.restore_pending&&pin.state==='QA_PENDING'&&e.completion.work==='WORK_COMPLETED'&&e.completion.accepted===false&&e.completion.physical_decision==='DENY','DYNAMIC_CURRENT_AUTHORITY','ISOLATION');
  check(Array.isArray(o.citations)&&o.citations.length===0,'DYNAMIC_CITATIONS','CITATIONS');
 }catch{findings.push({code:'DYNAMIC_MALFORMED_EVIDENCE',severity:'BLOCKER',criterion:'ARTIFACT',trace:{path:'$'}});return result('QA_INCONCLUSIVE');}
 return result(findings.length?'QA_FAIL':'QA_PASS');
 function result(verdict){return {verdict,policy_version:POLICY+':'+DYNAMIC_DIALECT,artifact_hash:bytesHash(bytes),findings,trace,criteria:DYNAMIC_CRITERIA.map(id=>({id,status:findings.some(f=>f.criterion===id)?'FAIL':verdict==='QA_INCONCLUSIVE'?'INCONCLUSIVE':'PASS'}))};}
}
