import {createHash} from 'node:crypto';
import {canonicalize,digest} from '../../contracts/canonical.mjs';
const bytesHash=b=>'sha256:'+createHash('sha256').update(b).digest('hex');
const criteria=['ARTIFACT','REQUIREMENTS','FUNCTIONAL','RECEIPTS','CHAIN','CITATIONS','ISOLATION'];
// Fixed additional dialect in the existing D08 entry point, not a worker scorer
// or caller-provided PASS. Candidate-only CR, separately source-pinned by SEC.
export function evaluateIntegration01({bytes,reference,requirements:r,evidence:e,operations,pin}){
 const findings=[],trace=[];
 const check=(ok,code,criterion)=>{trace.push({criterion,path:code,ok:Boolean(ok)});if(!ok)findings.push({code,severity:'ERROR',criterion,trace:{path:code}});};
 try{
  if(!Buffer.isBuffer(bytes)||bytes.length>32768)throw Error('ARTIFACT_SIZE');
  const o=JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(bytes));
  check(o.contract==='INTEGRATION01_OUTPUT_V1'&&canonicalize(o)===bytes.toString('utf8')&&bytesHash(bytes)===reference.file_hash&&bytes.length===reference.bytes,'I01_EXACT_ARTIFACT','ARTIFACT');
  check(r.project_id===reference.project_id&&r.task_id===reference.task_id&&digest(r.spec)===digest(pin.spec)&&digest(o.task)===r.task_hash&&digest(o.plan)===r.plan_hash&&digest(e.task)===r.task_hash&&digest(e.plan)===r.plan_hash,'I01_TASK_SPEC_PLAN','REQUIREMENTS');
  const x=o.execution;
  check(x?.decision==='SIMULATED'&&x.physical_decision==='DENY'&&x.accepted===false&&digest(x)===digest(e.execution)&&x.binding===e.sec_binding&&x.output.input_hash===digest(r.payload)&&x.output.text_bytes===Buffer.byteLength(r.payload.text)&&x.output.mode==='E0_SYNTHETIC_ONLY','I01_SEC_FIXED_DIGEST','FUNCTIONAL');
  check(digest(e.tool_manifest)===r.tool_manifest_hash&&e.tool_manifest.implementation==='FIXED_SYNTHETIC_DIGEST'&&e.tool_manifest.cost_micros==='0'&&e.tool_manifest.code_digest===r.code_digest,'I01_EXECUTOR_PIN','ISOLATION');
  const d=o.discovery;
  check(digest(d)===digest(e.discovery)&&d.status==='BOUND_E0_ONLY'&&d.physical_decision==='DENY'&&d.runtime_dispatch===false&&d.proposal.tool_id===e.tool_manifest.tool_id&&d.proposal.input_schema_digest===e.tool_manifest.schema_hash&&d.proposal.artifact_digest===r.tool_manifest_hash&&d.proposal.plan_digest===r.plan_hash&&d.proposal.max_cost_micros==='0','I01_TR_SEC','CHAIN');
  const m=o.model,op=e.model_operation,a=op?.attempts?.find(a=>a.id===m?.attemptId),req=op?.plan?.request,ctx=req?.payload?.context,mc=ctx&&JSON.parse(ctx.snapshot);
  check(m?.status==='SUCCEEDED'&&m.simulated===true&&m.physicalDecision==='DENY'&&m.outputReleased===true&&digest(m)===digest(e.model)&&op.status==='SUCCEEDED'&&op.attempts.length===1&&a?.status==='SETTLED'&&a.settledMicros===m.costMicros&&digest(a.usage)===digest(m.usage)&&m.receipt.planHash===op.planHash&&m.receipt.costMicros===m.costMicros&&m.receipt.accepted===false&&m.receipt.evidence==='SYNTHETIC','I01_D06_SINGLE_ATTEMPT','RECEIPTS');
  check(req.projectId===r.project_id&&req.taskId===r.task_id&&req.maxAttempts===1&&req.payload.format==='LLM01_TASK_MODEL_REQUEST_V1'&&req.payload.brokerScope.projectId===r.project_id&&req.payload.brokerScope.taskId===r.task_id&&ctx.readonly===true&&ctx.project_id===r.project_id&&ctx.task_id===r.task_id&&ctx.hash===digest({text:ctx.snapshot})&&mc.task_hash===r.task_hash&&mc.plan_hash===r.plan_hash&&mc.text===r.payload.text,'I01_BROKER_TASK_CONTEXT','ISOLATION');
  const ce=m.integrationContextEvidence;check(ce&&digest(ce.reference)===ctx.artifact_ref&&ce.reference.artifact.project_id===r.project_id&&ce.version===ce.readback_version&&Number.isSafeInteger(ce.version)&&ce.version>0&&ce.readback_hash===bytesHash(Buffer.from(ctx.snapshot)),'I01_MODEL_CONTEXT_D07','ARTIFACT');
  const observed=m.execution,attempt=observed?.attempts?.[0];
  const {evidenceHash,...body}=observed??{};
  check(observed?.version==='LLM01_EXECUTION_EVIDENCE_V1'&&evidenceHash===digest(body)&&observed.physicalDecision==='DENY'&&observed.planHash===op.planHash&&observed.contextHash===ctx.hash&&observed.attempts.length===1&&attempt.attemptId===a.id&&attempt.status==='SETTLED'&&attempt.observedCall?.attemptId===a.id&&attempt.observedCall.payloadHash===digest(req.payload)&&attempt.observedCall.modelId===m.receipt.modelId&&attempt.observedCall.idempotencyKey===a.idempotencyKey&&observed.responseHash===digest(m.output)&&attempt.costMicros===m.costMicros,'I01_OBSERVED_MOCK_BROKER','RECEIPTS');
  const pe=o.processEvidence,runs=o.runtime;
  check(digest(runs)===digest(e.runtime)&&digest(pe)===digest(e.processEvidence)&&runs.parent.status==='WORK_COMPLETED'&&runs.child.status==='WORK_COMPLETED'&&runs.parent.physical_decision==='DENY'&&runs.child.physical_decision==='DENY'&&runs.parent.authoritative_complete===false&&runs.child.authoritative_complete===false&&e.child_request.grant.parent_run_id===e.parent_request.grant.run_id&&e.child_request.actor_id==='child'&&e.parent_request.actor_id==='worker'&&e.child_request.model.id===m.receipt.modelId&&e.parent_request.model.id===m.receipt.modelId,'I01_RT_LINEAGE','CHAIN');
  const context=canonicalize({task:e.task,plan:e.plan}),contextHash=digest({text:context});
  check(pe.contract==='int04.rt01.process/1'&&pe.physical_decision==='DENY'&&pe.full_transcripts_transferred===false&&pe.processes.spawn_count===2&&pe.processes.active===0&&pe.processes.runs.length===2&&new Set(pe.processes.runs.map(p=>p.pid)).size===2&&pe.processes.runs.every(p=>Number.isSafeInteger(p.pid)&&p.pid>0&&p.exited===true&&p.exit_code===0&&p.fault===null)&&e.parent_request.context.hash===contextHash&&e.child_request.context.hash===contextHash,'I01_REAL_PROCESS_EXIT_CONTEXT','ISOLATION');
  check(pe.outputs.length===2&&new Set(pe.outputs.map(p=>p.run_id)).size===2,'I01_PROCESS_OUTPUT_COUNT','ARTIFACT');
  for(const v of pe.outputs){const run=v.run_id==='run_int04_child'?runs.child:v.run_id==='run_int04_parent'?runs.parent:null,outputBytes=Buffer.from(canonicalize(v.output)),record=pe.processes.runs.find(p=>p.run_id===v.run_id);
   check(run&&Object.keys(v.output).sort().join()===['schema','input_hash','utf8_bytes'].sort().join()&&v.output.schema==='rt01.process.result/1'&&v.output.input_hash===bytesHash(Buffer.from(context))&&v.output.utf8_bytes===Buffer.byteLength(context)&&digest(v.artifact)===digest(run.artifact)&&v.artifact.artifact_hash===bytesHash(outputBytes)&&v.readback_hash===bytesHash(outputBytes)&&v.bytes===outputBytes.length&&record.output_ref===v.artifact.artifact_ref&&v.stored_reference.artifact.project_id===r.project_id&&Number.isSafeInteger(v.stored_version)&&v.stored_version>0&&v.stored_version===v.readback_version&&v.readback_path==='site/index.txt'&&digest(v.readback_artifact)===digest(v.stored_reference.artifact),'I01_PROCESS_D07_READBACK','ARTIFACT');
  }
  const state=operations.find(v=>v.scope.operation_id===o.state_receipt?.scope?.operation_id);
  check(state?.status==='CONFIRMED'&&!state.retained_reservation&&digest(state.receipt)===digest(o.state_receipt)&&state.binding.payload_hash===digest(r.payload)&&o.state_receipt.outcome==='CONFIRMED'&&digest(o.state_receipt.spec)===digest(pin.spec)&&digest(o.state_receipt.epochs)===digest(pin.epochs),'I01_D03_RECEIPT','RECEIPTS');
  check(e.physical_dispatches===0&&e.completion.work==='WORK_COMPLETED'&&e.completion.physical_decision==='DENY'&&e.completion.accepted===false&&e.completion.published===false&&pin.state==='QA_PENDING'&&!pin.cancel_requested&&!pin.restore_pending,'I01_NO_FALSE_COMPLETE','CHAIN');
  check(!r.forbidden_literals.some(s=>bytes.toString('utf8').includes(s)),'I01_LEAKAGE','ISOLATION');
  check(Array.isArray(o.citations)&&o.citations.length===0,'I01_NO_FAKE_CITATIONS','CITATIONS');
 }catch{findings.push({code:'I01_MALFORMED_EVIDENCE',severity:'BLOCKER',criterion:'ARTIFACT',trace:{path:'$'}});return result('QA_INCONCLUSIVE');}
 return result(findings.length?'QA_FAIL':'QA_PASS');
 function result(verdict){return {verdict,policy_version:'INTEGRATION01_D08_CANDIDATE_V1',artifact_hash:bytesHash(bytes),findings,criteria:criteria.map(id=>({id,status:findings.some(f=>f.criterion===id)?'FAIL':verdict==='QA_INCONCLUSIVE'?'INCONCLUSIVE':'PASS'})),trace};}
}
