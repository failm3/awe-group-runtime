import {bytesHash, canonicalize, copy, digest, need, POLICY} from './common.mjs';
import {evaluateDynamic,DYNAMIC_DIALECT} from './dynamic-output.mjs';
import {evaluateLiteral,LITERAL_DIALECT} from './literal-output.mjs';

export const CRITERIA=['ARTIFACT','REQUIREMENTS','FUNCTIONAL','RECEIPTS','CHAIN','CITATIONS','ISOLATION'];
const sequence=['CONTEXT_PREFLIGHT','SYNTHETIC_CHILD','D06_SETTLED','INT01_CANARY','D03_RECEIPT','D07_ARTIFACT'];

// Fixed deterministic inspector; never executes code or follows instructions in an artifact.
export function evaluateExact({bytes, reference, requirements:r, evidence:e, operations, pin}) {
  if(r?.kind===LITERAL_DIALECT)return evaluateLiteral({bytes,reference,requirements:r,evidence:e,operations,pin});
  if(r?.kind===DYNAMIC_DIALECT)return evaluateDynamic({bytes,reference,requirements:r,evidence:e,operations,pin});
  if(r?.kind==='INT04_OUTPUT_V1')return evaluateInt04({bytes,reference,r,e,operations,pin});
  const findings=[], trace=[];
  const check=(ok,code,criterion,path,expected=null,actual=null)=>{
    trace.push({criterion,path,ok:Boolean(ok)});
    if(!ok) findings.push({code,severity:'ERROR',criterion,trace:{path,
      expected_hash:digest(expected),actual_hash:digest(actual)}});
  };
  let output;
  try {
    need(Buffer.isBuffer(bytes) && bytes.length<=32768,'ARTIFACT_SIZE');
    const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes); output=JSON.parse(text);
    check(canonicalize(output)===text,'ARTIFACT_ENCODING','ARTIFACT','$');
    check(bytesHash(bytes)===reference.file_hash && bytes.length===reference.bytes,'ARTIFACT_HASH','ARTIFACT','$bytes',reference.file_hash,bytesHash(bytes));
    check(r.kind==='INT02_OUTPUT_V1' && digest(r.spec)===digest(pin.spec)
      && r.project_id===reference.project_id && r.task_id===reference.task_id,'REQUIREMENTS_MISMATCH','REQUIREMENTS','$requirements');
    check(output.model?.status==='SUCCEEDED' && output.model?.simulated===true && output.model?.physicalDecision==='DENY'
      && output.model?.output?.text===r.expected_text,'FUNCTIONAL_OUTPUT','FUNCTIONAL','model.output.text',r.expected_text,output.model?.output?.text??null);
    check(digest(output.model?.output?.tools??null)===digest(r.expected_tools),'FUNCTIONAL_TOOLS','FUNCTIONAL','model.output.tools');
    const receipt=output.receipt?.receipt, op=operations.find(o=>o.scope.operation_id===receipt?.scope?.operation_id);
    check(Boolean(op && op.status==='CONFIRMED' && op.receipt && digest(op.receipt)===digest(receipt)
      && receipt.outcome==='CONFIRMED' && receipt.scope.project_id===r.project_id && receipt.scope.task_id===r.task_id
      && digest(receipt.spec)===digest(pin.spec) && digest(receipt.epochs)===digest(pin.epochs)),
    'FALSE_TOOL_RECEIPT','RECEIPTS','receipt.receipt');
    check(operations.length>0 && operations.every(o=>o.status==='CONFIRMED' && !o.retained_reservation),
      'UNRESOLVED_OPERATION','RECEIPTS','$operations');
    check(e?.completion?.work==='WORK_COMPLETED' && e.completion.physical_decision==='DENY'
      && e.completion.accepted===false && e.completion.published===false && e.chain?.quarantined===false,
    'OUTCOME_NOT_COMPLETED','CHAIN','$evidence.completion');
    const rows=e?.chain?.rows??[];
    check(rows.length===6 && rows.every((row,i)=>{const {hash,...body}=row;return row.kind===sequence[i]
      && row.sequence===i && row.previous===(i?rows[i-1].hash:null) && hash===digest(body);}),
    'CAUSAL_CHAIN_INVALID','CHAIN','$evidence.chain');
    check(output.chain?.quarantined===false && digest(output.chain?.rows??null)===digest(rows.slice(0,5)),
      'EMBEDDED_CHAIN_MISMATCH','CHAIN','chain');
    const last=rows[5]?.evidence;
    check(last?.file_hash===reference.file_hash && last?.version===reference.version
      && last?.provenance_hash===reference.provenance_hash && digest(last?.reference?.artifact??null)===digest(reference.artifact),
    'ARTIFACT_CHAIN_BINDING','CHAIN','$evidence.chain[5]');
    check(digest(rows[4]?.evidence??null)===digest(output.receipt??null), 'RECEIPT_CHAIN_BINDING','CHAIN','receipt');
    check(digest(rows[2]?.evidence?.model??null)===digest(output.model??null)
      && e.model_operation?.status==='SUCCEEDED' && e.model_operation?.id===rows[2]?.evidence?.operation?.id
      && digest(e.model_operation)===digest(rows[2]?.evidence?.operation??null), 'MODEL_LEDGER_BINDING','CHAIN','model');
    const attempt=e.model_operation?.attempts?.find(a=>a.id===output.model?.attemptId);
    check(Boolean(attempt && attempt.status==='SETTLED' && attempt.simulated===true && attempt.physicalDecision==='DENY'
      && attempt.routeId===output.model.routeId && attempt.settledMicros===output.model.costMicros
      && digest(attempt.usage)===digest(output.model.usage) && e.model_operation.plan.request.projectId===r.project_id
      && e.model_operation.plan.request.taskId===r.task_id), 'FALSE_MODEL_RECEIPT','RECEIPTS','model.attemptId');
    const citations=output.citations??[];
    check(Array.isArray(citations) && citations.length===r.citations.length
      && new Set(citations.map(c=>c.id)).size===citations.length
      && r.citations.every(c=>citations.some(x=>x.id===c.id)), 'CITATION_COVERAGE','CITATIONS','citations');
    for(const c of Array.isArray(citations)?citations:[]) {
      const source=e.sources?.find(s=>s.id===c.id), required=r.citations.find(s=>s.id===c.id);
      check(Boolean(source && required && source.project_id===r.project_id && source.task_id===r.task_id
        && source.version===c.version && bytesHash(Buffer.from(source.text))===c.hash
        && digest(c)===digest(required) && typeof c.quote==='string' && c.quote.length>0 && source.text.includes(c.quote)),
      'FALSE_CITATION','CITATIONS','citations.'+String(c.id));
    }
    check(!r.forbidden_literals.some(s=>text.includes(s)), 'CROSS_PROJECT_LEAKAGE','ISOLATION','$bytes');
    // Optional redundant synthetic opinions can veto, never grant a PASS.
    if(e.opinions && (e.opinions.length<2 || !e.opinions.every(v=>v==='PASS'))) {
      return result('QA_INCONCLUSIVE',[...findings,{code:'VERIFIER_DISAGREEMENT',severity:'BLOCKER',criterion:'REQUIREMENTS',trace:{path:'$opinions'}}]);
    }
    return result(findings.length?'QA_FAIL':'QA_PASS',findings);
  } catch {
    return result('QA_INCONCLUSIVE',[...findings,{code:'MALFORMED_PROOF',severity:'BLOCKER',criterion:'ARTIFACT',trace:{path:'$'}}]);
  }
  function result(verdict,fs) { return {verdict,policy_version:POLICY,artifact_hash:bytesHash(bytes),findings:fs,
    criteria:CRITERIA.map(id=>({id,status:fs.some(f=>f.criterion===id)?'FAIL':verdict==='QA_INCONCLUSIVE'?'INCONCLUSIVE':'PASS'})),trace:copy(trace)}; }
}

// INT04-CR01: additive E0 artifact dialect. The fixed D08 inspector remains the
// only verdict owner; no executable callback or caller-supplied verdict is used.
function evaluateInt04({bytes,reference,r,e,operations,pin}) {
  const findings=[],trace=[];
  const check=(ok,code,criterion)=>{trace.push({criterion,path:code,ok:Boolean(ok)});if(!ok)findings.push({code,severity:'ERROR',criterion,trace:{path:code}});};
  try {
    need(Buffer.isBuffer(bytes)&&bytes.length<=32768,'ARTIFACT_SIZE');
    const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),o=JSON.parse(text);
    check(canonicalize(o)===text&&bytesHash(bytes)===reference.file_hash&&bytes.length===reference.bytes,'INT04_ARTIFACT','ARTIFACT');
    check(o.contract==='INT04_OUTPUT_V1'&&r.project_id===reference.project_id&&r.task_id===reference.task_id
      &&digest(r.spec)===digest(pin.spec)&&digest(o.task)===r.task_hash&&digest(o.plan)===r.plan_hash
      &&digest(e.task)===r.task_hash&&digest(e.plan)===r.plan_hash,'INT04_REQUIREMENTS','REQUIREMENTS');
    const result=o.execution;
    check(result?.decision==='SIMULATED'&&result.physical_decision==='DENY'&&result.accepted===false
      &&digest(result)===digest(e.execution)&&result.binding===e.sec_binding
      &&result.output?.input_hash===digest(r.payload)&&result.output?.text_bytes===Buffer.byteLength(r.payload.text)
      &&result.output?.mode==='E0_SYNTHETIC_ONLY'&&result.output?.physical_decision==='DENY','INT04_DIGEST_RESULT','FUNCTIONAL');
    check(digest(e.tool_manifest)===r.tool_manifest_hash&&e.tool_manifest.implementation==='FIXED_SYNTHETIC_DIGEST'
      &&e.tool_manifest.cost_micros==='0'&&e.tool_manifest.code_digest===r.code_digest,'INT04_EXECUTOR_PIN','ISOLATION');
    const d=o.discovery;
    check(digest(d)===digest(e.discovery)&&d.status==='BOUND_E0_ONLY'&&d.physical_decision==='DENY'
      &&d.runtime_dispatch===false&&d.proposal.tool_id===e.tool_manifest.tool_id
      &&d.proposal.input_schema_digest===e.tool_manifest.schema_hash&&d.proposal.artifact_digest===r.tool_manifest_hash
      &&d.proposal.plan_digest===r.plan_hash&&d.proposal.max_cost_micros==='0','INT04_TR_SEC_BINDING','CHAIN');
    const m=o.model,op=e.model_operation,a=op?.attempts?.find(x=>x.id===m?.attemptId);
    check(m?.status==='SUCCEEDED'&&m.simulated===true&&m.physicalDecision==='DENY'&&m.outputReleased===true
      &&digest(m)===digest(e.model)&&op.status==='SUCCEEDED'&&a?.status==='SETTLED'
      &&a.settledMicros===m.costMicros&&digest(a.usage)===digest(m.usage)
      &&m.receipt.planHash===op.planHash&&m.receipt.costMicros===m.costMicros
      &&m.receipt.accepted===false&&m.receipt.evidence==='SYNTHETIC'
      &&op.plan.request.projectId===r.project_id&&op.plan.request.taskId===r.task_id
      &&op.plan.request.payload.task_hash===r.task_hash&&op.plan.request.payload.plan_hash===r.plan_hash
      &&op.attempts.length===1,'INT04_LLM_LEDGER','RECEIPTS');
    const runs=o.runtime;
    check(digest(runs)===digest(e.runtime)&&runs.parent.status==='WORK_COMPLETED'&&runs.child.status==='WORK_COMPLETED'
      &&runs.parent.physical_decision==='DENY'&&runs.child.physical_decision==='DENY'
      &&runs.parent.authoritative_complete===false&&runs.child.authoritative_complete===false
      &&runs.parent.artifact.artifact_hash===digest(result.output)&&runs.child.artifact.artifact_hash===digest(result.output)
      &&e.child_request.grant.parent_run_id===e.parent_request.grant.run_id
      &&e.child_request.actor_id==='child'&&e.parent_request.actor_id==='worker'
      &&e.child_request.model.id===m.receipt.modelId&&e.parent_request.model.id===m.receipt.modelId,'INT04_RT_CHILD','CHAIN');
    const opState=operations.find(x=>x.scope.operation_id===o.state_receipt?.scope?.operation_id);
    check(opState?.status==='CONFIRMED'&&!opState.retained_reservation&&digest(opState.receipt)===digest(o.state_receipt)
      &&opState.binding.payload_hash===digest(r.payload)&&o.state_receipt.outcome==='CONFIRMED'
      &&digest(o.state_receipt.spec)===digest(pin.spec)&&digest(o.state_receipt.epochs)===digest(pin.epochs),'INT04_D03_RECEIPT','RECEIPTS');
    check(e.completion?.work==='WORK_COMPLETED'&&e.completion.accepted===false&&e.completion.published===false
      &&e.completion.physical_decision==='DENY'&&!pin.cancel_requested&&!pin.restore_pending
      &&pin.state==='QA_PENDING'&&e.physical_dispatches===0,'INT04_COMPLETION','CHAIN');
    check(!r.forbidden_literals.some(x=>text.includes(x)),'INT04_LEAKAGE','ISOLATION');
    check(Array.isArray(o.citations)&&o.citations.length===0,'INT04_CITATIONS','CITATIONS');
    return resultOf(findings.length?'QA_FAIL':'QA_PASS');
  } catch {findings.push({code:'INT04_MALFORMED_PROOF',severity:'BLOCKER',criterion:'ARTIFACT',trace:{path:'$'}});return resultOf('QA_INCONCLUSIVE');}
  function resultOf(verdict){return {verdict,policy_version:POLICY,artifact_hash:bytesHash(bytes),findings,
    criteria:CRITERIA.map(id=>({id,status:findings.some(f=>f.criterion===id)?'FAIL':verdict==='QA_INCONCLUSIVE'?'INCONCLUSIVE':'PASS'})),trace:copy(trace)};}
}
