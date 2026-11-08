import {copy,digest,fields,frozen,need,VERSION} from './contracts.mjs';

// Pure return contract. AUTO02 alone owns persisted retry counts, admission,
// task CAS, cancellation, budget and dispatch. This module never retries anything.
export function buildFeedback(gate,context){
 fields(context,['handoff','attempts_used','max_attempts','deadline','remaining_budget_micros','now','outcome_unknown']);
 const {handoff:h,attempts_used:used,max_attempts:max}=context;
 need(h?.project_id===gate.scope.project_id&&h.task_id===gate.scope.task_id&&digest(h.spec)===digest(gate.spec),'AUTO02_SCOPE');
 need(['auto01/1','auto02/1'].includes(h.version),'AUTO02_HANDOFF_VERSION');
 need(typeof h.plan_hash==='string'&&typeof h.node_hash==='string'&&typeof h.node_id==='string'&&Number.isSafeInteger(h.revision)&&Number.isSafeInteger(h.fence),'AUTO02_HANDOFF');
 need(Number.isSafeInteger(used)&&used>=0&&Number.isSafeInteger(max)&&max>=0&&max<=2,'AUTO02_RETRY_LIMIT');
 need(/^(0|[1-9][0-9]*)$/.test(context.remaining_budget_micros),'AUTO02_BUDGET');
 need(Number.isFinite(Date.parse(context.now))&&Number.isFinite(Date.parse(context.deadline))&&typeof context.outcome_unknown==='boolean','AUTO02_CONTEXT');
 let action='ESCALATE',code=gate.reason;
 if(context.outcome_unknown){code='OUTCOME_UNKNOWN_RECONCILIATION_REQUIRED';}
 else if(gate.verdict==='PASS'){action='NONE';code='QA_EVIDENCE_READY_FOR_EXISTING_GATE';}
 else if(used>=max){code='REPAIR_LIMIT_EXHAUSTED';}
 else if(Date.parse(context.now)>=Date.parse(context.deadline)){code='REPAIR_DEADLINE';}
 else if(BigInt(context.remaining_budget_micros)===0n){code='REPAIR_BUDGET';}
 else if(gate.verdict==='FAIL'){action='REWORK';code='REPRODUCIBLE_DEFECT';}
 else if(gate.verdict==='UNCLEAR'){action='COLLECT_EVIDENCE';code='INSUFFICIENT_EVIDENCE';}
 const failures=gate.evidence.flatMap(r=>r.rows.filter(row=>row.status!=='PASS').map(row=>({role:r.role,criterion_id:row.criterion_id,requirement_id:row.requirement_id,code:row.code,status:row.status,evidence_hash:digest(row)})));
 const body={version:'qa02.auto02/1',scope:copy(gate.scope),spec:copy(gate.spec),handoff_hash:digest(h),
  plan_hash:h.plan_hash,node_hash:h.node_hash,node_id:h.node_id,expected_revision:h.revision,fence:h.fence,
  artifact:copy(gate.artifact),profile_hash:gate.profile_hash,evidence_hash:gate.evidence_hash,
  verdict:gate.verdict,action,code,failures,
  repair:{attempts_used:used,max_attempts:max,next_attempt:action==='REWORK'||action==='COLLECT_EVIDENCE'?used+1:null,
   deadline:context.deadline,remaining_budget_micros:context.remaining_budget_micros,
   only_affected_task:true,requires_new_artifact_version:true,requires_full_recheck:true},
  trust:{authority:'CANDIDATE_ONLY',requires_existing_d08_gate:true,requires_current_d03_cas:true,physical_decision:'DENY'}};
 return frozen({...body,idempotency_key:digest({version:VERSION,...body})});
}
