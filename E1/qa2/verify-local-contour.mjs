import fs from 'node:fs';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {digest} from '../contracts/index.mjs';
import {createMaintenanceMission,createBrokerRegistry,MODEL_POLICY} from '../broker/index.mjs';
import {createPsqlSession,createCoordinator} from '../coordinator/index.mjs';
import {evaluateMaintenanceArtifact} from './maintenance-oracle.mjs';
const hash=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const started_at=new Date().toISOString(),oracleBefore=hash('E1/qa2/maintenance-oracle.mjs');
const reportPath='E1/evidence2/LOCAL-CONTOUR.json',coldPath='E1/evidence2/COLD-READBACK.json';
const report=JSON.parse(fs.readFileSync(reportPath,'utf8')),cold=JSON.parse(fs.readFileSync(coldPath,'utf8'));
assert.equal(report.status,'PASS_REAL_LOCAL_CONTOUR');assert.equal(report.project_id,'prj_code_maintenance');assert.equal(report.accepted,false);assert.equal(report.external_effects,0);assert.equal(report.code_changes_applied,0);
const descriptor=JSON.parse(fs.readFileSync('.private/e1-resource.json','utf8'));
const db=await createPsqlSession(descriptor,{role:'qa'});
try{
 const q=createCoordinator({db,project_id:report.project_id}),state=await q.snapshot(),events=await q.events(),cursor=await q.getCursor(report.cursor.consumer_id);
 const mission=state.missions.find(x=>x.mission_id===report.mission_id);assert.ok(mission);assert.equal(mission.state,'COMPLETE');assert.equal(mission.plan_digest,report.model_plan_digest);assert.equal(cursor.sequence,report.cursor.sequence);
 const suffix=mission.mission_id.replace(/^mission_code_/,'');assert.notEqual(suffix,mission.mission_id);
 const registry=report.run_policy?.registry_created_at?createBrokerRegistry({now:report.run_policy.registry_created_at}):undefined;
 const f=createMaintenanceMission({now:mission.spec.facts_refs[0].created_at,suffix,concise:report.run_policy?.concise??false,...(registry?{registry}:{})});
 assert.equal(digest(f.spec),mission.spec_digest);assert.equal(digest(f.grant),mission.grant_digest);assert.equal(digest(f.source),mission.spec.facts_refs[0].digest);
 const plans=state.plans.filter(x=>x.mission_id===mission.mission_id);assert.equal(plans.length,2);
 for(const p of plans)assert.equal(digest(p.document),p.digest);
 const initial=plans.find(x=>x.revision===1),generated=plans.find(x=>x.revision===2);assert.equal(initial.digest,report.bootstrap_plan_digest);assert.equal(generated.digest,report.model_plan_digest);assert.equal(generated.document.previous_digest,initial.digest);
 const current=state.tasks.filter(x=>x.mission_id===mission.mission_id&&x.is_current),archived=state.task_history.filter(x=>x.mission_id===mission.mission_id).map(x=>x.body);
 assert.equal(current.length,report.current_tasks.length);assert.ok(current.every(x=>x.state==='ACCEPTED'));assert.equal(archived.length,2);
 const rows=new Map();for(const row of [...archived,...current])rows.set(row.plan_digest+'/'+row.task_id,row);
 const checked=[];
 for(const row of rows.values()){
  assert.equal(row.result_hash,digest(row.result));assert.equal(row.result.artifact_digest,digest(row.result.output));
  const phase=({'e1.code.parse':'parse','e1.head.plan':'head','e1.code.review':'review'})[row.document.capability.capability_id];assert.ok(phase);
  const result=evaluateMaintenanceArtifact({fixture:f,phase,output:row.result.output,artifact_digest:row.result.artifact_digest,task:row,...(phase==='head'?{plan:generated.document,draft:row.result.output}:{})});
  assert.equal(result.verdict,'PASS');assert.ok(events.some(e=>e.mission_id===mission.mission_id&&e.kind==='QA_PASS'&&e.body.result_hash===row.result_hash&&e.body.evaluator_id==='e1_qa'));
  checked.push({task_id:row.task_id,plan_digest:row.plan_digest,result_hash:row.result_hash,artifact_digest:row.result.artifact_digest,phase,oracle_verdict:result.verdict,oracle_evidence_digest:result.evidence_digest,oracle_code_digest:result.oracle_code_digest});
 }
 const attempts=state.attempts.filter(x=>x.mission_id===mission.mission_id);assert.equal(attempts.length,report.model_attempts.length);assert.ok(attempts.length>=2);assert.equal(new Set(attempts.map(x=>x.logical_request_id)).size,attempts.length);
 const measured=[];
 for(const attempt of attempts){
  assert.equal(attempt.state,'CONFIRMED');assert.equal(attempt.actual_cost,0);assert.equal(attempt.usage.model,MODEL_POLICY.model);assert.equal(attempt.usage.digest,MODEL_POLICY.digest);assert.equal(attempt.usage.wire_attempts,1);assert.ok(attempt.usage.input_tokens>0&&attempt.usage.output_tokens>0);assert.ok(attempt.provider_ref.startsWith('ollama:'));
  const m=report.model_attempts.find(x=>x.task_id===attempt.task_id);assert.ok(m);assert.equal(m.model.id,MODEL_POLICY.model);assert.equal(m.model.digest,MODEL_POLICY.digest);assert.equal(digest(m.usage),digest(attempt.usage));assert.equal(m.wire_attempts,1);assert.equal(m.accounting_status,'CONFIRMED');
  const types=['MODEL_RESERVED','MODEL_SENDING','MODEL_SETTLED'];const sequence=types.map(kind=>{const rows=events.filter(x=>x.mission_id===mission.mission_id&&x.kind===kind&&x.body.attempt_id===attempt.attempt_id);assert.equal(rows.length,1);return rows[0].sequence;});assert.ok(sequence[0]<sequence[1]&&sequence[1]<sequence[2]);
  measured.push({task_id:attempt.task_id,attempt_id:attempt.attempt_id,state:attempt.state,usage:attempt.usage,model_digest:MODEL_POLICY.digest,provider_ref_kind:'OLLAMA_CREATED_AT',accounting_sequence:sequence});
 }
 assert.equal(state.project.reserved,0);assert.equal(state.project.spent,0);assert.equal(state.project.quota_used,report.ledger.quota_used);assert.ok(state.project.quota_used>=attempts.length);
 assert.equal(cold.mission_id,mission.mission_id);assert.equal(cold.mission_state,'COMPLETE');assert.equal(cold.plan_digest,mission.plan_digest);assert.equal(cold.cursor.sequence,cursor.sequence);assert.notEqual(cold.pid,report.authority_pid);assert.equal(cold.new_model_wire_attempts,0);assert.equal(cold.attempts.length,attempts.length);
 for(const a of cold.attempts){const actual=attempts.find(x=>x.attempt_id===a.attempt_id);assert.ok(actual);assert.equal(a.state,actual.state);assert.equal(digest(a.usage),digest(actual.usage));assert.equal(a.request_hash,actual.request_hash);}
 assert.equal(hash('E1/qa2/maintenance-oracle.mjs'),oracleBefore);
 const previousId=report.run_policy?.previous_unknown_mission;let previousUnknown=null;
 if(previousId){const previous=state.missions.find(x=>x.mission_id===previousId),oldAttempts=state.attempts.filter(x=>x.mission_id===previousId);assert.equal(previous.state,'HOLD');assert.equal(oldAttempts.length,1);assert.equal(oldAttempts[0].state,'OUTCOME_UNKNOWN');assert.equal(oldAttempts[0].usage,null);assert.equal(oldAttempts[0].quota_units,1);assert.equal(events.filter(x=>x.mission_id===previousId&&x.kind==='MODEL_SENDING').length,1);assert.equal(state.leases.some(x=>x.mission_id===previousId),false);previousUnknown={mission_id:previousId,state:'HOLD',attempt_state:'OUTCOME_UNKNOWN',usage:'UNKNOWN',charged_quota_units:1,wire_send_events:1,held_execution_lease:false};}
 const output={schema:'awe.qa2.actual-contour-review/1',status:'PASS_REAL_LOCAL_MODEL_AND_NATIVE_COLD_READBACK',started_at,finished_at:new Date().toISOString(),reviewer_pid:process.pid,authority_pid:report.authority_pid,integrator_cold_pid:cold.pid,independent_qa_database_role:descriptor.roles.qa.database_role,resource_id:descriptor.resource_id,port:5433,mission_id:mission.mission_id,project_id:report.project_id,mission_state:mission.state,revisions:plans.length,model_plan_digest:mission.plan_digest,fixture_reconstruction:'Exact clean fixture independently reconstructed from persisted timestamp/suffix, concise policy and original registry time; spec/grant digests matched. Actual model outputs read from PostgreSQL.',checked_tasks:checked,model_attempts:measured,previous_unknown_preserved:previousUnknown,ledger:{reserved:state.project.reserved,spent:state.project.spent,quota_used:state.project.quota_used},cursor,readback_digest:digest({mission_id:mission.mission_id,plan_digest:mission.plan_digest,current_results:current.map(x=>({task_id:x.task_id,result_hash:x.result_hash})),attempts:measured,cursor}),input_artifacts:[{path:reportPath,sha256:hash(reportPath)},{path:coldPath,sha256:hash(coldPath)}],oracle_sha256:oracleBefore,new_model_wire_attempts:0,external_effects:0,code_fix_implemented:false,helper_function_tests:'NOT_RUN',owner_acceptance:'NOT_ISSUED',limits:['Synthetic local code-maintenance planning/analysis only.','Independent QA re-evaluated stored outputs and hashes; no model generation or write/acceptance operation was performed by this cold verifier.','No G4/G5/G6, production durability, paid/cloud route, or external exactly-once claim.']};
 fs.writeFileSync('E1/qa2/actual-contour-review.json',JSON.stringify(output,null,2)+'\n');
 console.log(JSON.stringify({status:output.status,mission_id:output.mission_id,checked_task_count:checked.length,model_attempts:measured.length,usage:measured.map(x=>({task_id:x.task_id,input_tokens:x.usage.input_tokens,output_tokens:x.usage.output_tokens,latency_ms:x.usage.latency_ms})),report_sha256:hash('E1/qa2/actual-contour-review.json'),new_model_wire_attempts:0},null,2));
}finally{await db.close();}
