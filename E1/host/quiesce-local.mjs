import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {digest,need} from '../contracts/index.mjs';
import {createPsqlSession,createCoordinator,LOCAL_MODEL_QUIESCENCE} from '../coordinator/index.mjs';

/** Manual host operation after a reviewed local timeout. Never called by the
 * broker/worker or scheduler; it cannot settle, requeue or retry an attempt. */
export async function quiesceReviewedLocalTimeout({resourcePath,suffix}){
  need(process.platform==='win32'&&/^[a-z0-9_-]{1,24}$/.test(suffix),'E1_LOCAL_OPERATOR_SCOPE');
  const failure=JSON.parse(fs.readFileSync('.private/canary-'+suffix+'/failure.json','utf8'));
  need(failure.status==='FAILED_OR_HOLD'&&failure.model_attempts.length===1&&failure.model_attempts[0].accounting_status==='UNKNOWN'&&failure.model_attempts[0].wire_attempts===1,'E1_SINGLE_UNKNOWN_TIMEOUT_REQUIRED');
  const resource=JSON.parse(fs.readFileSync(resourcePath,'utf8')),db=await createPsqlSession(resource,{role:'coordinator'});
  try{
    const coordinator=createCoordinator({db,project_id:failure.project_id}),before=await coordinator.snapshot();
    const mission=before.missions.find(m=>m.mission_id===failure.mission_id),attempts=before.attempts.filter(a=>a.mission_id===failure.mission_id);
    need(mission?.state==='HOLD'&&attempts.length===1&&attempts[0].state==='OUTCOME_UNKNOWN'&&attempts[0].usage===null,'E1_UNKNOWN_PERSISTED_SCOPE');
    const attempt=attempts[0],task=before.tasks.find(t=>t.mission_id===failure.mission_id&&t.task_id===attempt.task_id);
    need(task?.state==='HOLD'&&attempt.route_id===LOCAL_MODEL_QUIESCENCE.route_id,'E1_LOCAL_UNKNOWN_SCOPE');
    const filename=path.join(process.env.LOCALAPPDATA,'Ollama','server.log'),st=fs.statSync(filename);
    need(st.isFile()&&!fs.lstatSync(filename).isSymbolicLink()&&st.size<=32*1024*1024,'E1_OLLAMA_LOG_BOUND');
    const log=fs.readFileSync(filename,'utf8'),lines=log.split(/\r?\n/);
    // Match the single HTTP failure at the observed end of this exact request.
    // Server GIN dates use the Windows local timezone; no log is uploaded.
    const ended=Date.parse(failure.finished_at),matches=[];
    for(let i=0;i<lines.length;i++){
      const m=/\[GIN\] (\d{4})\/(\d\d)\/(\d\d) - (\d\d:\d\d:\d\d) \| 500 \|\s*2m0s\s*\|\s*127\.0\.0\.1 \| POST\s+"\/api\/generate"/.exec(lines[i]);
      if(m&&Math.abs(Date.parse(`${m[1]}-${m[2]}-${m[3]}T${m[4]}`)-ended)<=2000)matches.push(i);
    }
    need(matches.length===1,'E1_CANCEL_LOG_SCOPE');
    const start=matches[0],tail=lines.slice(start+1,start+7),cancelled=tail.find(x=>/srv\s+stop: cancel task, id_task = \d+/.test(x)),released=tail.find(x=>/slot\s+release:.*stop processing:/.test(x)),idle=tail.find(x=>/srv\s+update_slots: all slots are idle/.test(x));
    need(cancelled&&released&&idle,'E1_COMPLETED_CANCEL_REQUIRED');
    need(!lines.slice(start+1).some(x=>/POST\s+"\/api\/generate"/.test(x)),'E1_LATER_MODEL_REQUEST_REQUIRES_REVIEW');
    const prefix='artifact:e1-quiescence/'+suffix,artifacts=[];
    function evidence(kind,value){const row={ref:prefix+'/'+kind,value};artifacts.push(row);return {ref:row.ref,digest:digest(value),observed_at:value.observed_at};}
    const cancel=evidence('completed-cancel',{schema:'awe.e1.observed-ollama-cancel/1',observed_at:new Date().toISOString(),mission_id:mission.mission_id,attempt_id:attempt.attempt_id,request_hash:attempt.request_hash,http_500_at:failure.finished_at,completed_cancel:true,slot_idle_in_same_log_window:true,matched_log_lines_digest:digest([lines[start],cancelled,released,idle]),usage:'UNKNOWN_NO_FINAL_ACK',log_uploaded:false});
    async function readIdle(kind){const response=await fetch('http://127.0.0.1:11434/api/ps',{redirect:'error',signal:AbortSignal.timeout(10000)});need(response.ok&&!response.redirected,'E1_IDLE_READ_FAILED');const text=await response.text();need(Buffer.byteLength(text)<=65536,'E1_IDLE_READ_BOUND');const value=JSON.parse(text);need(Array.isArray(value.models)&&value.models.length===0,'E1_LOCAL_MODEL_NOT_IDLE');return evidence(kind,{schema:'awe.e1.observed-ollama-idle/1',observed_at:new Date().toISOString(),model_count:0,response_digest:digest(value),new_generation_requests:0});}
    const first=await readIdle('idle-one');await new Promise(resolve=>setTimeout(resolve,1100));const second=await readIdle('idle-two');
    const raw=execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',"@(Get-Process | Where-Object { $_.ProcessName -match 'llama.*server|ollama.*runner' }).Count"],{encoding:'utf8',windowsHide:true,timeout:10000});
    need(raw.trim()==='0','E1_LOCAL_RUNNER_PRESENT');
    const absence=evidence('runner-absence',{schema:'awe.e1.observed-local-runner/1',observed_at:new Date().toISOString(),runner_process_count:0,method:'WINDOWS_PROCESS_NAME_QUERY',process_arguments_collected:false});
    const scope=Object.fromEntries(['mission_id','task_id','logical_request_id','attempt_id','worker_id','fence'].map(k=>[k,attempt[k]]));
    const ref=(v,schema,status)=>({schema,...v,status});
    const proof={...LOCAL_MODEL_QUIESCENCE,...scope,project_id:failure.project_id,fence:String(attempt.fence),effect_class:'NONE',observed_at:new Date().toISOString(),proof_ref:prefix+'/operator-attestation',cancellation:ref(cancel,'awe.e1.local-cancel-proof-ref/1','COMPLETED'),idle_observations:[ref(first,'awe.e1.local-idle-proof-ref/1','IDLE'),ref(second,'awe.e1.local-idle-proof-ref/1','IDLE')],runner_absence:ref(absence,'awe.e1.local-runner-absence-proof-ref/1','ABSENT')};
    // Recheck every attested artifact commitment before the direct host call.
    for(const item of [proof.cancellation,...proof.idle_observations,proof.runner_absence])need(digest(artifacts.find(a=>a.ref===item.ref).value)===item.digest,'E1_OBSERVED_PROOF_DIGEST');
    // Preserve the exact host proof before mutation for crash readback/replay;
    // a rerun must not silently replace it with a different attestation.
    fs.writeFileSync('.private/quiescence-'+suffix+'.json',JSON.stringify({scope,proof,proof_digest:digest(proof),observations:artifacts},null,2)+'\n',{flag:'wx',flush:true});
    const receipt=await coordinator.quiesceLocalModel({...scope,proof,proof_digest:digest(proof)}),after=await coordinator.snapshot();
    need(digest(after.project)===digest(before.project)&&digest(after.attempts)===digest(before.attempts)&&digest(after.missions)===digest(before.missions),'E1_QUIESCENCE_CHANGED_ACCOUNTING');
    need(!after.leases.some(l=>l.mission_id===mission.mission_id&&l.task_id===attempt.task_id),'E1_QUIESCENCE_LEASE_REMAINS');
    const report={schema:'awe.e1.actual-local-quiescence/1',status:'QUIESCED_EXECUTION_ONLY_UNKNOWN_RETAINED',mission_id:mission.mission_id,project_id:failure.project_id,proof,proof_digest:digest(proof),observations:artifacts,receipt,ledger:{before:before.project,after:after.project},original_attempt_unchanged:true,original_mission_unchanged:true,original_task_state:'HOLD',usage:'UNKNOWN',new_model_wire_attempts:0,quota_refunded:0,external_effects:0,accepted:false,limitations:['Host/operator attestation over observed local cancellation and repeated physical idle; no provider usage or successful model output was recovered.','This does not authorize retry/resume of the held logical request.']};
    fs.mkdirSync('E1/evidence2',{recursive:true});fs.writeFileSync('E1/evidence2/ACTUAL-LOCAL-QUIESCENCE.json',JSON.stringify(report,null,2)+'\n',{flag:'wx'});
    console.log(JSON.stringify({status:report.status,mission_id:mission.mission_id,quota_used:after.project.quota_used,new_fence:receipt.new_fence,new_model_requests:0}));return report;
  }finally{await db.close();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  need(process.argv[2]==='--reviewed-local-timeout'&&process.argv.length===5,'E1_EXPLICIT_LOCAL_OPERATOR_COMMAND');
  await quiesceReviewedLocalTimeout({resourcePath:process.argv[3],suffix:process.argv[4]});
}
