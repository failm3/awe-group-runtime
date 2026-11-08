import {parseIntent,canonicalize,digest,freeze,copy,requireKeys,need,id,hash,micros,integer,denial} from './common.mjs';
import {compileIsolation} from './isolation.mjs';
import {simulateDigest} from './synthetic-executor.mjs';
import {rejectCredentialMaterial} from './secrets.mjs';
import {intentBinding} from './authority.mjs';
import {LOCAL_PROFILE,validateLocalRequest} from './local-reviewed.mjs';
import {isReviewedLocalAdmission} from './local-d09.mjs';
import {executeReviewedStats} from './local-adapter.mjs';
import {executeReviewedText} from './local-text-adapter.mjs';
const requestFields=['v','project_id','task_id','operation_id','attempt_id','effect_slot','idempotency_key','grant_token','tool_id','tool_version','tool_digest','schema_hash','manifest_hash','resource_id','payload','payload_hash','plan_hash','epochs','revision','fence','reserve_micros','expires_at','approval_token'];
/** Trusted host assembly: admission is D09/INT03-owned, not SEC-owned.
 * This module has no physical executor and cannot be switched to E1 by a flag.
 * All injected ports are TCB, not worker-supplied JavaScript objects.
 */
export function createExecutionGate({authority,verifier,registry,admission,audit}){
 const local=admission.profile===LOCAL_PROFILE;
 need(local?isReviewedLocalAdmission(admission):admission.profile==='SEC01_SYNTHETIC_ADMISSION_V1','E0_ADMISSION_PORT_REQUIRED');
 let tail=Promise.resolve(),quarantined=false;
 const serial=fn=>{const n=tail.then(fn);tail=n.catch(()=>{});return n;};
 function check(identity,peer,r){
  need(!quarantined,'HOST_QUARANTINED');requireKeys(r,[...requestFields,...(local?['local']:[])]);need(r.v==='sec01.execution.v1','VERSION_DENIED');
  for(const key of ['project_id','task_id','operation_id','attempt_id','effect_slot','idempotency_key','tool_id','tool_version','resource_id'])id(r[key]);
  for(const key of ['tool_digest','schema_hash','manifest_hash','payload_hash','plan_hash'])hash(r[key]);
  integer(r.revision,1);integer(r.fence,1);integer(r.expires_at);micros(r.reserve_micros);
  need(r.expires_at>verifier.now()&&r.expires_at-verifier.now()<=300000,'REQUEST_EXPIRED');
  need(r.payload_hash===digest(r.payload),'PAYLOAD_PIN_MISMATCH');
  const manifest=registry.resolve(r);registry.validateInput(manifest,r.payload);rejectCredentialMaterial(r.payload);
  need(local?manifest.implementation===LOCAL_PROFILE:manifest.implementation==='FIXED_SYNTHETIC_DIGEST','EXECUTOR_PROFILE_MISMATCH');
  const auth=authority.authorize(identity,peer,r,manifest),plan=local?validateLocalRequest(r,manifest,verifier,auth):compileIsolation(manifest,r.payload);
  // Semantic permissions can be evaluated in E0; credential transfer never runs.
  need(manifest.risk!=='CREDENTIAL_TRANSFER','CREDENTIAL_TRANSFER_DENIED');
  return {manifest,auth,plan,binding:intentBinding(r)};
 }
 async function record(kind,r,code,binding=null){
  // Audit failure closes the gate. No raw input/output, proofs or secret handles.
  await audit.append(freeze({v:'sec01.audit.v1',kind,project_id:r.project_id,task_id:r.task_id,operation_id:r.operation_id,attempt_id:r.attempt_id,code,binding,physical_decision:'DENY'}));
 }
 function receipt(value,r,binding,status){
  need(value&&value.physical_decision==='DENY'&&value.status===status&&value.attempt_id===r.attempt_id&&value.binding===binding&&value.committed===true,'ADMISSION_RECEIPT_INVALID');
 }
 async function quarantine(r){
  quarantined=true;
  try{await admission.flagUnknown({project_id:r.project_id,task_id:r.task_id,attempt_id:r.attempt_id});}catch{}
 }
 return Object.freeze({
  review(identity,peer,text){try{const r=parseIntent(text),d=check(identity,peer,r);return freeze({decision:local?'REVIEWED_LOCAL_CANDIDATE':'ALLOW_SIMULATION',physical_decision:'DENY',binding:d.binding,isolation:d.plan});}catch(e){return denial(e);}},
  execute:(identity,peer,text)=>{
   // Snapshot untrusted bytes before any async scheduling.
   let r;try{r=parseIntent(text);}catch(e){return Promise.resolve(denial(e));}
   const trustedPeer=copy(peer);
   return serial(async()=>{
    let admitted=false,sent=false,d;
    try{
     d=check(identity,trustedPeer,r);
     const barrier=await admission.recoveryBarrier({project_id:r.project_id,task_id:r.task_id});
     need(barrier?.status==='READY'&&barrier.physical_decision==='DENY','RECOVERY_BARRIER_CLOSED');
     d=check(identity,trustedPeer,r);await record('AUTHORIZE',r,local?'LOCAL_REVIEWED_PENDING_D09':'ALLOW_SIMULATION',d.binding);
     d=check(identity,trustedPeer,r);
     // Exact funds, approvals, lineage caps, operation/slot uniqueness are atomic D09 responsibilities.
     // Set before await: a lost response may already have committed.
     admitted=true;
     const a=await admission.admit(freeze({request:copy(r),authorization:d.auth,binding:d.binding}));receipt(a,r,d.binding,'ADMITTED');
     d=check(identity,trustedPeer,r); // revoke/cancel/TTL/version after asynchronous reserve
     sent=true;const s=await admission.markSent({project_id:r.project_id,task_id:r.task_id,attempt_id:r.attempt_id,binding:d.binding});receipt(s,r,d.binding,'SENT');
     d=check(identity,trustedPeer,r); // no await or callback between this check and fixed pure simulation
     const output=local?(r.tool_id==='tool_fs_write'?executeReviewedText({request:r,current:()=>check(identity,trustedPeer,r)}):await executeReviewedStats({request:r,current:()=>check(identity,trustedPeer,r)})):simulateDigest(d.manifest,r.payload);
     const result=await admission.complete({project_id:r.project_id,task_id:r.task_id,attempt_id:r.attempt_id,binding:d.binding,output});receipt(result,r,d.binding,'WORK_COMPLETED');
     // A late callback never restores rights or promotes a cancelled task.
     check(identity,trustedPeer,r);
     await record('WORK_COMPLETED',r,'QA_REQUIRED',d.binding);
     check(identity,trustedPeer,r);
     return freeze({decision:local?'EXECUTED_LOCAL':'SIMULATED',physical_decision:'DENY',work:'WORK_COMPLETED',qa:'QA_NOT_RUN',accepted:false,published:false,attempt_id:r.attempt_id,binding:d.binding,output,...(local?{attempt_ack:result.owner_ack}:{})});
    }catch(e){
     if(admitted){
      // Only explicit known rejection/not-sent evidence may release a reserve.
      if(!sent&&e?.knownNotAdmitted===true)admitted=false;
      else if(!sent&&e?.code&&e.code!=='ADMISSION_RECEIPT_INVALID'){
       try{const cancelled=await admission.cancelKnownPreSend({project_id:r.project_id,task_id:r.task_id,attempt_id:r.attempt_id});if(cancelled?.status!=='NOT_SENT'||cancelled.committed!==true)await quarantine(r);}catch{await quarantine(r);}
      }else await quarantine(r);
     }
     // Invalid untrusted IDs/payloads are never copied into audit error records.
     const result=denial(e);
     // Only trusted scope after successful authorization; never log denied text/tokens.
     try{await audit.append(freeze({v:'sec01.audit.v1',kind:quarantined?'QUARANTINE':'DENY',project_id:d?r.project_id:null,task_id:d?r.task_id:null,
      operation_id:null,attempt_id:null,code:quarantined?'OUTCOME_UNKNOWN':result.code,binding:d?.binding??null,physical_decision:'DENY'}));}catch{}
     if(quarantined)return freeze({...result,code:'OUTCOME_UNKNOWN',work:'OUTCOME_UNKNOWN',operator_action:'RECONCILE_REQUIRED'});
     return result;
    }
   });
  },
  requestPhysicalEffect:()=>freeze({decision:'DENY',physical_decision:'DENY',code:'E0_PHYSICAL_DISPATCH_DISABLED'}),
  submitQa:()=>freeze({decision:'DENY',physical_decision:'DENY',code:'WORKER_QA_FORBIDDEN'}),
  accept:()=>freeze({decision:'DENY',physical_decision:'DENY',code:'OWNER_REQUIRED'})
 });
}
