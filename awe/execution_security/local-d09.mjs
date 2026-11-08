import {createPostgresPersistence,createPostgresLocalPersistence} from '../persistence/postgres.mjs';
import {copy,digest,need,freeze} from './common.mjs';
import {LOCAL_PROFILE} from './local-reviewed.mjs';
const ports=new WeakSet();
const completions=new WeakSet();
export const isReviewedLocalAdmission=port=>ports.has(port);
export const isReviewedLocalCompletion=value=>completions.has(value);
const registrars=new WeakSet();
export const isLocalPlanRegistrar=value=>registrars.has(value);
// Separate issuer session, fixed SQL endpoint, no worker DML or JS ALLOW.
// SQL006 is a prepared producer candidate; real DB validation/enrollment is
// required. Missing migration, policy or registered identity is always a stop.
export function createLocalPlanRegistrar({issuerPool,authority,registry}){
 need(issuerPool?.connect&&authority?.lineageFor&&registry?.resolve,'D09_LOCAL_ISSUER_POOL_REQUIRED');
 const port=Object.freeze({async register({request,identity,peer,binding}){
  const authorization=authority.authorize(identity,peer,request,registry.resolve(request));
  need(binding===digest(Object.fromEntries(Object.entries(request).filter(([k])=>k!=='approval_token'))),'D09_LOCAL_REGISTRATION_BINDING');
  const lineage=authority.lineageFor(request.grant_token);
  const plan_hash=digest({profile:LOCAL_PROFILE,request,authorization,binding});let client,began=false,committing=false,broken=false;
  try{client=await issuerPool.connect();await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');began=true;await client.query('SET LOCAL synchronous_commit = on');await client.query("SET LOCAL statement_timeout = '10s'");
   const response=await client.query('SELECT awe_d09.register_local_master01($1::jsonb) AS result',[JSON.stringify({profile:LOCAL_PROFILE,request,authorization,lineage,binding,plan_hash})]);const r=response.rows?.[0]?.result;
   need(r?.status==='REGISTERED'&&r.physical_decision==='DENY'&&r.project_id===request.project_id&&r.task_id===request.task_id&&r.plan_hash===plan_hash&&r.local_binding===binding&&r.lineage_enforced===true,'D09_LOCAL_REGISTRATION_NOT_BOUND');committing=true;await client.query('COMMIT');began=false;return freeze({...copy(r),committed:true});
  }catch(e){broken=true;if(began)try{await client.query('ROLLBACK');}catch{}const x=Error(committing?'D09_LOCAL_REGISTRATION_OUTCOME_UNKNOWN':'D09_LOCAL_REGISTRATION_UNAVAILABLE');x.outcomeUnknown=committing;throw x;}
  finally{try{const close=await client?.release(broken);need(close?.released!==false,'D09_LOCAL_CLIENT_CLOSE_UNPROVEN');}catch(e){if(!broken)throw e;}}
 }});registrars.add(port);return port;
}
// No SQL/function/ledger is added here. The existing D09 must explicitly attest
// local permission and ALL lineage limits. Current deployed-offline schema does
// not issue that receipt: it stays blocked, even when ordinary ADMITTED succeeds.
export function createReviewedLocalAdmission({pool,master01=false}){
 const db=master01?createPostgresLocalPersistence(pool):createPostgresPersistence(pool),attempts=new Map();let hold=false;
 const receipt=(r,binding,status)=>freeze({profile:LOCAL_PROFILE,physical_decision:'DENY',status,attempt_id:r.attempt_id,binding,committed:true});
 function attest(x,r,binding,status){need(x?.status===status&&x.project_id===r.project_id&&x.task_id===r.task_id&&x.attempt_id===r.attempt_id&&x.physical_decision==='DENY'&&x.dispatch_authorized===false&&x.local_execution_authorized===true&&x.local_profile===LOCAL_PROFILE&&x.local_binding===binding&&x.lineage_enforced===true&&x.committed===true,'D09_LOCAL_AUTHORITY_NOT_BOUND');}
 const port={profile:LOCAL_PROFILE,
  async recoveryBarrier(r){need(!hold,'D09_LOCAL_HOLD');let x;try{x=await db.recover({project_id:r.project_id,...(master01?{task_id:r.task_id}:{})});}catch{need(false,'D09_LOCAL_AUTHORITY_UNAVAILABLE');}need(x.status==='READY'&&x.local_profile===LOCAL_PROFILE&&x.local_execution_authorized===true,'D09_LOCAL_AUTHORITY_NOT_BOUND');return {status:'READY',physical_decision:'DENY'};},
  async admit({request:r,authorization:a,binding}){
   need(!hold,'D09_LOCAL_HOLD');need(a.lineage?.length>0,'D09_LINEAGE_REQUIRED');
   // Full request, actor, signed lineage, lease, pins and limits are committed by
   // the plan binding; D09 must compare this to its owner-approved exact plan.
   const plan_hash=digest({profile:LOCAL_PROFILE,request:r,authorization:a,binding});
   const cmd={project_id:r.project_id,task_id:r.task_id,operation_id:r.operation_id,attempt_id:r.attempt_id,effect_slot:r.effect_slot,approval_id:r.local.d09_approval_id,grant_id:a.grant_id,idempotency_key:r.idempotency_key,plan_hash,payload_hash:r.payload_hash,reserve_micros:r.reserve_micros};
   const x=await db.admit(cmd);attest(x,r,binding,'ADMITTED');need(x.plan_hash===plan_hash,'D09_LOCAL_PLAN_MISMATCH');attempts.set(r.attempt_id,{request:copy(r),binding,plan_hash,fence:null});return receipt(r,binding,'ADMITTED');
  },
  async markSent(r){const a=attempts.get(r.attempt_id);need(a&&a.binding===r.binding,'D09_LOCAL_ATTEMPT_UNKNOWN');const c=await db.claim({project_id:r.project_id,attempt_id:r.attempt_id});attest(c,a.request,r.binding,'CLAIMED');need(Number.isSafeInteger(c.delivery_fence)&&c.delivery_fence>0,'D09_LOCAL_FENCE');a.fence=c.delivery_fence;const x=await db.markSent({project_id:r.project_id,attempt_id:r.attempt_id,fence:a.fence});attest(x,a.request,r.binding,'SENT');return receipt(r,r.binding,'SENT');},
  async complete(r){const a=attempts.get(r.attempt_id);need(a&&a.fence,'D09_LOCAL_ATTEMPT_UNKNOWN');const evidence_hash=digest(r.output),x=await db.recordResult({project_id:r.project_id,attempt_id:r.attempt_id,result:'SUCCEEDED',evidence_hash,...(master01?{output:r.output}:{})});attest(x,a.request,r.binding,'SUCCEEDED');need(x.plan_hash===a.plan_hash&&x.dynamic_plan_hash===a.request.plan_hash&&x.payload_hash===a.request.payload_hash&&x.output_hash===digest(r.output.output)&&x.evidence_hash===evidence_hash,'D09_LOCAL_RESULT_BINDING');attempts.delete(r.attempt_id);const ack=freeze(copy(x));completions.add(ack);return freeze({...receipt(r,r.binding,'WORK_COMPLETED'),owner_ack:ack});},
  async cancelKnownPreSend(r){hold=true;const x=await db.cancel({project_id:r.project_id,attempt_id:r.attempt_id});return master01&&x.status==='NOT_SENT'?{status:'NOT_SENT',committed:true}:{status:'RECONCILE_REQUIRED',committed:false};},
  async flagUnknown(r){hold=true;try{await db[master01?'flagUnknown':'inspect']({project_id:r.project_id,attempt_id:r.attempt_id});}catch{}return {status:'OUTCOME_UNKNOWN',retry_allowed:false};}
 };Object.freeze(port);ports.add(port);return port;
}
