// SEC transport decorator of the EXISTING INT03 host. It never emits BEGIN,
// COMMIT, reserve, attempt, retry, task transition or a dispatch capability.
import {createIntegratedHost} from '../integration_v3/postgres.mjs';
import {parseNativeAdmission} from '../integration_v3/native-contract.mjs';
import {copy,freeze,parseIntent,canonicalize,digest,exact,id} from './native-identity-contract.mjs';
import {createG102TestKeyVerifier,checkG102Session,requireG102 as need,SESSION_SQL,STAGE_SQL} from './native-bridge-verifier-g102.mjs';
const ADMIT_SQL='SELECT awe_int03.admit_native_cr01($1::jsonb) AS result';
const ALLOWED=new Set(['BEGIN ISOLATION LEVEL SERIALIZABLE','SET LOCAL synchronous_commit = on',"SET LOCAL statement_timeout = '10s'",ADMIT_SQL,'SELECT awe_int03.hold_native_cr01($1::jsonb) AS result','COMMIT','ROLLBACK']);
const closed=(decision,code)=>freeze({decision,code,physical_decision:'DENY',dispatch_enabled:false,native_admission:false,accepted:false});
export function createG102AuthorityBridge({subjectPool,expectedSession,trustedKeys,clock,projectId,taskId}){
 exact(expectedSession,['login','database']);id(expectedSession.login);id(expectedSession.database);
 expectedSession=freeze(copy(expectedSession));
 need(expectedSession.login.length<=63&&subjectPool&&typeof subjectPool.connect==='function','G102_SUBJECT_POOL');
 id(projectId);id(taskId);const scope=freeze({project_id:projectId,task_id:taskId});
 const verifier=createG102TestKeyVerifier({trustedKeys,clock});let pending=null,hold=false,busy=false;
 const decoratedPool=Object.freeze({async connect(){
  const raw=await subjectPool.connect();let began=false,staged=false;
  return Object.freeze({async query(sql,params){
   need(ALLOWED.has(sql),'G102_SQL_LANE');
   if(sql==='BEGIN ISOLATION LEVEL SERIALIZABLE'){need(!began,'G102_TRANSACTION');began=true;}
   if(sql===ADMIT_SQL){
    need(began&&!staged&&pending&&!hold,'G102_STAGE_REQUIRED');
    const command=parseIntent(params?.[0]);need(digest(command)===digest({...pending.command,...scope}),'G102_COMMAND');
    const session=await raw.query(SESSION_SQL);need(session.rows?.length===1,'G102_SESSION');checkG102Session(copy(session.rows[0]),expectedSession);
    // Signature, expiry and observed process are checked again after DB awaits.
    const e=verifier.verify(pending.input);const payload=freeze({...e,command});
    const stagedResult=await raw.query(STAGE_SQL,[canonicalize(payload)]);const value=copy(stagedResult.rows?.[0]?.result);
    exact(value,['schema','status','profile','input_hash','project_id','task_id','login','challenge_id','transaction_id','physical_decision','native_admission']);
    need(value.schema==='g102.stage.receipt.v1'&&value.status==='STAGED_UNCOMMITTED'&&value.profile==='G102_TEMPORARY_TEST_KEYS_ONLY'&&value.input_hash===digest(payload)&&value.project_id===projectId&&value.task_id===taskId&&value.login===expectedSession.login&&value.challenge_id===pending.input.expectedRequest.challenge_id&&typeof value.transaction_id==='string'&&/^[1-9][0-9]*$/.test(value.transaction_id)&&value.physical_decision==='DENY'&&value.native_admission===false,'G102_STAGE_RECEIPT');
    need(digest(verifier.verify(pending.input))===digest(e),'G102_PEER_CHANGED');staged=true;
   }
   // Best-effort HOLD uses the SAME subject login. Never borrow owner/issuer lane.
   if(sql==='SELECT awe_int03.hold_native_cr01($1::jsonb) AS result'){
    const identity=await raw.query(SESSION_SQL);need(identity.rows?.length===1,'G102_SESSION');checkG102Session(copy(identity.rows[0]),expectedSession);
   }
   const result=await raw.query(sql,params);if(sql==='COMMIT'||sql==='ROLLBACK')began=false;return result;
  },release:broken=>raw.release(broken)});
 }});
 const host=createIntegratedHost({workerPool:decoratedPool,projectId,taskId});
 return Object.freeze({bind({commandText,expectedRequest},observePeer){
  const command=parseNativeAdmission(commandText,scope),expected=freeze(copy(expectedRequest));
  need(expected.scope.project_id===projectId&&expected.scope.task_id===taskId&&expected.native_binding===command.binding&&typeof observePeer==='function','G102_BIND');
  const trustedCommandText=commandText;
  return Object.freeze({async submit(text){
   if(hold)return closed('HOLD','G102_HOLD');if(busy)return closed('DENY','G102_BUSY');
   let contacted=false;busy=true;
   try{
    const input={text,commandText:trustedCommandText,expectedRequest:expected,observePeer,expectedLogin:expectedSession.login};verifier.verify(input);
    pending=Object.freeze({command,input});contacted=true;
    await host.trusted.admitNative(trustedCommandText);
    // Even a future/incorrect backend returning admission cannot open this CR.
    hold=true;return closed('HOLD','G102_UNEXPECTED_ADMISSION_NO_DISPATCH');
   }catch{
    // Existing host owns rollback/commit handling and durable best-effort HOLD.
    // Any contacted failure is conservatively latched; no implicit resubmission.
    if(contacted)hold=true;return closed(hold?'HOLD':'DENY',hold?'G102_HOLD':'G102_AUTHORITY_REJECTED');
   }finally{pending=null;busy=false;}
  },physicalDispatch:()=>closed('DENY','G102_NATIVE_DISABLED')});
 },inspect:()=>freeze({profile:'G102_SOURCE_ONLY_TEST_KEYS',state:hold?'HOLD':'SOURCE_ONLY',coordinator:'EXISTING_INT03_D09',production_authn:'NOT_CONFIGURED',recovery:'NOT_CONFIGURED_DEC09',policy:'NOT_CONFIGURED_DEC03_DEC05',D07:'DENY',physical_decision:'DENY'}),physicalDispatch:()=>closed('DENY','G102_NATIVE_DISABLED')});
}
