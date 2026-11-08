// SEC-only challenge control client, not a task/attempt coordinator. One SQL
// statement owns its PostgreSQL transaction. No raw pool is exposed to subjects.
import {parseNativeAdmission} from '../integration_v3/native-contract.mjs';
import {copy,freeze,canonicalize,digest,hashBytes,exact,hash,id,integer,request,unpack} from './native-identity-contract.mjs';
import {SESSION_SQL,checkG102Session,requireG102 as need} from './native-bridge-verifier-g102.mjs';
export const CHALLENGE_SQL='SELECT awe_int03.issue_challenge_g102($1::jsonb) AS result';
export function createG102ChallengeClient({subjectPool,expectedSession,projectId,taskId}){
 exact(expectedSession,['login','database']);id(expectedSession.login);id(expectedSession.database);expectedSession=freeze(copy(expectedSession));
 id(projectId);id(taskId);need(subjectPool&&typeof subjectPool.connect==='function','G102_POOL');let hold=false,busy=false;
 return Object.freeze({async issue({commandText,expectedRequest,identityToken}){
  if(hold)return freeze({decision:'HOLD',code:'G102_CHALLENGE_HOLD',physical_decision:'DENY',native_admission:false});
  if(busy)return freeze({decision:'DENY',code:'G102_BUSY',physical_decision:'DENY',native_admission:false});
  let client,contacted=false,broken=true;busy=true;
  try{
   const expected=freeze(copy(expectedRequest));request(expected);const command=parseNativeAdmission(commandText,{project_id:projectId,task_id:taskId}),cert=unpack(identityToken).body;
   need(cert.login_ref===expectedSession.login&&cert.principal_id===expected.principal_id&&cert.role===expected.expected_role&&digest(cert.scope)===digest(expected.scope)&&expected.scope.project_id===projectId&&expected.scope.task_id===taskId&&expected.native_binding===command.binding,'G102_CHALLENGE_BINDING');
   client=await subjectPool.connect();const session=await client.query(SESSION_SQL);need(session.rows?.length===1,'G102_SESSION');checkG102Session(copy(session.rows[0]),expectedSession);
   const input={command:{...command,project_id:projectId,task_id:taskId},identity_hash:hashBytes(Buffer.from(identityToken)),request_text:canonicalize(expected)};
   contacted=true;const response=await client.query(CHALLENGE_SQL,[canonicalize(input)]),r=copy(response.rows?.[0]?.result);
   exact(r,['schema','profile','status','project_id','task_id','challenge_id','identity_hash','request_hash','nonce_hash','issued_ms','expires_ms','physical_decision','native_admission']);
   need(r.schema==='g102.challenge.receipt.v1'&&r.profile==='G102_TEMPORARY_TEST_KEYS_ONLY'&&r.status==='ISSUED_NOT_AUTHORIZED'&&r.project_id===projectId&&r.task_id===taskId&&r.challenge_id===expected.challenge_id&&r.identity_hash===input.identity_hash&&r.request_hash===digest(expected)&&r.physical_decision==='DENY'&&r.native_admission===false,'G102_CHALLENGE_RECEIPT');
   hash(r.nonce_hash);integer(r.issued_ms);integer(r.expires_ms,1);need(r.expires_ms>r.issued_ms&&r.expires_ms-r.issued_ms<=30000&&r.expires_ms<=expected.expires_at,'G102_CHALLENGE_TIME');
   broken=false;return freeze(r);
  }catch{if(contacted)hold=true;return freeze({decision:hold?'HOLD':'DENY',code:hold?'G102_CHALLENGE_HOLD':'G102_CHALLENGE_REJECTED',physical_decision:'DENY',native_admission:false});}
  finally{busy=false;try{client?.release(broken);}catch{}}
 },inspect:()=>freeze({state:hold?'HOLD':'CONTROL_ONLY',purpose:'ISSUE_CHALLENGE_NOT_AUTHN',physical_decision:'DENY',native_admission:false})});
}
