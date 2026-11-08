// G1-02A source-only candidate. Real Ed25519 verification of TEMPORARY TEST keys.
// No issuer, current authority store, nonce consumption, DB transaction or permit.
import {PROFILE,copy,freeze,parseIntent,canonicalize,digest,hashBytes,exact,id,integer,
 openAuthority,openProof,processBinding,subjectBinding,request} from './native-identity-contract.mjs';
import {bindPinnedNativeIdentityRequest} from './native-authority-binding.mjs';

class BridgeError extends Error {constructor(code){super(code);this.code=code;}}
const need=(ok,code)=>{if(!ok)throw new BridgeError(code);};
export const STAGE_SQL='SELECT awe_int03.stage_authority_g102($1::jsonb) AS result';
export const SESSION_SQL=`SELECT session_user::text AS session_login, current_user::text AS effective_login,
 current_database()::text AS database_name, pg_backend_pid() AS backend_pid,
 r.rolsuper AS superuser, r.rolcreaterole AS create_role, r.rolcreatedb AS create_db,
 r.rolreplication AS replication, r.rolbypassrls AS bypass_rls,
 pg_has_role(session_user,'awe_sec_bridge_g102','MEMBER') AS bridge_member,
 pg_has_role(session_user,'awe_int03_host','MEMBER') AS host_member,
 (pg_has_role(session_user,'awe_d09_owner','MEMBER') OR
 pg_has_role(session_user,'awe_d09_issuer','MEMBER') OR
 pg_has_role(session_user,'awe_sec_revoker_g102','MEMBER') OR
 pg_has_role(session_user,'awe_int03_owner','MEMBER') OR
 pg_has_role(session_user,'awe_int03_verifier','MEMBER') OR
 pg_has_role(session_user,'awe_int03_evaluator','MEMBER')) AS forbidden_member
 FROM pg_roles r WHERE r.rolname=session_user`;
export function requireG102(ok,code='G102_INVALID'){need(ok,code);}
export function checkG102Session(value,expected){
 exact(value,['session_login','effective_login','database_name','backend_pid','superuser','create_role','create_db','replication','bypass_rls','bridge_member','host_member','forbidden_member']);
 need(value.session_login===expected.login&&value.effective_login===expected.login&&value.database_name===expected.database,'G102_SESSION_BINDING');
 integer(value.backend_pid,1);
 need(value.bridge_member===true&&value.host_member===true&&value.forbidden_member===false,'G102_SESSION_ROLE');
 for(const k of ['superuser','create_role','create_db','replication','bypass_rls'])need(value[k]===false,'G102_UNSAFE_DB_ROLE');
 return freeze(copy(value));
}
export function createG102TestKeyVerifier({trustedKeys,clock}){
 need(typeof clock==='function'&&Array.isArray(trustedKeys)&&trustedKeys.length>0&&trustedKeys.length<=16,'G102_TRUST');
 const keys=new Map();
 for(const k of trustedKeys){exact(k,['issuer','kid','generation','publicKey','projects','profile']);id(k.issuer);id(k.kid);integer(k.generation,1);
  need(k.profile===PROFILE&&k.publicKey?.type==='public'&&k.publicKey.asymmetricKeyType==='ed25519'&&Array.isArray(k.projects)&&k.projects.length>0&&k.projects.length<=16,'G102_TRUST');k.projects.forEach(id);
  const name=k.issuer+'|'+k.kid;need(!keys.has(name)&&new Set(k.projects).size===k.projects.length,'G102_TRUST');
  keys.set(name,{...k,projects:[...k.projects],key_hash:hashBytes(k.publicKey.export({type:'spki',format:'der'}))});
 }
 let last=-1;
 return Object.freeze({verify({text,commandText,expectedRequest,observePeer,expectedLogin}){
  const time=clock();integer(time);need(time>=last,'G102_CLOCK_ROLLBACK');last=time;
  const w=freeze(parseIntent(text));exact(w,['identity','grants','proof','request']);request(expectedRequest);request(w.request);
  need(digest(w.request)===digest(expectedRequest),'G102_REQUEST');
  need(Array.isArray(w.grants)&&w.grants.length>0&&w.grants.length<=4,'G102_LINEAGE');
  const i=openAuthority(w.identity,'IDENTITY',keys,expectedRequest.scope,time),c=i.body;
  need(c.login_ref===expectedLogin&&c.role===expectedRequest.expected_role&&c.principal_id===expectedRequest.principal_id&&digest(c.scope)===digest(expectedRequest.scope),'G102_SUBJECT');
  const gs=w.grants.map(g=>openAuthority(g,'GRANT',keys,expectedRequest.scope,time));
  need(new Set(gs.map(g=>g.body.grant_id)).size===gs.length,'G102_LINEAGE');
  const leaf=gs.at(-1).body,p=expectedRequest.permission;
  need(leaf.subject_id===c.principal_id&&leaf.subject_role===c.role&&leaf.subject_generation===c.principal_generation&&leaf.process_generation===c.process_binding.generation&&leaf.identity_hash===i.token_hash&&digest(leaf.scope)===digest(c.scope)&&leaf.parent_run_id===c.parent_run_id,'G102_GRANT_SUBJECT');
  need(leaf.actions.includes(p.action)&&leaf.resources.includes(p.resource)&&leaf.capability_hashes.includes(p.capability_hash)&&leaf.policy_hash===p.policy_hash,'G102_PERMISSION');
  for(let n=0;n<gs.length;n++){const g=gs[n].body;
   need(g.iss===c.iss&&g.kid===c.kid&&g.issuer_generation===c.issuer_generation,'G102_ISSUER');
   if(n===0)need(g.parent_grant_id===null&&g.delegator_id===null&&g.parent_run_id===null&&g.subject_role!=='SUBAGENT','G102_LINEAGE');
   else{const a=gs[n-1].body;need(g.parent_grant_id===a.grant_id&&g.delegator_id===a.subject_id&&g.subject_id!==a.subject_id&&g.parent_run_id===a.scope.run_id&&g.scope.run_id!==a.scope.run_id&&g.subject_role==='SUBAGENT'&&['MAIN_AGENT','SUBAGENT'].includes(a.subject_role)&&a.actions.includes('CHILD_CREATE')&&g.exp<=a.exp&&g.iat>=a.iat&&g.policy_hash===a.policy_hash,'G102_LINEAGE');
    for(const field of ['actions','resources','capability_hashes'])need(g[field].every(x=>a[field].includes(x)),'G102_ESCALATION');}
  }
  const proof=openProof(w.proof,i.proofKey,time).body;
  need(proof.principal_id===c.principal_id&&proof.identity_hash===i.token_hash&&proof.challenge_id===expectedRequest.challenge_id&&proof.request_hash===digest(expectedRequest)&&proof.grant_chain_hash===digest(w.grants.map(t=>hashBytes(Buffer.from(t))))&&proof.subject_binding_hash===subjectBinding(c),'G102_PROOF');
  need(expectedRequest.expires_at>time&&proof.exp<=expectedRequest.expires_at,'G102_EXPIRED');
  const observed=copy(observePeer());exact(observed,['profile','process_binding']);
  need(['OS_OBSERVED_TEST_PROCESS','SYNTHETIC_UNIT_TEST_PEER'].includes(observed.profile),'G102_PEER');processBinding(observed.process_binding);
  need(digest(observed.process_binding)===digest(c.process_binding),'G102_PROCESS');
  const projected=bindPinnedNativeIdentityRequest({commandText,pinnedBinding:expectedRequest.native_binding,identityToken:w.identity,grantTokens:w.grants,expectedRole:c.role,permission:p,challengeId:proof.challenge_id,expiresAt:expectedRequest.expires_at});
  need(digest(projected)===digest(expectedRequest),'G102_FULL_BINDING');
  return freeze({schema:'g102.sec.stage.v1',profile:'G102_TEMPORARY_TEST_KEYS_ONLY',identity:w.identity,grants:copy(w.grants),proof:w.proof,request_text:canonicalize(expectedRequest),observed_process:copy(observed.process_binding),peer_profile:observed.profile,issuer_key_hash:i.key.key_hash});
 }});
}
