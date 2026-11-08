import {hashBytes,need,requireKeys} from './common.mjs';
/** Production vault/OS keychain remains an integration gate. This fixture cannot
 * enroll real keys or export values. Only a synthetic canary is held in memory.
 */
export function createSyntheticSecretBroker({verifier}){
 const canary=Buffer.from('SEC01_CANARY_ONLY_NO_REAL_CREDENTIAL');
 return Object.freeze({
  invoke(identity,peer,text){
   requireKeys(text,['mode','project_id','purpose','handle']);
   verifier.authenticate(identity,peer,text.project_id,'EXECUTOR');
   need(text.mode==='E0_SYNTHETIC_ONLY'&&text.project_id==='prj_alpha'&&text.purpose==='CANARY_DIGEST'&&text.handle==='synthetic:canary','SECRET_ACCESS_DENIED');
   // No raw return value, arbitrary callback, model input or log sink.
   return Object.freeze({used:true,synthetic:true,physical_decision:'DENY',receipt_hash:hashBytes(canary)});
  },
  requestRealSecret(){return Object.freeze({decision:'DENY',physical_decision:'DENY',code:'REAL_VAULT_NOT_AUTHORIZED'});}
 });
}
export function rejectCredentialMaterial(payload){
 // Defense in depth for known formats; not a claim to detect arbitrary secrets.
 const text=JSON.stringify(payload);
 need(!/(?:SEC01_CANARY_ONLY|-----BEGIN [A-Z ]*PRIVATE KEY|Bearer\s+[A-Za-z0-9_.-]{8,}|sk-[A-Za-z0-9_-]{16,}|password\s*[:=])/i.test(text),'CREDENTIAL_MATERIAL_DENIED');
}
