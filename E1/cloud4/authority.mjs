import {createPublicKey, verify as verifySignature} from 'node:crypto';
import {canonicalize,digest,immutable,need} from '../contracts/index.mjs';

export const PROVENANCE='HOST_ATTESTED_CHAT_AND_GITHUB_DELEGATION';
export const LIMITS=immutable({total_actual_micros:'10000000',account_reserve_unallocated_micros:'21000000',total_attempts:22,canary:{budget_micros:'500000',per_attempt_micros:'250000',attempts:2,route_ids:['router.cheap.chat.gpt-6-sol','router.cheap.chat.claude-opus-4-8']},followup:{budget_micros:'9500000',per_attempt_micros:'1000000',attempts:20},wire_attempts_per_request:1,unknown_policy:'HOLD',fallback:'DENY',account_changes:'DENY'});
const authorities=new WeakMap(),tokens=new WeakMap(),gates=new WeakMap();
const id=v=>typeof v==='string'&&/^[a-z][a-z0-9_.-]{0,79}$/.test(v);
const sha=v=>typeof v==='string'&&/^sha256:[a-f0-9]{64}$/.test(v);
const base64=v=>typeof v==='string'&&/^[A-Za-z0-9+/]+={0,2}$/.test(v);
export function validateAuthorizationDocument(doc,{now=new Date().toISOString()}={}){
  canonicalize(doc);
  need(doc?.schema==='awe.e1.cloud4.owner-authorization/1'&&doc.provenance===PROVENANCE&&doc.owner_consent==='ISSUED','CLOUD4_OWNER_AUTHORIZATION_SCHEMA');
  need(id(doc.key_binding_id)&&id(doc.owner_id)&&id(doc.issuer_id)&&sha(doc.mandate_digest),'CLOUD4_OWNER_AUTHORIZATION_SCOPE');
  need(Array.isArray(doc.project_ids)&&doc.project_ids.length>0&&doc.project_ids.length<=32&&doc.project_ids.every(id)&&new Set(doc.project_ids).size===doc.project_ids.length,'CLOUD4_OWNER_AUTHORIZATION_SCOPE');
  need(digest(doc.limits)===digest(LIMITS),'CLOUD4_OWNER_AUTHORIZATION_LIMITS');
  need(doc.issued_at<=now&&now<doc.expires_at&&Date.parse(doc.expires_at)-Date.parse(doc.issued_at)<=86400000&&Number.isFinite(Date.parse(doc.issued_at))&&Number.isFinite(Date.parse(doc.expires_at)),'CLOUD4_OWNER_AUTHORIZATION_EXPIRY');
  need(doc.provider==='router.cheap'&&doc.budget_group_id==='router.cheap.shared/1'&&['AUTHENTICATED_HOST','EXPLICIT_SYNTHETIC'].includes(doc.evidence_mode),'CLOUD4_OWNER_AUTHORIZATION_SCHEMA');
  if(doc.prior_authorization_digest!==undefined)need(sha(doc.prior_authorization_digest)&&Number.isSafeInteger(doc.scope_revision)&&doc.scope_revision>=2,'CLOUD4_SCOPE_AMENDMENT_BINDING');
  if(doc.evidence_mode==='EXPLICIT_SYNTHETIC')need(doc.key_binding_id.startsWith('synthetic_')&&doc.project_ids.every(p=>/^prj_(cloud|qa3|qa4)_/.test(p)),'CLOUD4_SYNTHETIC_SCOPE');
  else need(!doc.key_binding_id.startsWith('synthetic_'),'CLOUD4_SYNTHETIC_SCOPE');
  return immutable(doc);
}
export function verifyCloud4Receipt(receipt,{trusted_public_key_digest,now=new Date().toISOString(),schema='awe.e1.cloud4.owner-authorization/1'}={}){
  need(receipt?.schema==='awe.e1.cloud4.signed-receipt/1'&&receipt.algorithm==='Ed25519'&&receipt.document?.schema===schema,'CLOUD4_SIGNATURE_REQUIRED');
  need(base64(receipt.public_key_spki_der)&&base64(receipt.signature)&&Buffer.from(receipt.signature,'base64').length===64,'CLOUD4_SIGNATURE_REQUIRED');
  const publicBytes=Buffer.from(receipt.public_key_spki_der,'base64');
  need(sha(trusted_public_key_digest)&&digest({spki_der:receipt.public_key_spki_der})===trusted_public_key_digest&&receipt.public_key_digest===trusted_public_key_digest,'CLOUD4_SIGNER_NOT_TRUSTED');
  need(receipt.document_digest===digest(receipt.document),'CLOUD4_SIGNATURE_BINDING');
  let valid=false;try{const publicKey=createPublicKey({key:publicBytes,format:'der',type:'spki'});valid=publicKey.asymmetricKeyType==='ed25519'&&verifySignature(null,Buffer.from(canonicalize(receipt.document)),publicKey,Buffer.from(receipt.signature,'base64'));}catch{}
  need(valid,'CLOUD4_SIGNATURE_INVALID');
  if(schema==='awe.e1.cloud4.owner-authorization/1')validateAuthorizationDocument(receipt.document,{now});
  else if(schema==='awe.e1.cloud4.canary-gate/1')validateCanaryGateDocument(receipt.document,{now});
  else need(false,'CLOUD4_SIGNATURE_SCHEMA');
  return immutable(receipt);
}

/** Uses the actual native host authority's opaque context, with the owner's
 * verified directive resolved by the host. JSON alone cannot mint this token.
 * Signer is host-owned; no provider credential is involved in this module.
 */
export function createCloud4AuthorizationAuthority({authenticateContext,mandate_digest,verifyMandate,verifyIndependentCanary,signer,trusted_public_key_digest,clock=()=>new Date().toISOString()}){
  need(typeof authenticateContext==='function'&&typeof verifyMandate==='function'&&typeof signer?.sign==='function'&&sha(mandate_digest)&&sha(trusted_public_key_digest),'CLOUD4_HOST_AUTHORITY_REQUIRED');
  const authority=Object.freeze({kind:'CLOUD4_HOST_AUTHORIZATION_AUTHORITY'});
  authorities.set(authority,{authenticateContext,mandate_digest,verifyMandate,verifyIndependentCanary,signer,trusted_public_key_digest,clock});return authority;
}
export async function issueCloud4Authorization(authority,request,context){
  const port=authorities.get(authority);need(port,'CLOUD4_HOST_AUTHORITY_REQUIRED');
  const principal=await port.authenticateContext(context);
  need(principal&&['OWNER','COORDINATOR'].includes(principal.role)&&id(principal.principal_id)&&id(principal.project_id),'CLOUD4_AUTHENTICATED_HOST_REQUIRED');
  need(await port.verifyMandate({mandate_digest:port.mandate_digest,principal,request:immutable(request),context}),'CLOUD4_MANDATE_NOT_VERIFIED');
  need(request.project_ids?.includes(principal.project_id),'CLOUD4_OWNER_AUTHORIZATION_SCOPE');
  const document=validateAuthorizationDocument({schema:'awe.e1.cloud4.owner-authorization/1',provenance:PROVENANCE,owner_consent:'ISSUED',provider:'router.cheap',budget_group_id:'router.cheap.shared/1',key_binding_id:request.key_binding_id,owner_id:request.owner_id,project_ids:request.project_ids,issuer_id:principal.principal_id,mandate_digest:port.mandate_digest,evidence_mode:request.evidence_mode??'AUTHENTICATED_HOST',issued_at:port.clock(),expires_at:request.expires_at,limits:LIMITS},{now:port.clock()});
  const receipt=verifyCloud4Receipt(await port.signer.sign(document),{trusted_public_key_digest:port.trusted_public_key_digest,now:port.clock()});
  const token=Object.freeze({kind:'CLOUD4_AUTHENTICATED_OWNER_AUTHORIZATION'});tokens.set(token,{receipt,authority,context});return token;
}
export function cloud4AuthorizationReceipt(token){const value=tokens.get(token);need(value,'CLOUD4_AUTHORIZATION_TOKEN_REQUIRED');return value.receipt;}
export async function cloud4AuthorizationAdmission(authority,token,context){
  const value=tokens.get(token);need(value&&value.authority===authority&&value.context===context,'CLOUD4_AUTHORIZATION_TOKEN_REQUIRED');
  const port=authorities.get(authority),principal=await port.authenticateContext(context),doc=value.receipt.document;
  need(principal&&['OWNER','COORDINATOR'].includes(principal.role)&&principal.principal_id===doc.issuer_id&&doc.project_ids.includes(principal.project_id),'CLOUD4_AUTHENTICATED_HOST_REQUIRED');
  need(await port.verifyMandate({mandate_digest:port.mandate_digest,principal,request:doc,context}),'CLOUD4_MANDATE_NOT_VERIFIED');
  return verifyCloud4Receipt(value.receipt,{trusted_public_key_digest:port.trusted_public_key_digest,now:port.clock()});
}
export async function restoreCloud4Authorization(authority,receipt,context){
 const port=authorities.get(authority);need(port,'CLOUD4_HOST_AUTHORITY_REQUIRED');const verified=verifyCloud4Receipt(receipt,{trusted_public_key_digest:port.trusted_public_key_digest,now:port.clock()});
 need(verified.document.mandate_digest===port.mandate_digest,'CLOUD4_MANDATE_NOT_VERIFIED');
 const token=Object.freeze({kind:'CLOUD4_AUTHENTICATED_OWNER_AUTHORIZATION'});tokens.set(token,{receipt:verified,authority,context});await cloud4AuthorizationAdmission(authority,token,context);return token;
}
export async function amendCloud4Authorization(authority,current,{project_ids,expires_at},context){
 const prior=await cloud4AuthorizationAdmission(authority,current,context),port=authorities.get(authority),doc=prior.document;
 need(Array.isArray(project_ids)&&project_ids.length>doc.project_ids.length&&doc.project_ids.every(p=>project_ids.includes(p)),'CLOUD4_SCOPE_EXPANSION_ONLY');
 const expiry=expires_at??doc.expires_at;need(expiry<=doc.expires_at,'CLOUD4_SCOPE_EXPIRY_EXTENSION_DENIED');
 const document=validateAuthorizationDocument({...doc,project_ids:[...project_ids].sort(),issued_at:port.clock(),expires_at:expiry,prior_authorization_digest:prior.document_digest,scope_revision:(doc.scope_revision??1)+1},{now:port.clock()});
 const principal=await port.authenticateContext(context);need(await port.verifyMandate({mandate_digest:port.mandate_digest,principal,request:document,context}),'CLOUD4_MANDATE_NOT_VERIFIED');
 const receipt=verifyCloud4Receipt(await port.signer.sign(document),{trusted_public_key_digest:port.trusted_public_key_digest,now:port.clock()});const token=Object.freeze({kind:'CLOUD4_AUTHENTICATED_OWNER_AUTHORIZATION'});tokens.set(token,{receipt,authority,context});return token;
}
export function validateCanaryGateDocument(doc,{now=new Date().toISOString()}={}){
  canonicalize(doc);need(doc?.schema==='awe.e1.cloud4.canary-gate/1'&&doc.provenance==='HOST_ATTESTED_INDEPENDENT_CANARY_QA'&&doc.verdict==='PASS'&&id(doc.key_binding_id)&&id(doc.evaluator_id)&&sha(doc.authorization_digest),'CLOUD4_INDEPENDENT_QA_REQUIRED');
  need(Array.isArray(doc.attempt_ids)&&doc.attempt_ids.length===2&&new Set(doc.attempt_ids).size===2&&doc.attempt_ids.every(x=>typeof x==='string'&&/^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/.test(x))&&doc.attempt_ids.join(',')===[...doc.attempt_ids].sort().join(','),'CLOUD4_CANARY_ATTEMPTS_REQUIRED');
  need(doc.issued_at<=now&&now<doc.expires_at&&Date.parse(doc.expires_at)-Date.parse(doc.issued_at)<=86400000,'CLOUD4_CANARY_GATE_EXPIRY');return immutable(doc);
}
export async function issueCloud4CanaryGate(authority,authorization,{attempt_ids},context){
  const port=authorities.get(authority),owner=tokens.get(authorization);need(port&&owner?.authority===authority&&typeof port.verifyIndependentCanary==='function','CLOUD4_INDEPENDENT_QA_REQUIRED');
  const principal=await port.authenticateContext(context);need(principal?.role==='QA'&&id(principal.principal_id)&&owner.receipt.document.project_ids.includes(principal.project_id),'CLOUD4_INDEPENDENT_QA_REQUIRED');
  need(await port.verifyIndependentCanary({authorization:owner.receipt,attempt_ids,evaluator_id:principal.principal_id,context}),'CLOUD4_INDEPENDENT_QA_REQUIRED');
  const document=validateCanaryGateDocument({schema:'awe.e1.cloud4.canary-gate/1',provenance:'HOST_ATTESTED_INDEPENDENT_CANARY_QA',verdict:'PASS',key_binding_id:owner.receipt.document.key_binding_id,authorization_digest:owner.receipt.document_digest,evaluator_id:principal.principal_id,attempt_ids:[...attempt_ids].sort(),issued_at:port.clock(),expires_at:owner.receipt.document.expires_at},{now:port.clock()});
  const receipt=verifyCloud4Receipt(await port.signer.sign(document),{trusted_public_key_digest:port.trusted_public_key_digest,now:port.clock(),schema:document.schema});const token=Object.freeze({kind:'CLOUD4_INDEPENDENT_CANARY_GATE'});gates.set(token,{authority,context,receipt});return token;
}
export async function cloud4CanaryAdmission(authority,token,context){const gate=gates.get(token),port=authorities.get(authority);need(gate?.authority===authority&&gate.context===context&&port,'CLOUD4_INDEPENDENT_QA_REQUIRED');const principal=await port.authenticateContext(context);need(principal?.role==='QA'&&principal.principal_id===gate.receipt.document.evaluator_id,'CLOUD4_INDEPENDENT_QA_REQUIRED');return verifyCloud4Receipt(gate.receipt,{trusted_public_key_digest:port.trusted_public_key_digest,now:port.clock(),schema:'awe.e1.cloud4.canary-gate/1'});}

export function cloud4PaidReadiness({authorization,provider_contract}={}){
  const signed=authorization&&tokens.has(authorization);
  return immutable({schema:'awe.e1.cloud4.paid-readiness/1',owner_consent:signed?'ISSUED_AUTHENTICATED_HOST_ATTESTATION':'ISSUED_PENDING_HOST_ATTESTATION',financial_authorization_provenance:PROVENANCE,total_actual_authorized_micros:LIMITS.total_actual_micros,unallocated_account_reserve_micros:LIMITS.account_reserve_unallocated_micros,provider_actual_cap:'UNVERIFIED',charged_ack_contract:'UNVERIFIED',provider_request_cap_binding:'UNVERIFIED',spending_enabled:false,state:signed?'PREPARED_PROVIDER_BLOCKED':'HOST_ATTESTATION_PENDING',reason:'PROVIDER_ACTUAL_CHARGE_CAP_AND_ACK_NOT_PROVEN',provider_contract_supplied:Boolean(provider_contract)});
}
