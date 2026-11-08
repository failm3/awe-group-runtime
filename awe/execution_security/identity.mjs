import {sign,verify} from 'node:crypto';
import {canonicalize,digest,parseIntent,copy,freeze,requireKeys,VERSION,need,id,integer} from './common.mjs';
const identityFields=['v','kind','iss','kid','aud','jti','iat','exp','principal_id','subject','principal_kind','role','project_id','generation','auth_epoch','channel_binding','database_login','assurance'];
const lanes={USER:'user',WORKER:'producer',SUPERVISOR:'producer',VERIFIER:'verifier',EVALUATOR:'evaluator',OWNER:'owner',REGISTRY:'registry',EXECUTOR:'executor',PROVIDER:'provider'};
const b64=bytes=>Buffer.from(bytes).toString('base64url');
function unpack(segment){need(typeof segment==='string'&&/^[A-Za-z0-9_-]+$/.test(segment),'PROOF_ENCODING');const bytes=Buffer.from(segment,'base64url');need(b64(bytes)===segment,'PROOF_ENCODING');return bytes;}

/** Host composition only. Signer/directory never belong to an LLM or worker process.
 * Ed25519 is real cryptography; local provisioning is explicitly NOT human AuthN.
 * The directory is an online trusted port; outage is a denial, not cached authority.
 */
export function createIdentityVerifier({keys,directory,clock}) {
 const pinned=new Map(keys.map(k=>[k.kid,{...k}]));let last=-1;
 function now(){const n=integer(clock());need(n>=last,'CLOCK_ROLLBACK');last=n;return n;}
 function live(){need(directory.health()===true,'IDENTITY_DIRECTORY_UNAVAILABLE');}
 function principal(principalId,projectId){live();const p=copy(directory.principal(principalId));
  need(p&&p.active&&p.projects.includes(projectId),'IDENTITY_SCOPE_DENIED');
  need(p.valid_until>now()&&lanes[p.role],'IDENTITY_EXPIRED');return p;}
 function snapshot(projectId,taskId){live();const s=copy(directory.snapshot(projectId,taskId));
  need(s&&s.project_id===projectId&&s.task_id===taskId,'STATE_SCOPE_DENIED');return s;}
 function open(token,kind,audience){
  need(typeof token==='string'&&token.length<=32768,'PROOF_INVALID');const segments=token.split('.');need(segments.length===2,'PROOF_INVALID');
  const bytes=unpack(segments[0]),body=parseIntent(bytes.toString('utf8'));
  need(canonicalize(body)===bytes.toString('utf8'),'PROOF_ENCODING');
  const key=pinned.get(body.kid);live();need(key&&key.issuer===body.iss&&directory.keyActive(body.kid)===true,'ISSUER_UNTRUSTED');
  need(key.publicKey.asymmetricKeyType==='ed25519','ISSUER_ALGORITHM');
  need(verify(null,bytes,key.publicKey,unpack(segments[1])),'SIGNATURE_INVALID');
  need(body.v===VERSION&&body.kind===kind&&body.aud===audience,'PROOF_AUDIENCE');
  const n=now();integer(body.iat);integer(body.exp);id(body.jti);
  need(body.iat<=n&&body.exp>n&&body.exp-body.iat<=300000&&body.exp>body.iat,'PROOF_EXPIRED');
  need(directory.proofActive(body.jti)===true,'PROOF_REVOKED');return freeze(body);
 }
 function authenticate(token,peer,projectId,role=null){
  const b=open(token,'identity','sec01.ingress');requireKeys(b,identityFields);
  const p=principal(b.principal_id,projectId),s=snapshot(projectId,directory.identityTask(projectId));
  // `peer` is supplied by authenticated host IPC, never decoded from worker JSON.
  need(peer&&peer.binding===p.channel_binding&&peer.database_login===p.database_login,'CHANNEL_BINDING_DENIED');
  need(b.project_id===projectId&&b.channel_binding===p.channel_binding&&b.database_login===p.database_login&&b.auth_epoch===s.epochs.auth,'IDENTITY_EPOCH_STALE');
  need(b.generation===p.generation&&b.subject===p.subject&&b.role===p.role&&b.principal_kind===p.kind&&b.assurance==='E0_LOCAL_PROVISIONED','IDENTITY_CHANGED');
  if(role)need(p.role===role,'ROLE_DENIED');
  need(!['OWNER','USER'].includes(p.role)||p.kind==='HUMAN','OWNER_PRINCIPAL_KIND');
  need(!['EVALUATOR','VERIFIER','REGISTRY','EXECUTOR','PROVIDER'].includes(p.role)||p.kind==='SERVICE','SERVICE_PRINCIPAL_KIND');
  // Check subject aliases and shared workload/DB credentials, not just friendly IDs.
  for(const other of directory.principals())if(other.active&&other.principal_id!==p.principal_id&&other.projects.includes(projectId)) {
   need(other.channel_binding!==p.channel_binding&&other.database_login!==p.database_login,'IDENTITY_SEPARATION_DENIED');
   if(lanes[other.role]!==lanes[p.role])need(other.subject!==p.subject,'IDENTITY_SEPARATION_DENIED');
  }
  return freeze({...p,project_id:projectId});
 }
 return Object.freeze({open,authenticate,principal,snapshot,now});
}

export function createLocalIssuer({issuer,kid,privateKey,verifier,directory}) {
 need(privateKey.asymmetricKeyType==='ed25519','ISSUER_ALGORITHM');let sequence=0;
 function seal(kind,audience,claims,ttl=60000){
  need(ttl>0&&ttl<=300000&&Number.isSafeInteger(ttl),'TTL_INVALID');
  const iat=verifier.now(),jti=id(issuer+':'+(++sequence)+':'+directory.incarnation());
  const body={...copy(claims),v:VERSION,kind,iss:issuer,kid,aud:audience,jti,iat,exp:iat+ttl};
  directory.registerProof(jti);const bytes=Buffer.from(canonicalize(body));return b64(bytes)+'.'+b64(sign(null,bytes,privateKey));
 }
 return Object.freeze({
  // Trusted authenticator calls this after enrollment; there is no worker enrollment API.
  issueIdentity(principalId,projectId,ttl){const p=verifier.principal(principalId,projectId),s=verifier.snapshot(projectId,directory.identityTask(projectId));
   return seal('identity','sec01.ingress',{principal_id:p.principal_id,subject:p.subject,principal_kind:p.kind,role:p.role,project_id:projectId,generation:p.generation,auth_epoch:s.epochs.auth,channel_binding:p.channel_binding,database_login:p.database_login,assurance:'E0_LOCAL_PROVISIONED'},ttl);
  },
  // This handle stays only inside the permission issuer composition root.
  seal,
  fingerprint:()=>digest({issuer,kid,profile:'E0_LOCAL_PROVISIONED'})
 });
}
