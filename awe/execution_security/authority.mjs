import {digest,hashBytes,parseIntent,copy,freeze,requireKeys,need,id,micros,integer,hash} from './common.mjs';
export const RISKS=Object.freeze(['READ','PROJECT_WRITE','NETWORK','PAYMENT','DESTRUCTIVE','CREDENTIAL_TRANSFER']);
export const ELEVATED=Object.freeze(['NETWORK','PAYMENT','DESTRUCTIVE','CREDENTIAL_TRANSFER']);
const subset=(a,b)=>Array.isArray(a)&&a.length>0&&new Set(a).size===a.length&&a.every(x=>b.includes(x));
const claims=['grant_id','parent_id','issuer_id','issuer_generation','subject_id','subject_generation','project_id','task_id','epochs','revision','fence','tools','resources','risks','domains','max_cost_micros','max_attempts','max_children','depth'];
const envelope=['v','kind','iss','kid','aud','jti','iat','exp'];
export const intentBinding=r=>digest(Object.fromEntries(Object.entries(r).filter(([k])=>k!=='approval_token')));

/** Permission owner only: not a monetary ledger, attempt counter, task or QA store.
 * E0 grant allocations/revocations are process-local. E1 needs reviewed durable issuer.
 */
export function createPermissionAuthority({verifier,issuer}) {
 const grants=new Map(),approvals=new Map();let serial=0;
 function state(projectId,taskId){const s=verifier.snapshot(projectId,taskId);
  need(s.status==='RUNNING'&&!s.cancelled&&!s.restore_pending&&!s.uncertain&&s.lease_until>verifier.now(),'TASK_NOT_EXECUTABLE');return s;}
 function current(b){const s=state(b.project_id,b.task_id);
  need(digest(s.epochs)===digest(b.epochs)&&s.revision===b.revision&&s.fence===b.fence,'AUTHORITY_STATE_STALE');return s;}
 function grant(token,seen=new Set()){
  const b=verifier.open(token,'grant','sec01.execution');requireKeys(b,[...claims,...envelope]);
  const g=grants.get(b.grant_id);need(g&&g.token===token&&!g.revoked&&!seen.has(b.grant_id),'GRANT_REVOKED');seen.add(b.grant_id);
  current(b);const subject=verifier.principal(b.subject_id,b.project_id),iss=verifier.principal(b.issuer_id,b.project_id);
  need(subject.generation===b.subject_generation&&iss.generation===b.issuer_generation,'GRANT_IDENTITY_REVOKED');
  if(b.parent_id){const parent=grants.get(b.parent_id);need(parent,'GRANT_LINEAGE_INVALID');const p=grant(parent.token,seen);
   need(b.depth===p.depth+1&&b.exp<=p.exp&&b.issuer_id===p.subject_id,'GRANT_LINEAGE_INVALID');
  }else need(b.depth===0&&iss.role==='SUPERVISOR','ROOT_ISSUER_DENIED');
  return b;
 }
 function issueGrant(identity,peer,requestText,parentToken=null){
  const r=parseIntent(requestText);
  requireKeys(r,['subject_id','project_id','task_id','tools','resources','risks','domains','max_cost_micros','max_attempts','max_children','ttl_ms']);
  id(r.subject_id);id(r.project_id);id(r.task_id);integer(r.max_attempts,1);integer(r.max_children);need(r.max_children<=16,'CHILD_LIMIT');micros(r.max_cost_micros);
  integer(r.ttl_ms,1);need(r.ttl_ms<=300000,'TTL_INVALID');
  for(const list of [r.tools,r.resources,r.risks,r.domains])need(Array.isArray(list)&&list.length<=32&&new Set(list).size===list.length,'GRANT_LIST_INVALID');
  need(r.tools.length>0&&r.resources.length>0&&subset(r.risks,RISKS),'GRANT_SCOPE_INVALID');r.tools.forEach(hash);r.resources.forEach(id);
  need(r.domains.every(d=>typeof d==='string'&&/^[a-z0-9]+(?:[.-][a-z0-9]+)+$/.test(d)),'DOMAIN_INVALID');
  const a=verifier.authenticate(identity,peer,r.project_id),p=verifier.principal(r.subject_id,r.project_id),s=state(r.project_id,r.task_id);
  need(p.role==='WORKER'&&['AGENT','SUBAGENT'].includes(p.kind),'GRANT_SUBJECT_INVALID');
  let parent=null,record=null;
  if(parentToken){parent=grant(parentToken);record=grants.get(parent.grant_id);
   need(a.principal_id===parent.subject_id&&p.kind==='SUBAGENT'&&p.principal_id!==a.principal_id,'DELEGATION_ACTOR_DENIED');
   need(parent.project_id===r.project_id&&parent.task_id===r.task_id&&parent.depth<2,'CHILD_SCOPE_DENIED');
   need(subset(r.tools,parent.tools)&&subset(r.resources,parent.resources)&&subset(r.risks,parent.risks)&&r.domains.every(d=>parent.domains.includes(d)),'CHILD_ESCALATION');
   need(verifier.now()+r.ttl_ms<=parent.exp&&r.max_children<=parent.max_children,'CHILD_TTL_OR_DEPTH');
   need(record.children<parent.max_children&&record.attempts+r.max_attempts<=parent.max_attempts&&record.cost+micros(r.max_cost_micros)<=micros(parent.max_cost_micros),'CHILD_ALLOCATION_EXCEEDED');
  }else need(a.role==='SUPERVISOR'&&p.kind==='AGENT','SUPERVISOR_REQUIRED');
  const grantId='grant:'+ ++serial;
  const body={grant_id:grantId,parent_id:parent?.grant_id??null,issuer_id:a.principal_id,issuer_generation:a.generation,subject_id:p.principal_id,subject_generation:p.generation,
   project_id:r.project_id,task_id:r.task_id,epochs:s.epochs,revision:s.revision,fence:s.fence,tools:r.tools,resources:r.resources,risks:r.risks,domains:r.domains,
   max_cost_micros:r.max_cost_micros,max_attempts:r.max_attempts,max_children:r.max_children,depth:parent?parent.depth+1:0};
  const token=issuer.seal('grant','sec01.execution',body,r.ttl_ms);
  grants.set(grantId,{token,revoked:false,children:0,attempts:0,cost:0n});
  if(record){record.children++;record.attempts+=r.max_attempts;record.cost+=micros(r.max_cost_micros);}
  return token;
 }
 function issueApproval(identity,peer,request,subjectId,ttl=60000){
  const a=verifier.authenticate(identity,peer,request.project_id,'OWNER');current(request);
  const g=grant(request.grant_token);need(g.subject_id===subjectId,'APPROVAL_SUBJECT_INVALID');
  const target=verifier.principal(subjectId,request.project_id);need(a.subject!==target.subject,'SELF_APPROVAL_DENIED');
  const approvalId='approval:'+ ++serial;
  const token=issuer.seal('approval','sec01.execution',{approval_id:approvalId,owner_id:a.principal_id,owner_generation:a.generation,subject_id:subjectId,project_id:request.project_id,task_id:request.task_id,
   intent_hash:intentBinding(request),grant_id:g.grant_id,epochs:copy(request.epochs),revision:request.revision,fence:request.fence},ttl);
  approvals.set(approvalId,{token,revoked:false});return token;
 }
 function authorize(identity,peer,r,manifest){
  const actor=verifier.authenticate(identity,peer,r.project_id,'WORKER'),g=grant(r.grant_token);current(r);
  need(g.subject_id===actor.principal_id&&g.project_id===r.project_id&&g.task_id===r.task_id,'GRANT_SCOPE_DENIED');
  need(g.tools.includes(digest(manifest))&&g.resources.includes(r.resource_id)&&g.risks.includes(manifest.risk),'CAPABILITY_DENIED');
  need(micros(r.reserve_micros)===micros(manifest.cost_micros)&&micros(r.reserve_micros)<=micros(g.max_cost_micros),'GRANT_COST_DENIED');
  need(manifest.domains.every(d=>g.domains.includes(d)),'GRANT_EGRESS_DENIED');
  let approvalId=null;
  if(ELEVATED.includes(manifest.risk)){
   const a=verifier.open(r.approval_token,'approval','sec01.execution');
   requireKeys(a,[...envelope,'approval_id','owner_id','owner_generation','subject_id','project_id','task_id','intent_hash','grant_id','epochs','revision','fence']);
   const record=approvals.get(a.approval_id),owner=verifier.principal(a.owner_id,r.project_id);current(a);
   need(record&&!record.revoked&&record.token===r.approval_token&&owner.role==='OWNER'&&owner.kind==='HUMAN'&&owner.generation===a.owner_generation&&owner.subject!==actor.subject,'APPROVAL_REVOKED');
   need(a.subject_id===actor.principal_id&&a.grant_id===g.grant_id&&a.intent_hash===intentBinding(r)&&a.project_id===r.project_id&&a.task_id===r.task_id,'APPROVAL_BINDING_DENIED');approvalId=a.approval_id;
  }else need(r.approval_token===null,'UNEXPECTED_APPROVAL');
  return freeze({actor_id:actor.principal_id,subject:actor.subject,database_login:actor.database_login,grant_id:g.grant_id,parent_id:g.parent_id,
   lineage:lineage(g),approval_id:approvalId,max_cost_micros:g.max_cost_micros,max_attempts:g.max_attempts,expires_at:Math.min(g.exp,r.expires_at)});
 }
 function lineage(g){const rows=[];let b=g;while(b){rows.push({grant_id:b.grant_id,max_attempts:b.max_attempts,max_cost_micros:b.max_cost_micros});b=b.parent_id?grant(grants.get(b.parent_id).token):null;}return rows;}
 const lineageFor=token=>{const rows=[];let body=grant(token);while(body){rows.push({body:copy(body),token_hash:hashBytes(Buffer.from(grants.get(body.grant_id).token))});body=body.parent_id?grant(grants.get(body.parent_id).token):null;}return freeze(rows);};
 return Object.freeze({authorize,grant,lineageFor,control:Object.freeze({issueGrant,issueApproval,
  revokeGrant(grantId){need(grants.has(grantId),'GRANT_UNKNOWN');grants.get(grantId).revoked=true;},
  revokeApproval(approvalId){need(approvals.has(approvalId),'APPROVAL_UNKNOWN');approvals.get(approvalId).revoked=true;}
 })});
}
