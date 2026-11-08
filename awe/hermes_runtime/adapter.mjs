import {validate,createValidationContext} from '../../contracts/validate.mjs';
import {launchRequest,eventRequest,digest,copy,freeze,need,same,deny,terminal,bounded,parseIntent,exact,id,hash} from './protocol.mjs';
import {configHash,manifestHash,profile,requireOffline} from './profile.mjs';

export const planHash=r=>digest({grant:r.grant,actor_id:r.actor_id,child_id:r.child_id,context:r.context,model:r.model,tools:r.tools,runtime_pin:r.runtime_pin});
// Trusted host assembly. Every supplied port is host-owned. Never pass this
// factory, ports, journal, sessions, transport or host API to an agent.
export function createHermesRuntime({state,security,context,artifacts,models,tools,attempts,journal,transport,clock,supervisor,timeoutMs=profile.limits.port_timeout_ms}) {
 requireOffline();need(transport?.mode==='RT01_SYNTHETIC_ONLY','REAL_HERMES_NOT_RUN');
 need(Number.isSafeInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=1000,'TIMEOUT_INVALID');
 const runs=new Map(),handles=new Map();let tail=Promise.resolve(),quarantined=false;
 const serial=fn=>{const p=tail.then(fn);tail=p.catch(()=>{});return p;};
 const call=fn=>bounded(fn,timeoutMs);
 const save=r=>{try{journal.append({type:'RUN',run:copy(r)});}catch(e){quarantined=true;throw e;}};
 for(const row of journal.read()) {
  need(row.entry.type==='RUN','JOURNAL_ENTRY_INVALID');const r=row.entry.run;
  launchRequest(JSON.stringify(r.request));runs.set(r.request.grant.run_id,copy(r));
 }
 for(const r of runs.values())if(!terminal.has(r.status)){r.status='OUTCOME_UNKNOWN';r.reason='RESTART_ORPHAN_QUARANTINED';save(r);}
 const get=id=>{need(runs.has(id),'RUN_UNKNOWN');return runs.get(id);};
 const children=r=>[...runs.values()].filter(c=>c.request.grant.parent_run_id===r.request.grant.run_id);
 const view=r=>freeze(copy({run_id:r.request.grant.run_id,project_id:r.request.grant.scope.project_id,task_id:r.request.grant.scope.task_id,
 actor_id:r.request.actor_id,child_id:r.request.child_id,status:r.status,reason:r.reason,cursor:r.cursor,checkpoint:r.checkpoint,
 artifact:r.artifact,qa:'QA_NOT_RUN',authoritative_complete:false,physical_decision:'DENY',mode:'RT01_SYNTHETIC_ONLY'}));
 const unknown=(r,reason)=>{if(r.status!=='OUTCOME_UNKNOWN'){r.status='OUTCOME_UNKNOWN';r.reason=reason;save(r);}
  for(const child of children(r))if(!terminal.has(child.status))unknown(child,'PARENT_OUTCOME_UNKNOWN');return view(r);};
 function live(r) {
  need(!quarantined,'RUNTIME_QUARANTINED');const req=r.request,g=req.grant,s=state.read(g.scope);
  need(s.state==='RUNNING'&&s.project_status==='READY'&&!s.cancelled&&!s.restore_pending&&!s.acceptance_stale,'STATE_DENIED');
  need(same(s.epochs,g.epochs)&&same(s.spec,g.spec)&&same(s.runtime_pin,req.runtime_pin)&&s.revision===g.expected_revision,'STATE_PIN_STALE');
  need(clock()<g.deadline&&s.lease_expires_at>clock()&&s.lease_actor===supervisor,'LEASE_EXPIRED');
  need(security.current(req)===true,'AUTHORITY_REVOKED');
  need(models.check(req.model)===true&&tools.check(req.tools)===true,'CAPABILITY_PIN_STALE');
  if(g.parent_run_id){const p=get(g.parent_run_id);need(p.status==='RUNNING','PARENT_NOT_RUNNING');live(p);}
  return s;
 }
 const guarded=fn=>async(...args)=>{try{return await fn(...args);}catch(e){return deny(e.message);}};
 async function launch(text) {
  const req=launchRequest(text),g=req.grant,existing=runs.get(g.run_id);
  if(existing){need(same(req,existing.request),'IDEMPOTENCY_CONFLICT');return view(existing);}
  const parent=g.parent_run_id===null?null:get(g.parent_run_id);
  const s=state.read(g.scope),ctx=createValidationContext({now:clock(),authenticated_identity_id:supervisor,
   principals:{[supervisor]:{role:'SUPERVISOR',projects:[g.scope.project_id]}},project_id:g.scope.project_id,task_id:g.scope.task_id,
   operation:{id:g.scope.operation_id},epochs:s.epochs,spec:s.spec,revision:s.revision,parent_grant:parent?.request.grant??null});
  need(validate('run-grant',g,ctx).ok,'GRANT_INVALID');
  need(g.max_physical_attempts>=1,'ATTEMPT_LIMIT');
  need(g.config_hash===configHash&&g.manifest_hash===manifestHash,'PROFILE_PIN_STALE');
  need(g.deadline<=s.lease_expires_at,'LEASE_EXPIRED');
  need(security.authorizeLaunch(req)===true,'ISSUER_DENIED');
  need(req.context.project_id===g.scope.project_id&&req.context.task_id===g.scope.task_id,'CONTEXT_SCOPE_DENIED');
  need(req.admission.project_id===g.scope.project_id&&req.admission.task_id===g.scope.task_id&&req.admission.operation_id!==g.scope.operation_id
   &&req.admission.plan_hash===planHash(req)&&req.admission.payload_hash===req.context.hash,'ADMISSION_BINDING_DENIED');
  need(req.tools.every(t=>g.capabilities.includes(t.id))&&g.capabilities.every(t=>req.tools.some(x=>x.id===t)),'TOOL_SCOPE_DENIED');
  if(parent){
   live(parent);const p=parent.request,pg=p.grant;
   need(parent.status==='RUNNING'&&pg.depth===0&&g.depth===1&&same(g.scope,pg.scope)&&same(g.epochs,pg.epochs)&&same(g.spec,pg.spec)
    &&same(req.model,p.model)&&same(req.runtime_pin,p.runtime_pin)&&req.context.revision===p.context.revision,'CHILD_SCOPE_WIDENED');
   need(req.tools.every(t=>p.tools.some(x=>same(x,t))),'CHILD_TOOLS_WIDENED');
   need(children(parent).length<pg.max_children,'CHILD_LIMIT');
   need(1+children(parent).reduce((n,c)=>n+c.request.grant.max_physical_attempts,0)+g.max_physical_attempts<=pg.max_physical_attempts,'TREE_ATTEMPT_LIMIT');
  }
  need(![...runs.values()].some(r=>r.request.child_id===req.child_id&&r.request.grant.scope.project_id===g.scope.project_id),'CHILD_ID_REUSED');
  need(![...runs.values()].some(r=>r.request.admission.attempt_id===req.admission.attempt_id&&r.request.grant.scope.project_id===g.scope.project_id),'ATTEMPT_REUSED');
  need(![...runs.values()].some(r=>r.request.admission.operation_id===req.admission.operation_id&&r.request.grant.scope.project_id===g.scope.project_id),'OPERATION_REUSED');
  const r={request:req,status:'LAUNCH_INTENT',reason:null,cursor:0,event_hashes:[],tool_operations:[],checkpoint:null,artifact:null};live(r);
  const bytes=await call(()=>context.read(req.context));
  need(typeof bytes==='string'&&digest({text:bytes})===req.context.hash&&Buffer.byteLength(bytes)<=32000,'CONTEXT_HASH_DENIED');live(r);
  // Persistent intent precedes D09 admission and any synthetic launch.
  save(r);runs.set(g.run_id,r);
  try {
   const admission=await call(()=>attempts.begin(req.admission));need(admission.physical_decision==='DENY'&&admission.attempt_id===req.admission.attempt_id,'ATTEMPT_RESPONSE_INVALID');live(r);
   const handle=await call(()=>transport.launchChild(freeze(copy(req)),bytes));handles.set(g.run_id,handle);live(r);
   r.status='RUNNING';save(r);return view(r);
  }catch(e){return unknown(r,e.message);}
 }
 async function consume(r,text) {
  const e=eventRequest(text),req=r.request,g=req.grant;
  need(e.project_id===g.scope.project_id&&e.task_id===g.scope.task_id&&e.actor_id===req.actor_id&&e.run_id===g.run_id&&e.child_id===req.child_id,'EVENT_SCOPE_DENIED');
  need(same(e.model,req.model),'MODEL_SWAP_DENIED');
  const previous=r.event_hashes.find(x=>x.seq===e.seq||x.id===e.event_id);
  if(previous){need(previous.hash===digest(e)&&previous.seq===e.seq&&previous.id===e.event_id,'EVENT_CONFLICT');return;}
  need(e.seq===r.cursor+1,'EVENT_GAP');
  need(r.status==='RUNNING'||(r.status==='CANCEL_REQUESTED'&&e.kind==='CANCELLED'),'LATE_EVENT_DENIED');
  if(e.kind!=='CANCELLED')live(r);
  if(e.kind==='TOOL_PROPOSAL') {
   exact(e.payload,['operation_id','tool_id','tool_digest','input_hash']);id(e.payload.operation_id);hash(e.payload.input_hash);
   const t=req.tools.find(t=>t.id===e.payload.tool_id);need(t&&t.digest===e.payload.tool_digest,'TOOL_PIN_DENIED');
   need(!r.tool_operations.includes(e.payload.operation_id),'TOOL_OPERATION_REPLAY');
   r.tool_operations.push(e.payload.operation_id);
   // Deliberately no TR01 dispatch. A proposal never becomes an effect here.
  }else if(e.kind==='RESULT') {
   exact(e.payload,['artifact_ref','artifact_hash']);hash(e.payload.artifact_ref);hash(e.payload.artifact_hash);
   need(children(r).every(c=>c.status==='WORK_COMPLETED'),'CHILDREN_NOT_JOINED');
   need(await call(()=>artifacts.verify(req,e.payload))===true,'ARTIFACT_READBACK_DENIED');live(r);
   r.artifact=copy(e.payload);r.status='WORK_COMPLETED';
  }else if(e.kind==='ERROR'){exact(e.payload,['code']);id(e.payload.code);
   for(const child of children(r))await cancel(child.request.grant.run_id);
   need(children(r).every(c=>terminal.has(c.status)&&c.status!=='OUTCOME_UNKNOWN'),'CHILD_FAILURE_UNCERTAIN');r.status='FAILED';r.reason=e.payload.code;}
  else if(e.kind==='CANCELLED'){exact(e.payload,[]);need(r.status==='CANCEL_REQUESTED'&&children(r).every(c=>terminal.has(c.status)&&c.status!=='OUTCOME_UNKNOWN'),'CANCEL_UNPROVEN');r.status='CANCELLED';}
  else exact(e.payload,[]);
  const finalStatus=r.status,terminalEvent=e.kind==='RESULT'||e.kind==='ERROR'||e.kind==='CANCELLED';
  r.cursor=e.seq;r.event_hashes.push({seq:e.seq,id:e.event_id,hash:digest(e)});
  // No durable success before D09 acknowledges the result transaction. A crash
  // at TERMINAL_INTENT is always quarantined by the next host, never accepted.
  if(terminalEvent)r.status='TERMINAL_INTENT';save(r);
  if(terminalEvent) {
   try{const result=await call(()=>attempts.result(req.admission,e.kind==='RESULT'?'SUCCEEDED':e.kind==='ERROR'?'FAILED':'CANCELLED',digest(e)));
    need(result.physical_decision==='DENY','ATTEMPT_RESPONSE_INVALID');if(e.kind!=='CANCELLED')live(r);r.status=finalStatus;save(r);}
   catch(error){unknown(r,error.message);}
  }
 }
 async function poll(runId) {
  const r=get(runId);if(terminal.has(r.status))return view(r);
  try {
   if(r.status!=='CANCEL_REQUESTED')live(r);need(handles.has(runId),'HANDLE_LOST');
   const batch=await call(()=>transport.streamEvents(handles.get(runId),r.cursor));
   need(Array.isArray(batch)&&batch.length<=profile.limits.event_batch,'EVENT_BATCH_INVALID');
   for(const text of batch)await consume(r,text);return view(r);
  }catch(e){return unknown(r,e.message);}
 }
 async function cancel(runId) {
  const r=get(runId);if(terminal.has(r.status))return view(r);
  r.status='CANCEL_REQUESTED';save(r);
  for(const c of children(r))await cancel(c.request.grant.run_id);
  try {
   const cancelled=await call(()=>attempts.cancel(r.request.admission));need(cancelled.physical_decision==='DENY','ATTEMPT_RESPONSE_INVALID');
   need(handles.has(runId),'HANDLE_LOST');
   const response=await call(()=>transport.cancel(handles.get(runId)));
   need(response.accepted===true,'CANCEL_NOT_ACKNOWLEDGED');
   // accepted means requested, never proof of process termination or refund.
   return await poll(runId);
  }catch(e){return unknown(r,e.message);}
 }
 const host=Object.freeze({
  launchChild:guarded(text=>serial(()=>launch(text))),
  streamEvents:guarded(runId=>serial(()=>poll(runId))),
  join:guarded(runId=>serial(async()=>{const r=get(runId);if(terminal.has(r.status))return view(r);await poll(runId);
   if(!terminal.has(r.status))return unknown(r,'JOIN_TIMEOUT');return view(r);})),
  cancel:guarded(runId=>serial(()=>cancel(runId))),
  checkpoint:guarded(runId=>serial(async()=>{const r=get(runId);live(r);need(r.status==='RUNNING','RUN_NOT_RUNNING');
   const pin={run_id:runId,request_hash:digest(r.request),cursor:r.cursor};r.checkpoint=digest(pin);save(r);return freeze({...pin,hash:r.checkpoint,resumable:false,physical_decision:'DENY'});})),
  reconcile:guarded(runId=>serial(async()=>{const r=get(runId);if(terminal.has(r.status))return view(r);
   try{live(r);need(handles.has(runId),'ORPHAN_HANDLE');const reply=await call(()=>transport.reconcile(handles.get(runId)));
    need(reply.connected===true,'DISCONNECTED');return await poll(runId);}catch(e){return unknown(r,e.message);}})),
  inspect:runId=>view(get(runId)),
  bindWorker(runId,session) {
   const r=get(runId),auth=()=>{need(security.authenticate(session,r.request)===true,'WORKER_UNAUTHENTICATED');};
   return Object.freeze({status:()=>{auth();return view(r);},cancel:guarded(()=>{auth();return host.cancel(runId);}),
    join:guarded(()=>{auth();return host.join(runId);}),
    proposeChild:text=>{auth();parseIntent(text);return deny('HOST_SCHEDULER_REQUIRED');},
    readMemory:()=>deny('D07_SCOPED_CONTEXT_ONLY'),writeMemory:()=>deny('D07_PROPOSAL_REQUIRED'),
    submitQa:()=>deny('INDEPENDENT_D08_REQUIRED'),accept:()=>deny('OWNER_REQUIRED'),
    executeTool:()=>deny('TR01_PROPOSAL_ONLY'),requestPhysicalEffect:()=>deny('E0_PHYSICAL_DENIED')});
  }
 });return host;
}
