import fs from 'node:fs';
import path from 'node:path';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {digest,canonicalize} from '../../contracts/canonical.mjs';
import {createDiscovery} from '../tool_registry/discovery.mjs';
import {canonical as trCanonical,digest as trDigest} from '../tool_registry/common.mjs';
import {createModelGateway} from '../model_gateway/gateway.mjs';
import {syntheticProfile} from '../model_gateway/profiles.mjs';
import {createExecutionGate} from '../execution_security/gate.mjs';
import {intentBinding} from '../execution_security/authority.mjs';
import {SecurityError,need} from '../execution_security/common.mjs';
import {createEvaluationBoundary,evaluationPins} from '../execution_security/evaluation.mjs';
import {createHermesRuntime,planHash} from '../hermes_runtime/adapter.mjs';
import {createD03ReadPort} from '../hermes_runtime/d03-port.mjs';
import {openJournal} from '../hermes_runtime/journal.mjs';
import {configHash,manifestHash} from '../hermes_runtime/profile.mjs';
import {createD03QaPort} from '../qa/state-port.mjs';
import {writeCheckpoint} from './checkpoint.mjs';
const copy=structuredClone;
const hashBytes=bytes=>'sha256:'+createHash('sha256').update(bytes).digest('hex');

/** Explicit E0 TEST composition. All supplied handles are trusted fixture ports.
 * It calls the delivered TR/RT/LLM/SEC modules and unchanged D03/D06/D07 APIs.
 * It has no real Hermes, model, network, shell, dispatcher or second ledger.
 */
export async function createInt04OfflineHost({h,sec,m,b,modelRequest,directory,journalPath,task,options={}}){
 need(task.project_id==='prj_alpha'&&task.task_id==='task_one'&&typeof task.text==='string'&&task.text.length<=1024,'INT04_TASK');
 fs.mkdirSync(directory,{recursive:true});
 fs.writeFileSync(path.join(directory,'identity.json'),JSON.stringify({format:'INT04_E0_ONLY',task_hash:digest(task)})+'\n',{flag:'wx'});
 const scope={project_id:task.project_id,task_id:task.task_id,operation_id:'op_control_one'};
 const operationScope={...scope,operation_id:'op_int04_digest'};
 const payload={text:task.text},manifest=sec.manifest;
 let bundle=null,prepared=null,execution=null,model=null,discoveryBinding=null,parentRequest=null,childRequest=null;
 const plan={version:'INT04_PLAN_V1',task_hash:digest(task),steps:['DISCOVER','AUTHORIZE','MODEL','PARENT','CHILD','LOCAL_DIGEST','READBACK','D08','OWNER'],
  lifecycle_owner:'D03_StateService',money_owner:'D06_MemoryLedger',model_retry_owner:'D06_RouteBroker',runtime_retry_owner:'DISABLED',physical_decision:'DENY'};
 const save=()=>writeCheckpoint(directory,{task,plan,d03:h.storage.snapshot(),d06:b.ledger.checkpoint(),bundle});
 const read=()=>h.storage.read(db=>db.int04??{});
 const tx=async fn=>{const result=await h.storage.transaction(db=>{db.int04??={phase:'CREATED',transitions:[],events:{},runtime:{},attempts:{},audit:[],qa:null};const before=db.int04.phase,result=fn(db.int04);if(db.int04.phase!==before){const rows=db.int04.transitions,body={sequence:rows.length,previous:rows.at(-1)?.hash??null,from:before,to:db.int04.phase};rows.push({...body,hash:digest(body)});}return result;});save();return result;};
 await tx(()=>null);
 // D03 owns the operation intent and send marker. The only work is a pure digest.
 let t=h.service.getTask(h.state,scope);
 await h.service.intent(h.supervisor,{scope:operationScope,payload,tool_id:manifest.tool_id,tool_digest:manifest.code_digest,action:'read',resource:manifest.resources[0],effect_class:'READ_ONLY',approval_ref:null},t.revision,t.lease,'int04-intent');
 await h.dispatch(operationScope);save();
 const snapshot=()=>{const p=h.service.getProject(h.state,task.project_id),t=h.service.getTask(h.state,scope);return {project_id:task.project_id,task_id:task.task_id,status:t.state,epochs:p.epochs,revision:t.revision,fence:t.fence,cancelled:t.cancel_requested,restore_pending:t.restore_pending,uncertain:false,lease_until:Date.parse(t.lease?.expires_at??0)};};
 sec.directory.snapshot=(p,t)=>p===task.project_id&&t===task.task_id?snapshot():null;
 sec.setTime(Date.parse(h.now()));
 for(const p of Object.values(sec.principals))p.valid_until=Date.parse(h.now())+300000;
 const identity=id=>sec.token(id),peer=id=>sec.peer(id);
 const rootGrant=sec.auth.control.issueGrant(identity('supervisor'),peer('supervisor'),JSON.stringify({...sec.grantRequest,max_cost_micros:'0',max_attempts:3,max_children:1}));
 const childGrant=sec.auth.control.issueGrant(identity('worker'),peer('worker'),JSON.stringify({...sec.grantRequest,subject_id:'child',max_cost_micros:'0',max_attempts:1,max_children:0}),rootGrant);
 const s=snapshot();
 const request={...copy(sec.request),payload,payload_hash:digest(payload),plan_hash:digest(plan),grant_token:childGrant,epochs:s.epochs,revision:s.revision,fence:s.fence,expires_at:Date.parse(h.now())+60000};
 const review=()=>gate.review(identity('child'),peer('child'),JSON.stringify(request));
 const ack=(r,binding,status)=>({attempt_id:r.attempt_id,binding,status,committed:true,physical_decision:'DENY'});
 const admission={profile:'SEC01_SYNTHETIC_ADMISSION_V1',
  recoveryBarrier:async()=>({status:read().uncertain?'QUARANTINED':'READY',physical_decision:'DENY'}),
  admit:async({request:r,authorization:a,binding})=>tx(x=>{
   if(Object.keys(x.attempts).length||x.uncertain){const e=new SecurityError('INT04_OPERATION_REPLAY');e.knownNotAdmitted=true;throw e;}
   need(r.reserve_micros==='0'&&a.actor_id==='child'&&a.lineage.length===2&&r.plan_hash===digest(plan),'INT04_ADMISSION_SCOPE');
   x.attempts[r.attempt_id]={request_hash:digest(r),binding,status:'ADMITTED',lineage:a.lineage};return ack(r,binding,'ADMITTED');}),
  markSent:async r=>tx(x=>{need(x.attempts[r.attempt_id]?.status==='ADMITTED','INT04_ATTEMPT_STATE');x.attempts[r.attempt_id].status='SENT';return ack(r,r.binding,'SENT');}),
  complete:async r=>tx(x=>{need(x.attempts[r.attempt_id]?.status==='SENT'&&!snapshot().cancelled,'INT04_LATE_RESULT');x.attempts[r.attempt_id].status='WORK_COMPLETED';x.attempts[r.attempt_id].output=copy(r.output);return ack(r,r.binding,'WORK_COMPLETED');}),
  cancelKnownPreSend:async r=>tx(x=>{need(x.attempts[r.attempt_id]?.status==='ADMITTED','INT04_NOT_SENT_UNPROVEN');x.attempts[r.attempt_id].status='NOT_SENT';return {status:'NOT_SENT',committed:true};}),
  flagUnknown:async()=>tx(x=>{x.uncertain=true;return {status:'OUTCOME_UNKNOWN'};})};
 const gate=createExecutionGate({authority:sec.auth,verifier:sec.verifier,registry:sec.registry,admission,audit:{append:r=>tx(x=>{x.audit.push(copy(r));return null;})}});
 const trKeys=generateKeyPairSync('ed25519'),trEpochs={auth:s.epochs.auth,policy:s.epochs.policy,tool:1,project:1};
 const trPayload={tenant_id:'tenant_int04',actor_id:'child',project_id:task.project_id,tool_id:manifest.tool_id,version:manifest.version,revision:1,input_schema_digest:manifest.schema_hash,capabilities:['code.test'],epochs:trEpochs,issued_at:h.now(),valid_until:new Date(Date.parse(h.now())+60000).toISOString()};
 const trTool={tool_id:manifest.tool_id,title:'INT04 fixed synthetic digest',version:manifest.version,revision:1,capabilities:['code.test'],verified:'TESTED',available:'AVAILABLE',platform:['offline'],cost:{amount_micros:'0',currency:'RUB',basis:'E0_SYNTHETIC'},risk:'READ',disabled:false,compromised:false,hazards:[],valid_until:trPayload.valid_until,input_schema_digest:manifest.schema_hash,manifest_digest:trDigest(trPayload),signed_manifest:{key_id:'int04-e0',payload:trPayload,signature:sign(null,Buffer.from(trCanonical(trPayload)),trKeys.privateKey).toString('base64')}};
 const acl=(p,a)=>need(p===task.project_id&&a.tenant_id==='tenant_int04'&&a.actor_id==='child','INT04_TR_ACL');
 const discovery=createDiscovery({principal:{tenant_id:'tenant_int04',actor_id:'child'},clock:()=>Date.parse(h.now()),issuerKeys:{'int04-e0':trKeys.publicKey},repository:{search:async(r,a)=>{acl(r.project_id,a);return copy(options.toolDenied?[]:[trTool]);},get:async(p,id,a)=>{acl(p,a);return id===trTool.tool_id?copy(trTool):null;}},pep:{review:async({request:r})=>{
  const d=review();need(d.decision==='ALLOW_SIMULATION'&&r.artifact_digest===digest(manifest)&&r.plan_digest===digest(plan)&&r.input_schema_digest===manifest.schema_hash,'INT04_PEP_DENIED');
  return {decision:'ALLOW_E0_PROPOSAL',approval_digest:d.binding,request_digest:trDigest(r)};
 }}});
 const profiles=b.routes.map(r=>syntheticProfile(r));
 const gateway=createModelGateway({...b,profiles,readAuthority:()=>{
  // Bridge the delivered LLM authority barrier to current SEC lineage/task,
  // including its post-await check. D06 still owns monetary settlement.
  sec.auth.grant(rootGrant);sec.auth.grant(childGrant);return b.ledger.authority();
 }});
 const contextText=canonicalize({task,plan}),contextHash=digest({text:contextText});
 const contextArtifact=m.stageArtifact('art_int04_context',m.files(contextText));
 // RT01 revision identifiers exclude ':'; preserve all 256 bits with an
 // explicit identifier namespace instead of weakening its validator.
 const modelPin=()=>({id:prepared.plan.modelId,revision:'rev_'+prepared.plan.quote.profileHash.slice(7),route_id:prepared.request.allowedRoutes[0],route_revision:'route_'+prepared.plan.quote.routeHash.slice(7)});
 let journal=openJournal(journalPath),host;
 const queues=new Map(),resultArtifacts=new Map();let duplicateDelivered=false;
 const emit=(q,kind,payload={})=>{const r=q.request;const event={version:'rt01/1',project_id:task.project_id,task_id:task.task_id,actor_id:r.actor_id,run_id:r.grant.run_id,child_id:r.child_id,seq:q.events.length+1,event_id:'evt_'+r.grant.run_id+'_'+(q.events.length+1),kind,model:r.model,payload};q.events.push(JSON.stringify(event));return event;};
 const transport={mode:'RT01_SYNTHETIC_ONLY',
  launchChild:async r=>{const handle=r.grant.run_id;need(!queues.has(handle),'INT04_DUPLICATE_LAUNCH');queues.set(handle,{request:copy(r),events:[],worked:false});return handle;},
  streamEvents:async(handle,cursor)=>{
   const q=queues.get(handle);need(q,'INT04_CHILD_LOST');
   if(!q.worked&&handle==='run_int04_child'){
    q.worked=true;
    if(options.childFailure)emit(q,'ERROR',{code:'synthetic_child_failure'});
    else {execution=await gate.execute(identity('child'),peer('child'),JSON.stringify(request));
     if(execution.decision==='SIMULATED'){
      const bytes=Buffer.from(canonicalize(execution.output)),hash=digest(execution.output),ref=digest({run:handle,hash});resultArtifacts.set(ref,bytes);
      emit(q,'RESULT',{artifact_ref:ref,artifact_hash:hash});await tx(x=>{x.execution=copy(execution);return null;});
     }else emit(q,'ERROR',{code:'sec_denied'});
    }
   }else if(!q.worked&&handle==='run_int04_parent'&&host.inspect('run_int04_child').status==='WORK_COMPLETED'){
    q.worked=true;emit(q,'RESULT',host.inspect('run_int04_child').artifact);
   }
   const batch=q.events.filter(x=>JSON.parse(x).seq>cursor);
   if(options.duplicateEvent&&handle==='run_int04_child'&&!duplicateDelivered&&batch.length){duplicateDelivered=true;return [batch[0],batch[0],...batch.slice(1)];}
   return batch;
  },
  cancel:async handle=>{const q=queues.get(handle);need(q,'INT04_CHILD_LOST');q.worked=true;emit(q,'CANCELLED');return {accepted:true};},
  reconcile:async handle=>({connected:queues.has(handle)})};
 const state=createD03ReadPort({service:h.service,reader:h.state});
 const requestFor=(run,parent=null)=>{
  const t=h.service.getTask(h.state,scope),p=h.service.getProject(h.state,task.project_id),pin=state.read(scope).runtime_pin;
  const grant={schema_version:'1.0.0',contract:'run-grant',request_id:'req_int04',correlation_id:'corr_int04',causation_id:null,actor:h.supervisor,scope,epochs:p.epochs,spec:t.spec,created_at:h.now(),expected_revision:t.revision,run_id:run,parent_run_id:parent,capabilities:[manifest.tool_id],deadline:new Date(Date.parse(h.now())+6000).toISOString(),budget_ref:digest({owner:'D06',plan:prepared.plan.d06PlanHash}),config_hash:configHash,manifest_hash:manifestHash,depth:parent?1:0,max_children:parent?0:1,max_physical_attempts:parent?1:3};
  const r={version:'rt01/1',grant,actor_id:parent?'child':'worker',child_id:'child_'+run,context:{project_id:task.project_id,task_id:task.task_id,revision:1,readonly:true,hash:contextHash,artifact_ref:digest(contextArtifact.reference)},model:modelPin(),tools:[{id:manifest.tool_id,digest:manifest.code_digest}],runtime_pin:pin,
   admission:{project_id:task.project_id,task_id:task.task_id,operation_id:'op_'+run,attempt_id:'attempt_'+run,effect_slot:'slot_'+run,approval_id:'approval_'+run,grant_id:'grant_'+run,idempotency_key:'key_'+run,plan_hash:digest({}),payload_hash:contextHash,reserve_micros:'0'}};
  r.admission.plan_hash=planHash(r);return r;
 };
 const rtSecurity={authorizeLaunch:r=>{
  try{const actor=sec.verifier.authenticate(identity(r.actor_id),peer(r.actor_id),task.project_id,'WORKER');const g=sec.auth.grant(r.actor_id==='child'?childGrant:rootGrant);return actor.principal_id===g.subject_id&&r.tools.length===1&&r.tools[0].digest===manifest.code_digest;}catch{return false;}},
  current:r=>rtSecurity.authorizeLaunch(r),authenticate:(session,r)=>session===workerSessions[r.actor_id]&&rtSecurity.authorizeLaunch(r)};
 const workerSessions={worker:Object.freeze({}),child:Object.freeze({})};
 const args={state,security:rtSecurity,context:{read:()=>{const r=m.artifacts.read(m.session('act_worker'),JSON.stringify({artifact_id:'art_int04_context',version:contextArtifact.version,path:'site/index.txt'}));need(r.ok,'INT04_CONTEXT_READBACK');return Buffer.from(r.value.bytes_base64,'base64').toString('utf8');}},
  artifacts:{verify:async(req,c)=>{const bytes=resultArtifacts.get(c.artifact_ref);return Boolean(bytes&&hashBytes(bytes)===c.artifact_hash&&req.grant.scope.project_id===task.project_id);}},
  models:{check:p=>Boolean(prepared&&digest(p)===digest(modelPin())&&prepared.plan.d06PlanHash===model?.receipt?.planHash)},
  tools:{check:p=>Boolean(discoveryBinding?.status==='BOUND_E0_ONLY'&&p.length===1&&p[0].id===manifest.tool_id&&p[0].digest===manifest.code_digest&&review().decision==='ALLOW_SIMULATION')},
  attempts:{begin:r=>tx(x=>{need(r.reserve_micros==='0'&&!x.runtime[r.attempt_id],'INT04_RT_ADMISSION');x.runtime[r.attempt_id]={command:copy(r),status:'ADMITTED'};return {attempt_id:r.attempt_id,physical_decision:'DENY'};}),
   result:(r,status,event_hash)=>tx(x=>{need(x.runtime[r.attempt_id],'INT04_RT_UNKNOWN');x.runtime[r.attempt_id].status=status;x.runtime[r.attempt_id].event_hash=event_hash;return {physical_decision:'DENY'};}),
   cancel:r=>tx(x=>{need(x.runtime[r.attempt_id],'INT04_RT_UNKNOWN');x.runtime[r.attempt_id].cancel_requested=true;return {physical_decision:'DENY'};})},
  journal,transport,clock:h.now,supervisor:h.supervisor.identity_id,timeoutMs:1000};
 host=createHermesRuntime(args);
 const phase=async value=>tx(x=>{x.phase=value;return value;});
 const start=async()=>{
  if(read().phase!=='CREATED')return {status:'DENIED',reason:'INT04_START_REPLAY',physical_decision:'DENY'};
  await phase('PLANNED');
  const found=await discovery.searchCapabilities({project_id:task.project_id,need:'Запустить тест кода',capabilities:['code.test'],mode:'VERIFIED'});
  if(found.results.length!==1){await phase('TOOL_DENIED');return {status:'DENIED',reason:'TOOL_NOT_FOUND',physical_decision:'DENY'};}
  discoveryBinding=await discovery.bindTool({project_id:task.project_id,task_id:task.task_id,tool_id:trTool.tool_id,capability:'code.test',version:trTool.version,revision:1,manifest_digest:trTool.manifest_digest,input_schema_digest:trTool.input_schema_digest,epochs:trEpochs,operation_id:request.operation_id,idempotency_key:request.idempotency_key,artifact_digest:digest(manifest),plan_digest:digest(plan),max_cost_micros:'0',currency:'RUB'});
  if(discoveryBinding.status!=='BOUND_E0_ONLY'){await phase('AUTH_DENIED');return discoveryBinding;}
  prepared=gateway.prepare({...modelRequest,payload:{task_hash:digest(task),plan_hash:digest(plan),text:task.text},maxAttempts:1});
  if(prepared.decision!=='READY_OFFLINE'){await phase('MODEL_DENIED');return prepared;}
  // Only the authenticated synthetic HUMAN OWNER configures the D06 approval.
  sec.verifier.authenticate(identity('owner'),peer('owner'),task.project_id,'OWNER');
  const r=prepared.request,id='approval_int04_model';
  try{b.ledger.approve({id,operationId:r.operationId,logicalRequestId:r.logicalRequestId,correlationId:r.correlationId,scopeId:r.scopeId,effectSlot:r.effectSlot,planHash:prepared.d06.planHash,authority:r.authority,maxMicros:prepared.d06.totalBoundMicros,maxAttempts:1,expiresAt:r.deadline,allowUnknownCost:false});
   await phase('MODEL_SEND_INTENT');model=await gateway.run(prepared.handle,id);save();
  }catch(e){await phase('BUDGET_DENIED');return {status:'DENIED',code:e.code??e.message,physical_decision:'DENY'};}
  if(model.status!=='SUCCEEDED'){await phase('MODEL_'+model.status);return model;}
  parentRequest=requestFor('run_int04_parent');childRequest=requestFor('run_int04_child','run_int04_parent');
  const parent=await host.launchChild(JSON.stringify(parentRequest));if(parent.status!=='RUNNING')return parent;
  const child=await host.launchChild(JSON.stringify(childRequest));await phase('RUNNING');return {status:child.status,parent,child,physical_decision:'DENY'};
 };
 const finish=async()=>{
  if(read().phase!=='RUNNING')return {status:'DENIED',reason:'INT04_NOT_RUNNING',physical_decision:'DENY'};
  const child=await host.join('run_int04_child');if(child.status!=='WORK_COMPLETED'){await host.cancel('run_int04_parent');await phase(child.status);return child;}
  const parent=await host.join('run_int04_parent');if(parent.status!=='WORK_COMPLETED'){await phase(parent.status);return parent;}
  const receipt=h.receipt(operationScope,'CONFIRMED');await h.service.recordToolReceipt(h.state,receipt);
  await h.go('QA_PENDING');
  const qaPort=createD03QaPort({state:h.service,storage:h.storage,reader:h.state,supervisor:h.supervisor,scope,clock:h.now});
  const {pin,operations}=qaPort.read();
  const artifact={contract:'INT04_OUTPUT_V1',task,plan,discovery:discoveryBinding,model,runtime:{parent,child},execution,state_receipt:receipt,citations:[]};
  const bytes=Buffer.from(canonicalize(artifact)),staged=m.stageArtifact('art_int04_output',m.files(bytes.toString('utf8')));
  const readback=m.artifacts.read(m.session('act_worker'),JSON.stringify({artifact_id:'art_int04_output',version:staged.version,path:'site/index.txt'}));need(readback.ok&&hashBytes(Buffer.from(readback.value.bytes_base64,'base64'))===hashBytes(bytes),'INT04_D07_READBACK');
  bundle={reference:{project_id:task.project_id,task_id:task.task_id,artifact:copy(staged.reference.artifact),version:staged.version,file_hash:hashBytes(bytes),bytes:bytes.length,path:'site/index.txt',provenance_hash:staged.provenance_hash},bytes_base64:bytes.toString('base64'),pin,operations,
   requirements:{kind:'INT04_OUTPUT_V1',project_id:task.project_id,task_id:task.task_id,spec:pin.spec,task_hash:digest(task),plan_hash:digest(plan),payload,tool_manifest_hash:digest(manifest),code_digest:manifest.code_digest,forbidden_literals:['FOREIGN_CANARY_SECRET']},
   evidence:{task,plan,execution,sec_binding:intentBinding(request),tool_manifest:manifest,discovery:discoveryBinding,model,model_operation:b.ledger.operation(modelRequest.operationId),runtime:{parent,child},parent_request:parentRequest,child_request:childRequest,physical_dispatches:0,completion:{work:'WORK_COMPLETED',physical_decision:'DENY',accepted:false,published:false}}};
  await tx(x=>{x.phase='WORK_COMPLETED';x.bundle_hash=digest(bundle);x.bundle=copy(bundle);return null;});return {status:'WORK_COMPLETED',reference:bundle.reference,qa:'QA_NOT_RUN',accepted:false,physical_decision:'DENY'};
 };
 // QA record shares the existing D03 serial storage queue. SEC supplies identities
 // and signs only the result computed by unchanged fixed D08 entry point.
 const qaRequest={project_id:task.project_id,task_id:task.task_id,run_id:'qa_int04'};
 const qaCheck=r=>{need(r.project_id===task.project_id&&r.task_id===task.task_id&&r.run_id==='qa_int04','INT04_QA_SCOPE');need(bundle&&read().phase==='WORK_COMPLETED'&&!read().uncertain,'INT04_WORK_REQUIRED');need(digest(snapshot())===read().qa?.pin_hash||read().qa===null,'INT04_QA_STALE');need(!snapshot().cancelled&&!snapshot().restore_pending,'INT04_QA_BLOCKED');};
 const store={start:async(r,a)=>tx(x=>{qaCheck(r);need(x.qa===null,'INT04_QA_REPLAY');x.qa={pin_hash:digest(snapshot()),pin:snapshot(),binding:intentBinding(request),plan_hash:request.plan_hash,producer_id:'child',producer_generation:sec.principals.child.generation,producer_subject:sec.principals.child.subject,verifier_id:a.principal_id,verifier_generation:a.generation,verifier_subject:a.subject,qa:'QA_PENDING',proof:null,accepted:false};return {qa:'QA_PENDING',committed:true,physical_decision:'DENY'};}),
  readPending:async r=>{qaCheck(r);const x=read();need(x.qa.qa==='QA_PENDING'&&digest(x.bundle)===x.bundle_hash,'INT04_BUNDLE_CHANGED');return {...x.qa,bundle:copy(x.bundle),physical_decision:'DENY'};},
  finish:async(r,a,proof,result)=>tx(x=>{qaCheck(r);need(x.qa.qa==='QA_PENDING'&&a.role==='EVALUATOR','INT04_EVALUATOR_REQUIRED');x.qa.qa=result.verdict;x.qa.proof=proof;return {qa:result.verdict,committed:true,physical_decision:'DENY'};}),
  accept:async(r,a,proof,p)=>tx(x=>{qaCheck(r);need(!x.qa.rejected&&x.qa.proof===proof&&x.qa.qa==='QA_PASS'&&a.role==='OWNER'&&p.binding===x.qa.binding&&p.artifact_hash===x.bundle.reference.file_hash&&p.plan_hash===x.qa.plan_hash,'INT04_PROOF_NOT_COMMITTED');x.qa.accepted=true;return {accepted:true,committed:true,physical_decision:'DENY'};}),
  flagUnknown:async()=>tx(x=>{x.uncertain=true;if(x.qa)x.qa.accepted=false;return null;})};
 const evaluation=createEvaluationBoundary({verifier:sec.verifier,issuer:sec.issuer,store,pins:evaluationPins()});
 return {start,finish,plan,task,request,review,gate,discovery,gateway,sec,h,m,b,read,save,
  get bundle(){return copy(bundle);},get model(){return copy(model);},get runtime(){return host;},get prepared(){return prepared;},
  async verify(){const started=await evaluation.start(identity('verifier'),peer('verifier'),JSON.stringify(qaRequest));if(started.qa!=='QA_PENDING')return started;return evaluation.evaluateRun(identity('evaluator'),peer('evaluator'),JSON.stringify(qaRequest));},
  accept:(proof,who='owner')=>evaluation.accept(identity(who),peer(who),JSON.stringify(qaRequest),proof),
  reject:()=>tx(x=>{need(x.qa&&!x.qa.accepted,'INT04_OWNER_STATE');sec.verifier.authenticate(identity('owner'),peer('owner'),task.project_id,'OWNER');x.qa.rejected=true;return {acceptance:'OWNER_REJECTED',accepted:false,physical_decision:'DENY'};}),
  async cancel(){await host.cancel('run_int04_parent');const t=h.service.getTask(h.state,scope);await h.service.cancel(h.supervisor,scope,t.revision,'int04-user-cancel');b.ledger.cancel(modelRequest.operationId);await phase('CANCELLED');return {status:'CANCELLED',physical_decision:'DENY'};},
  worker:()=>host.bindWorker('run_int04_child',workerSessions.child),
  async deliverEvent(id,value){return tx(x=>{const hash=digest(value);if(x.events[id]){need(x.events[id]===hash,'INT04_EVENT_CONFLICT');return {status:'REPLAY'};}x.events[id]=hash;return {status:'RECORDED'};});},
  async restartRuntime(){journal.close();journal=openJournal(journalPath);host=createHermesRuntime({...args,journal});return host.inspect('run_int04_parent');},
  close(){journal.close();},
  testControl:{loseChild(){queues.delete('run_int04_child');},revokeChild(){sec.principals.child.generation++;},corruptBundle:()=>tx(x=>{x.bundle.bytes_base64=Buffer.from('{}').toString('base64');return null;})}
 };
}
