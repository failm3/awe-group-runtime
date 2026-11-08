import {randomUUID} from 'node:crypto';
import {canonicalize,digest} from '../../contracts/canonical.mjs';
import {compileLiteralGoal,LITERAL_DIALECT} from '../../awe/integration_v4/literal-contract.mjs';
import {isPostgresStateStorage} from '../../awe/state/postgres-storage.mjs';
import {isD09QuotaEvidencePort} from '../../awe/budget/d09-quota-port.mjs';
import {reviewedWriteManifest,LOCAL_PROFILE,validateLocalRequest} from '../../awe/execution_security/local-reviewed.mjs';
import {createReviewedLocalAdmission,isLocalPlanRegistrar} from '../../awe/execution_security/local-d09.mjs';
import {createExecutionGate} from '../../awe/execution_security/gate.mjs';
import {intentBinding} from '../../awe/execution_security/authority.mjs';
import {readReviewedText} from '../../awe/execution_security/local-text-adapter.mjs';
import {createD03ArtifactPort} from '../../awe/artifacts/d03-artifact-port.mjs';
import {createData02CataloguePort} from '../../awe/artifacts/data02-catalogue-port.mjs';
import {createD03QaPort} from '../../awe/qa/state-port.mjs';
import {createQaService} from '../../awe/qa/service.mjs';
import {createDynamicD08Store} from '../../awe/qa/dynamic-store.mjs';
import {createEvaluationBoundary,evaluationPins} from '../../awe/execution_security/evaluation.mjs';
import {createProfileQa} from '../../awe/qa_profiles/service.mjs';
import {createSecProfileIssuer} from '../../awe/qa_profiles/sec-issuer.mjs';
import {runnerHash} from '../../awe/qa_profiles/runner.mjs';
import {isSavedSessionResumePort} from '../../MASTER-INTEGRATION-01/saved-session.mjs';
import {isOwnerFinalizationPort} from '../../MASTER-INTEGRATION-01/owner-finalization-port.mjs';
import {hashBytes,need,freeze} from '../../awe/execution_security/common.mjs';

// One bounded profile of the existing INT04 coordinator. No scheduler, ledger,
// mock model, fixture authority or auto acceptance. This function is host-only.
export async function createLiteralProfile(configuration){
 const {host,sessionId='master01'}=configuration;
 need(/^[a-z][a-z0-9_]{0,15}$/.test(sessionId),'MASTER_SESSION_ID');
 if(!host)return Object.freeze({profile:'MASTER01',prepare:input=>({status:'BLOCKED',code:'OWNER_POSTGRESQL_ADMISSION_REQUIRED',compiled:compileLiteralGoal(input),task_registered:false,effects:0,qa:'NOT_RUN',accepted:false,authoritative_complete:false,physical_decision:'DENY'})});
 const {state,storage,sessions,projectId,clock,security:sec,d09Pool,registrar,stores,readers,readerIds,retentionUntil,memoryStores}=host;
 need(isPostgresStateStorage(storage)&&storage.status().status==='BOUND','MASTER_D03_DURABLE_BINDING_REQUIRED');
 const finalizing=isOwnerFinalizationPort(host.finalize);need(!host.finalize||finalizing,'MASTER_FINALIZATION_HOST_PORT_REQUIRED');
 need(finalizing||(isLocalPlanRegistrar(registrar)&&d09Pool),'MASTER_REAL_D09_REQUIRED');
 need(finalizing||isD09QuotaEvidencePort(host.quota),'MASTER_REAL_D09_QUOTA_REQUIRED');
 const scope={project_id:projectId,task_id:'task_'+sessionId,operation_id:'op_control_'+sessionId},effectScope={...scope,operation_id:'op_write_'+sessionId};
 const ids=sec.actors,now=clock,identity=id=>sec.identity(id),peer=id=>sec.peer(id);
 const memory=createData02CataloguePort({state,owner:sessions.owner,reader:sessions.owner,scope,stores:memoryStores,clock:now});
 need(sessions.supervisor.identity_id===ids.supervisor&&sessions.owner.identity_id===ids.owner,'MASTER_IDENTITY_MAPPING');
 state.getProject(sessions.owner,projectId);
 const saved=()=>storage.read(db=>db.projects[projectId].master01?.[sessionId]??null);
 const tx=fn=>storage.transaction(db=>{const p=db.projects[projectId];p.master01??={};const r=p.master01[sessionId]??={phase:'NEW',scope,events:[]};const result=fn(r);return result;});
 const event=async(phase,details={})=>tx(r=>{r.phase=phase;r.events.push({phase,at:now(),...details});});
 let sealed,request,execution,reference,requirements,evaluation,proof,qaRequest,recheck;let busy=false;
 const get=()=>state.getTask(sessions.state,scope);
 const change=async to=>{if(to==='RUNNING')await host.quota.refresh();const {task,epochs,guards}=state.getTransitionContext(sessions.supervisor,scope);return state.transition(sessions.supervisor,{schema_version:'1.0.0',contract:'state-transition',request_id:'req_master',correlation_id:'corr_master',causation_id:null,actor:sessions.supervisor,scope,epochs,spec:task.spec,created_at:now(),expected_revision:task.revision,event_id:'evt_'+randomUUID().replaceAll('-',''),from_state:task.state,to_state:to,lease_epoch:task.lease_epoch,fence:task.fence,resume_state:task.resume_state,reason:'MASTER01 exact local text profile',guard_refs:Object.values(guards),owner_action_id:null,subscription_id:null});};
 const artifactOptions=producerId=>({state,writer:sessions.state,reader:sessions.owner,producerId,scope,stores,readers,clock:now});
 const originalArtifacts=createD03ArtifactPort(artifactOptions(ids.worker)),artifacts=finalizing?host.finalize.wrapArtifacts(originalArtifacts):originalArtifacts;
 const persist=async(port,artifact_id,bytes,path,media_type='text/plain')=>(await port.persist({artifact_id,files:[{path,media_type,bytes}],reader_ids:readerIds,retention_until:retentionUntil}))[0];
 const saveMemory=async(kind,value)=>{const x=await memory.persist({record_id:'mem_'+sessionId+'_'+kind.toLowerCase(),source_id:'src_'+sessionId+'_'+kind.toLowerCase(),version:1,kind,text:value,reader_ids:readerIds,purposes:['PERSIST','HISTORY','BUILD'],retention_until:retentionUntil});need(x.ok,'MASTER_DATA02_SAVE');return x;};
 const resuming=Boolean(saved()&&isSavedSessionResumePort(host.resume));
 if(saved()&&!resuming&&!finalizing)return Object.freeze({profile:'MASTER01',snapshot:()=>({...saved(),status:'HOLD',code:'MASTER_RESTART_RECONCILIATION_REQUIRED',accepted:false,authoritative_complete:false}),prepare(){throw Error('MASTER_RESTART_RECONCILIATION_REQUIRED');}});
 if(!resuming&&!finalizing)await tx(()=>null);
 const hold=async e=>{if(storage.status().status==='BOUND')try{await event('HOLD',{code:e.code??e.message});}catch{};};
 const api={profile:'MASTER01',snapshot:()=>({...saved(),accepted:saved()?.phase==='COMPLETE',authoritative_complete:saved()?.phase==='COMPLETE',physical_decision:'DENY'}),
  async continueAcceptance(){need(finalizing&&!busy&&saved().phase==='OWNER_ACCEPTANCE_REQUIRED','MASTER_FINALIZATION_STATE');busy=true;try{const x=await host.finalize.resume();({sealed,request,execution,reference,recheck}=x);qaRequest={project_id:projectId,task_id:scope.task_id,run_id:x.run_id};await event('QA_REQUIRED',{reason:'OWNER_FINALIZATION_FRESH_QA',owner_decision:recheck.owner_decision});return {status:'QA_REQUIRED',reference,dispatch:false};}catch(e){await hold(e);throw e;}finally{busy=false;}},
  async prepare(input){
   need(!finalizing&&!busy&&saved().phase===(resuming?'HOLD':'NEW'),'MASTER_REPLAY_FORBIDDEN');busy=true;
   try{sealed=compileLiteralGoal(input);const p=state.getProject(sessions.owner,projectId);need(p.status==='READY','MASTER_PROJECT_NOT_READY');
    const spec={spec_id:'spec_'+sessionId,revision:1,content_hash:sealed.spec_hash};
    if(resuming){need(digest(get().spec)===digest(spec)&&storage.read(db=>digest(db.projects[projectId].specs[spec.spec_id+':1'].content))===digest(sealed.spec),'MASTER_SAVED_SPEC_DRIFT');await host.resume.resume();await tx(r=>{need(r.phase==='HOLD','MASTER_SAVED_PHASE_DRIFT');r.scope=scope;r.phase='RESUMING';r.events.push({phase:'RESUMING',at:now(),permit_hash:host.resume.permitHash()});});}
    else{await state.storeSpec(sessions.owner,{schema_version:'1.0.0',contract:'spec-revision',request_id:'req_master_spec',correlation_id:'corr_master',causation_id:null,actor:sessions.owner,scope,epochs:p.epochs,spec,created_at:now(),expected_revision:p.revision,status:'APPROVED',requirements:['reqmt_exact_text','reqmt_exact_bytes'],norms:['constitution:0.1-draft:C-01'],supersedes:null},sealed.spec);
     await state.createTask(sessions.supervisor,{scope,name:'Create exact UTF-8 text artifact',dependencies:[],spec},sessionId);
     await state.acquireLease(sessions.supervisor,scope,get().revision,60000);await change('READY');}
    await change('RUNNING');
    memory.reconcile(sessions.owner,state.readCatalogue(sessions.owner,scope).pin);need(memory.status().durable_writer==='MASTER01_POSTGRES_D03','MASTER_DATA02_DURABLE_BINDING_REQUIRED');
    const manifest=reviewedWriteManifest(projectId);sec.registry.control.register(identity(ids.registry),peer(ids.registry),JSON.stringify(manifest));
    let t=get();await state.intent(sessions.supervisor,{scope:effectScope,payload:sealed.spec.input,tool_id:manifest.tool_id,tool_digest:manifest.code_digest,action:'fs.write',resource:manifest.resources[0],effect_class:'IDEMPOTENT_WRITE',approval_ref:host.approvalId},t.revision,t.lease,sessionId+'_write');t=get();
    const epochs=state.getProject(sessions.owner,projectId).epochs,expires_at=Math.min(Date.parse(t.lease.expires_at),sec.verifier.now()+45000);
    const grant=sec.auth.control.issueGrant(identity(ids.supervisor),peer(ids.supervisor),JSON.stringify({subject_id:ids.worker,project_id:projectId,task_id:scope.task_id,tools:[digest(manifest)],resources:manifest.resources,risks:['PROJECT_WRITE'],domains:[],max_cost_micros:'0',max_attempts:1,max_children:0,ttl_ms:expires_at-sec.verifier.now()}));
    request={v:'sec01.execution.v1',...effectScope,attempt_id:'attempt_'+sessionId,effect_slot:'slot_'+sessionId,idempotency_key:'key_'+sessionId,grant_token:grant,tool_id:manifest.tool_id,tool_version:manifest.version,tool_digest:manifest.code_digest,schema_hash:manifest.schema_hash,manifest_hash:digest(manifest),resource_id:manifest.resources[0],payload:sealed.spec.input,payload_hash:digest(sealed.spec.input),plan_hash:sealed.plan_hash,epochs,revision:t.revision,fence:t.fence,reserve_micros:'0',expires_at,approval_token:null,local:{profile:LOCAL_PROFILE,d09_approval_id:host.approvalId,spec,lease:t.lease,lease_until:Date.parse(t.lease.expires_at),deadline:expires_at,...Object.fromEntries(['tools02_manifest_digest','runtime_artifact_digest','execution_binding_digest','input_schema_digest','output_schema_digest','limits'].map(k=>[k,manifest.local_binding[k]]))}};
    await saveMemory('GOAL',input.goal);await saveMemory('SPEC',canonicalize(sealed.spec));await tx(r=>{r.spec=spec;r.plan=sealed.plan;r.request_binding=intentBinding(request);});await event('PREPARED');return {status:'PREPARED',spec,plan:sealed.plan,physical_decision:'DENY'};
   }catch(e){await hold(e);throw e;}finally{busy=false;}
  },
  async execute(){
   need(!finalizing&&!busy&&saved().phase==='PREPARED','MASTER_REPLAY_FORBIDDEN');busy=true;
   try{const manifest=sec.registry.resolve(request),authorization=sec.auth.authorize(identity(ids.worker),peer(ids.worker),request,manifest);
    // SEC's complete live binding is required before the first D09 write. The
    // execution gate repeats this check immediately before admission/dispatch.
    validateLocalRequest(request,manifest,sec.verifier,authorization);
    await registrar.register({request,identity:identity(ids.worker),peer:peer(ids.worker),binding:intentBinding(request)});
    const gate=createExecutionGate({authority:sec.auth,verifier:sec.verifier,registry:sec.registry,admission:createReviewedLocalAdmission({pool:d09Pool,master01:true}),audit:sec.audit});
    execution=await gate.execute(identity(ids.worker),peer(ids.worker),JSON.stringify(request));need(execution.decision==='EXECUTED_LOCAL','MASTER_'+(execution.code??'EXECUTION_NOT_CONFIRMED'));
    const bytes=readReviewedText(request,execution.output,()=>sec.auth.authorize(identity(ids.worker),peer(ids.worker),request,manifest));
    reference=await persist(artifacts,'art_'+sessionId,bytes,sealed.spec.input.path);
    const t=get(),receipt={schema_version:'1.0.0',contract:'tool-receipt',request_id:'req_master_receipt',correlation_id:'corr_master',causation_id:null,actor:sessions.state,scope:effectScope,epochs:request.epochs,spec:t.spec,created_at:now(),expected_revision:t.revision,receipt_id:'rcpt_'+sessionId,tool_id:manifest.tool_id,tool_digest:manifest.code_digest,payload_hash:request.payload_hash,effect_class:'IDEMPOTENT_WRITE',outcome:'CONFIRMED',output:reference.artifact,full_output_bytes:reference.artifact.bytes,truncated:false,retry_allowed:false,external_receipt:digest(execution.attempt_ack)};
    await state.recordLocalToolReceipt(sessions.state,receipt,execution.attempt_ack);await change('QA_PENDING');
    await saveMemory('RESULT',canonicalize({reference,receipt_hash:digest(receipt),d09_ack_hash:digest(execution.attempt_ack)}));await tx(r=>{r.reference=reference;r.d03_receipt=receipt;});await event('QA_REQUIRED');return {work:'WORK_COMPLETED',reference,accepted:false,physical_decision:'DENY'};
   }catch(e){await hold(e);throw e;}finally{busy=false;}
  },
  async verify(){
   need(!busy&&saved().phase==='QA_REQUIRED','MASTER_QA_STATE');busy=true;
   try{const statePort=createD03QaPort({state,storage,reader:sessions.state,supervisor:sessions.supervisor,scope,clock:now}),spec=get().spec;
    const issuer=createSecProfileIssuer({verifier:sec.verifier,issuer:sec.issuer,roles:{[ids.qa]:'EXAMINER',[ids.auditor]:'AUDITOR'},producerId:ids.worker});
    const qa=createProfileQa({statePort,artifacts:artifacts.reader(readers[0].reader_id),postSaveArtifacts:artifacts.reader(readers[1].reader_id),issuer,requirements:{version:'qa02/1',profile:'document',scope,spec,criteria:sealed.spec.criterion_requirement_mapping.map(m=>({id:m.criterion_id,requirement_id:m.requirement_id,check:m.check})),local_ids:['Q01','Q02']},reference,clock:now});
    const a=issuer.credential(identity(ids.qa),peer(ids.qa),qa.binding()),b=issuer.credential(identity(ids.auditor),peer(ids.auditor),qa.binding());
    const local=await qa.local(),examiner=await qa.examine(a.session,a.grant),auditor=await qa.audit(b.session,b.grant,{local,examiner});
    need(qa.gate({local,examiner,auditor}).verdict==='PASS','MASTER_CANDIDATE_QA_FAILED');
    const reports=[qa.inspect(examiner),qa.inspect(auditor)],logs=[];
    for(const [i,report]of reports.entries()){
     const identity_id=i?ids.auditor:ids.qa,reader_id=readers[i].reader_id,logPort=createD03ArtifactPort(artifactOptions(identity_id));
     const ref=await persist(logPort,'art_'+sessionId+(finalizing?'_owner1':'')+'_log'+i,Buffer.from(canonicalize(report)),'log.json','application/json');
     const bytes=logPort.read(ref,reader_id);logs.push({role:report.role,identity_id,generation:sec.verifier.principal(identity_id,projectId).generation,reader_id,reference:ref,readback_hash:hashBytes(bytes),readback_provenance_hash:ref.provenance_hash,bytes_base64:bytes.toString('base64')});
    }
    const handoff={project_id:projectId,task_id:scope.task_id,spec,plan_hash:sealed.plan_hash,node_hash:digest(sealed.plan.nodes[0]),payload_hash:request.payload_hash};
    requirements={kind:LITERAL_DIALECT,project_id:projectId,task_id:scope.task_id,spec,immutable_spec:sealed.spec,original_user_goal_hash:sealed.spec.original_user_goal_hash,dynamic_plan_hash:sealed.plan_hash,node_hash:digest(sealed.plan.nodes[0]),exact_handoff_hash:digest(handoff),criterion_requirement_mapping:sealed.spec.criterion_requirement_mapping};
    const evidence={read:()=>({original_user_goal:sealed.original_user_goal,current_spec:get().spec,dynamic_plan:sealed.plan,node:sealed.plan.nodes[0],exact_handoff:handoff,d03_receipt:saved().d03_receipt,d09_attempt_ack:execution.attempt_ack,execution:{attempt_id:execution.attempt_id,binding:execution.binding},d07_reference:reference,independent_readback:{reader_id:readers[1].reader_id,project_id:projectId,task_id:scope.task_id,version:reference.version,file_hash:reference.file_hash,provenance_hash:reference.provenance_hash,bytes_hash:hashBytes(artifacts.read(reference,readers[1].reader_id))},producer_id:ids.worker,producer_subject:sec.verifier.principal(ids.worker,projectId).subject,logs:logs.map(l=>({...l,bytes_base64:artifacts.read(l.reference,l.reader_id).toString('base64')})),log_authorities:logs.map(l=>{const p=sec.verifier.principal(l.identity_id,projectId);return {role:l.role,id:l.identity_id,subject:p.subject,generation:p.generation,active:p.active,valid_until:p.valid_until};}),now:sec.verifier.now(),qa02_runner_hash:runnerHash(),examiner_report_hash:digest(reports[0]),completion:{work:'WORK_COMPLETED',accepted:false,physical_decision:'DENY'}})};
    const artifactReader=artifacts.reader(readers[0].reader_id);const reporting=createQaService({statePort,artifacts:artifactReader,evidence,issuer,requirements,initialReference:reference});
    if(!finalizing)await reporting.worker.report({work:'WORK_COMPLETED',reference,expected_revision:reporting.inspect().revision});
    const store=createDynamicD08Store({statePort,artifacts:artifactReader,evidence,requirements,verifier:sec.verifier,...(finalizing?{recheck}:{})});evaluation=createEvaluationBoundary({verifier:sec.verifier,issuer:sec.issuer,store,pins:evaluationPins()});qaRequest??={project_id:projectId,task_id:scope.task_id,run_id:'qa_'+sessionId};
    need((await evaluation.start(identity(ids.qa),peer(ids.qa),JSON.stringify(qaRequest))).qa==='QA_PENDING','MASTER_D08_START');
    const result=await evaluation.evaluateRun(identity(ids.evaluator),peer(ids.evaluator),JSON.stringify(qaRequest));need(result.qa==='QA_PASS','MASTER_D08_NOT_PASS');proof=result.proof;
    await event('OWNER_ACCEPTANCE_REQUIRED',{proof_hash:digest(proof)});return {qa:'QA_PASS',accepted:false,reference,proof_hash:digest(proof),physical_decision:'DENY'};
   }catch(e){await hold(e);throw e;}finally{busy=false;}
  },
  async accept(ownerIdentity,ownerPeer,proofHash){
   need(!busy&&saved().phase==='OWNER_ACCEPTANCE_REQUIRED'&&proofHash===digest(proof),'MASTER_EXACT_OWNER_ACCEPTANCE_REQUIRED');busy=true;
   try{need(sec.verifier.authenticate(ownerIdentity,ownerPeer,projectId,'OWNER').principal_id===ids.owner,'MASTER_OWNER_IDENTITY');const accepted=await evaluation.accept(ownerIdentity,ownerPeer,JSON.stringify(qaRequest),proof);need(accepted.accepted===true,'MASTER_OWNER_NOT_ACCEPTED');
    await change('PERSISTING');const t=get();await state.checkpoint(sessions.supervisor,scope,t.revision,t.lease);await change('COMPLETE');const bytes=artifacts.read(reference,readers[1].reader_id);need(bytes.equals(Buffer.from(sealed.spec.input.text)),'MASTER_FINAL_READBACK');await event('COMPLETE');return {status:'COMPLETE',accepted:true,reference,bytes_base64:bytes.toString('base64'),physical_decision:'DENY'};
   }catch(e){await hold(e);throw e;}finally{busy=false;}
  }
 };return Object.freeze(api);
}
