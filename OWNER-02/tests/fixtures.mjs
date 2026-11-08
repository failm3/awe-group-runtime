import fs from 'node:fs';
import path from 'node:path';
import {fixture as secFixture} from '../../tests/execution_security/fixtures.mjs';
import {harness,scope} from '../../tests/state/harness.mjs';
import {fixture as artifactFixture} from '../../tests/memory_artifacts/fixtures.mjs';
import {createD07ArtifactReader} from '../../awe/qa/ports.mjs';
import {createD03QaPort} from '../../awe/qa/state-port.mjs';
import {createFixtureIssuer} from '../../awe/qa/authority.mjs';
import {createQaService} from '../../awe/qa/service.mjs';
import {createProfileQa} from '../../awe/qa_profiles/service.mjs';
import {runnerHash} from '../../awe/qa_profiles/runner.mjs';
import {canonicalize,digest,hashBytes} from '../../awe/execution_security/common.mjs';
import {reviewedManifest,LOCAL_PROFILE} from '../../awe/execution_security/local-reviewed.mjs';
import {createReviewedLocalAdmission} from '../../awe/execution_security/local-d09.mjs';
import {createExecutionGate} from '../../awe/execution_security/gate.mjs';
import {createData02CataloguePort} from '../../awe/artifacts/data02-catalogue-port.mjs';
import {createFileStore} from '../../DATA-02/src/file-store.mjs';
export {canonicalize,digest,hashBytes};
export function localFixture({recover,connect}={}){
 const f=secFixture({cost:'0'}),m=reviewedManifest('prj_alpha');
 f.state.spec={spec_id:'spec_local',revision:1,content_hash:digest({goal:'stats'})};
 f.state.lease={holder:'supervisor',lease_epoch:1,fence:f.state.fence,expires_at:new Date(f.state.lease_until).toISOString()};
 f.registry.control.register(f.token('registry'),f.peer('registry'),JSON.stringify(m));
 const root=f.auth.control.issueGrant(f.token('supervisor'),f.peer('supervisor'),JSON.stringify({...f.grantRequest,tools:[digest(m)],resources:m.resources,max_attempts:2}));
 const calls=[];
 const pool={connect:connect??(async()=>({query:async(sql,args)=>{calls.push({sql,args});if(sql.includes('recover_project'))return {rows:[{result:recover?await recover(f):{status:'READY',physical_decision:'DENY'}}]};return {rows:[]};},release(){}}))};
 const admission=createReviewedLocalAdmission({pool});
 const gate=createExecutionGate({authority:f.auth,verifier:f.verifier,registry:f.registry,admission,audit:f.audit});
 const r=structuredClone({...f.request,grant_token:root,tool_id:m.tool_id,tool_version:m.version,tool_digest:m.code_digest,schema_hash:m.schema_hash,manifest_hash:digest(m),resource_id:m.resources[0],local:{profile:LOCAL_PROFILE,d09_approval_id:'unissued_owner_review',spec:f.state.spec,lease:f.state.lease,lease_until:f.state.lease_until,deadline:f.request.expires_at,...Object.fromEntries(['tools02_manifest_digest','runtime_artifact_digest','execution_binding_digest','input_schema_digest','output_schema_digest','limits'].map(k=>[k,m.local_binding[k]]))}});
 const token=f.token('worker'),peer=f.peer('worker');
 return {...f,m,r,calls,pool,admission,gate,review:(q=r)=>gate.review(token,peer,JSON.stringify(q)),run:(q=r)=>gate.execute(token,peer,JSON.stringify(q))};
}
export async function dataFixture({storeFault={},storage}={}){
 const h=harness({storage});await h.running();
 const root=path.resolve(import.meta.dirname,'../../DATA-02/sandbox');fs.mkdirSync(root,{recursive:true});const dir=fs.mkdtempSync(path.join(root,'owner02-'));
 const stores=['a','b'].map(id=>createFileStore(path.join(dir,id),'owner02_'+id,{fault:storeFault[id]}));
 const options={state:h.service,owner:h.owner,reader:h.owner,scope:scope(),stores,clock:h.now};const port=createData02CataloguePort(options);
 port.reconcile(h.owner,h.service.readCatalogue(h.owner,scope()).pin);
 const input={record_id:'mem_owner02',source_id:'src_owner02',version:1,kind:'GOAL',text:'runtime goal text',reader_ids:['act_owner','act_worker'],purposes:['PERSIST','CONTEXT','BUILD','HISTORY'],retention_until:'2026-12-01T00:00:00.000Z'};
 return {h,dir,stores,port,input,options};
}
export async function dynamicFixture(){
 const goal='Посчитай статистику текста: тест 🧪\n42',input={text:'тест 🧪\n42'};
 const mapping=['utf8_bytes','code_points','lines','sha256'].map((field,i)=>({criterion_id:'Q0'+(i+1),requirement_id:'req_'+field,field}));
 const immutable_spec={dialect:'OWNER02_TEXT_STATS_V1',original_user_goal_hash:hashBytes(Buffer.from(goal)),input,criterion_requirement_mapping:mapping};
 const h=harness();await h.project();const spec=await h.spec('prj_alpha',immutable_spec);await h.task(scope(),[],spec);await h.lease();await h.go('READY');await h.go('RUNNING');
 const intent=await h.intent(scope(),'READ_ONLY',input);await h.dispatch(intent.scope);const receipt=h.receipt(intent.scope);await h.service.recordToolReceipt(h.state,receipt);
 const node={id:'node_stats',capability:'js.text.stats',input},plan={nodes:[node]},handoff={version:'auto01/1',project_id:'prj_alpha',task_id:'task_one',spec,plan_hash:digest(plan),node_hash:digest(node)};
 const output={utf8_bytes:Buffer.byteLength(input.text),code_points:[...input.text].length,lines:input.text.split('\n').length,sha256:hashBytes(Buffer.from(input.text))};
 const body={contract:'OWNER02_TEXT_STATS_V1',original_user_goal_hash:immutable_spec.original_user_goal_hash,dynamic_plan_hash:digest(plan),node_hash:digest(node),exact_handoff_hash:digest(handoff),output,citations:[]};
 const m=artifactFixture();m.bump(w=>{w.projects.prj_alpha.spec=spec;w.projects.prj_alpha.epochs=h.service.getProject(h.owner,'prj_alpha').epochs;});
 let head;
 const stage=(value,version=1)=>{const bytes=Buffer.from(canonicalize(value)),a=m.stageArtifact('art_dynamic',m.files(bytes.toString()),{version});head={project_id:'prj_alpha',task_id:'task_one',artifact:a.reference.artifact,version:a.version,file_hash:hashBytes(bytes),bytes:bytes.length,path:'site/index.txt',provenance_hash:a.provenance_hash};return head;};stage(body);
 const artifacts=createD07ArtifactReader({artifacts:m.artifacts,token:m.session('act_examiner'),readHead:()=>head});
 const independent=createD07ArtifactReader({artifacts:m.artifacts,token:m.session('act_auditor'),readHead:()=>head});
 const statePort=createD03QaPort({state:h.service,storage:h.storage,reader:h.state,supervisor:h.supervisor,scope:scope(),clock:h.now});
 const roles={worker:'EXECUTOR',qa:'EXAMINER',auditor:'AUDITOR',owner:'OWNER'};
 const issuer=createFixtureIssuer({principals:Object.fromEntries(Object.entries(roles).map(([id,role])=>[id,{role,active:true,subject:'subject:'+id,scopes:[{project_id:'prj_alpha',task_id:'task_one'}]}])),workerId:'worker',clock:()=>Date.parse(h.now())});
 const sessions=Object.fromEntries(Object.keys(roles).map(id=>[id,issuer.control.session(id)]));
 const profile={version:'qa02/1',profile:'document',scope:scope(),spec,criteria:mapping.map(x=>({id:x.criterion_id,requirement_id:x.requirement_id,check:{kind:'json-field',path:['output',x.field],expected:output[x.field]}})),local_ids:mapping.map(x=>x.criterion_id)};
 const qa02=createProfileQa({statePort,artifacts,postSaveArtifacts:independent,issuer,requirements:profile,reference:head,clock:h.now});
 const grant=(id,b=qa02.binding(),action='VERIFY')=>issuer.control.grant(sessions[id],action,b,Date.parse(h.now())+5000);
 const local=await qa02.local(),examiner=await qa02.examine(sessions.qa,grant('qa')),auditor=await qa02.audit(sessions.auditor,grant('auditor'),{local,examiner});
 const candidate=qa02.gate({local,examiner,auditor});
 const examinerReport=qa02.inspect(examiner),auditorReport=qa02.inspect(auditor);
 const logs=[examinerReport,auditorReport].map((report,i)=>{
  const bytes=Buffer.from(canonicalize(report)),a=m.stageArtifact('art_log_'+i,m.files(bytes.toString()));
  const ref={project_id:'prj_alpha',task_id:'task_one',artifact:a.reference.artifact,version:a.version,file_hash:hashBytes(bytes),bytes:bytes.length,path:'site/index.txt',provenance_hash:a.provenance_hash};
  const reader=createD07ArtifactReader({artifacts:m.artifacts,token:m.session(i?'act_examiner':'act_auditor'),readHead:()=>ref});const read=reader.read(ref);
  return {role:report.role,identity_id:i?'auditor':'qa',generation:1,reader_id:i?'qa':'auditor',reference:ref,readback_hash:hashBytes(read),readback_provenance_hash:ref.provenance_hash,bytes_base64:read.toString('base64')};
 });
 const requirements=structuredClone({kind:'OWNER02_TEXT_STATS_V1',project_id:'prj_alpha',task_id:'task_one',spec,immutable_spec,original_user_goal_hash:immutable_spec.original_user_goal_hash,dynamic_plan_hash:digest(plan),node_hash:digest(node),exact_handoff_hash:digest(handoff),criterion_requirement_mapping:mapping});
 // Explicit D09 COMPONENT fixture only. Not a real local admission or E2E proof.
 const e={original_user_goal:goal,current_spec:spec,dynamic_plan:plan,node,exact_handoff:handoff,d03_receipt:receipt,d09_attempt_ack:{local_profile:'E0_LOCAL_REVIEWED_ONLY',committed:true,status:'SUCCEEDED',local_execution_authorized:true,lineage_enforced:true,physical_decision:'DENY',dispatch_authorized:false,project_id:'prj_alpha',task_id:'task_one',operation_id:intent.scope.operation_id,attempt_id:'component_attempt',local_binding:digest('component'),dynamic_plan_hash:digest(plan),payload_hash:digest(input),output_hash:digest(output),spec_hash:digest(spec),epochs:h.service.getProject(h.owner,'prj_alpha').epochs},execution:{attempt_id:'component_attempt',binding:digest('component')},d07_reference:structuredClone(head),independent_readback:{reader_id:'auditor',project_id:'prj_alpha',task_id:'task_one',version:head.version,file_hash:head.file_hash,provenance_hash:head.provenance_hash,bytes_hash:hashBytes(independent.read(head))},producer_id:'worker',producer_subject:'subject:worker',logs,log_authorities:[{role:'independent',id:'qa',subject:'subject:qa',generation:1,active:true,valid_until:Date.parse(h.now())+5000},{role:'auditor',id:'auditor',subject:'subject:auditor',generation:1,active:true,valid_until:Date.parse(h.now())+5000}],now:Date.parse(h.now()),qa02_runner_hash:runnerHash(),examiner_report_hash:digest(examinerReport),completion:{work:'WORK_COMPLETED',accepted:false,physical_decision:'DENY'}};
 const evidence={read:()=>{for(const l of e.logs){const reader=createD07ArtifactReader({artifacts:m.artifacts,token:m.session(l.role==='auditor'?'act_examiner':'act_auditor'),readHead:()=>l.reference});const b=reader.read(l.reference);if(hashBytes(b)!==l.readback_hash)throw Error('LOG_READBACK_CHANGED');}return structuredClone(e);}};
 const service=createQaService({statePort,artifacts,evidence,issuer,requirements,initialReference:head});
 const report=()=>service.worker.report({work:'WORK_COMPLETED',reference:head,expected_revision:service.inspect().revision});
 const start=async()=>{const b=service.binding(),g=grant('qa',b);const handle=await service.verifier.start(sessions.qa,g,{expected_revision:service.inspect().revision,key:'dynamic'});return {g,handle};};
 const finish=run=>service.verifier.finish(sessions.qa,run.g,run.handle);
 const accept=run=>{const b=service.owner.binding(run.handle),g=grant('owner',b,'ACCEPT');return service.owner.accept(sessions.owner,g,run.handle,{expected_revision:service.inspect().revision,key:'owner'});};
 return {h,m,head:()=>head,statePort,artifacts,independent,evidence,issuer,sessions,requirements,e,body,candidate,service,report,start,finish,accept,replace:(change)=>{const b=structuredClone(body);change(b);stage(b,head.version+1);return head;},stage};
}
