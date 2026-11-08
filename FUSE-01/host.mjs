import fs from 'node:fs';
import path from 'node:path';
import {digest,canonicalize} from '../contracts/canonical.mjs';
import {harness} from '../tests/state/harness.mjs';
import {createArtifactStore} from '../awe/context/store.mjs';
import {createInt04OfflineHost} from '../INTEGRATION-01/adapters/int04-host.mjs';
import {createMockModel,createMockExecutors} from '../AUTO-01/mock.mjs';
import {fixture as securityFixture} from '../tests/execution_security/fixtures.mjs';
import {createExecutableTools} from '../awe/executable_tools/host.mjs';
import {programManifest,prepareNativeHermesTransport} from '../awe/hermes_runtime/executor-adapter.mjs';
import {verifyExecutionPins} from '../awe/hermes_runtime/execution-profile.mjs';
import {createD09ModelBroker} from '../llm02/broker.mjs';
import {transportConfig,query} from '../llm02/tests/fixtures.mjs';
import {binding,config} from '../tests/model_gateway/model-broker-fixtures.mjs';
import {createPostgresPersistence} from '../awe/persistence/postgres.mjs';
import {fixture as memoryFixture} from '../DATA-02/tests/fixture.mjs';
import {createCoordinatorPorts} from '../DATA-02/src/integration-ports.mjs';
import {reviewedManifest,LOCAL_PROFILE} from '../awe/execution_security/local-reviewed.mjs';
import {createReviewedLocalAdmission} from '../awe/execution_security/local-d09.mjs';
import {createExecutionGate} from '../awe/execution_security/gate.mjs';

// A host adapter of the delivered coordinator, never a second dispatcher.
// Positive fixture admission is deliberately NOT substituted for SEC/D09.
export async function createFuseCandidate({sessionId='fuse',h=harness(),beforePreflight=async()=>{},ownerContracts=false}={}){
 try{h.service.getProject(h.owner,'prj_alpha');}catch{await h.project();}
 const attempts=[],preflights=[];let effectCalls=0;
 const model=createMockModel();
 const executors=createMockExecutors({execute:async(id,handoff)=>{
  await beforePreflight(handoff);
  const scope={project_id:handoff.project_id,task_id:handoff.task_id,operation_id:'op_'+handoff.task_id.slice(5)};
  const current=h.service.getTask(h.state,scope);
  if(current.cancel_requested||current.restore_pending)throw Error('FUSE01_D03_CANCEL_OR_RESTORE');
  const sec=securityFixture({cost:'0'});
  const admission={current:()=>false,execute:async()=>{effectCalls++;throw Error('FUSE01_D09_ADMISSION_NOT_BOUND');}};
  const tools=createExecutableTools({scope,admission,reviewer:null,generator_id:'act_generator',limits:{timeout_ms:1000,max_output_bytes:8192}});
  let preflight;
  try{
   const pin=tools.resolve('js.text.stats')[0],manifest=tools.manifest(pin),rt=programManifest('javascript','sum');
   let runtimePins='VERIFIED';try{verifyExecutionPins();}catch(e){runtimePins=e.code??e.message;}
   // Exact executable/source/schema hashes are proposed as DATA. No grant is issued.
   const proposal=ownerContracts?reviewedManifest(scope.project_id):{...sec.manifest,tool_id:pin.id,code_digest:manifest.artifact_digest,schema_hash:manifest.input_schema_hash,
    implementation:'TOOLS02_EXECUTABLE_V1',cost_micros:'0'};
   let registryCode='UNEXPECTED_ACCEPT';
   try{sec.registry.control.register(sec.token('registry'),sec.peer('registry'),JSON.stringify(proposal));}
   catch(e){registryCode=e.code??e.message;}
   let localAdmission=null;
   if(ownerContracts&&registryCode==='UNEXPECTED_ACCEPT'){
    registryCode='REGISTERED_E0_LOCAL_REVIEWED_ONLY';
    Object.assign(sec.state,{task_id:scope.task_id,revision:current.revision,fence:current.fence,spec:current.spec,lease:current.lease,lease_until:Date.parse(current.lease.expires_at)});
    const grant=sec.auth.control.issueGrant(sec.token('supervisor'),sec.peer('supervisor'),JSON.stringify({...sec.grantRequest,task_id:scope.task_id,tools:[digest(proposal)],resources:proposal.resources,max_attempts:2}));
    const r={...sec.request,...scope,grant_token:grant,revision:current.revision,fence:current.fence,tool_id:proposal.tool_id,tool_version:proposal.version,tool_digest:proposal.code_digest,schema_hash:proposal.schema_hash,manifest_hash:digest(proposal),resource_id:proposal.resources[0],plan_hash:handoff.plan_hash,payload:{text:handoff.instructions},payload_hash:digest({text:handoff.instructions}),local:{profile:LOCAL_PROFILE,d09_approval_id:'unissued_owner_review',spec:current.spec,lease:current.lease,lease_until:sec.state.lease_until,deadline:sec.request.expires_at,...Object.fromEntries(['tools02_manifest_digest','runtime_artifact_digest','execution_binding_digest','input_schema_digest','output_schema_digest','limits'].map(k=>[k,proposal.local_binding[k]]))}};
    const admission=createReviewedLocalAdmission({pool:{connect:async()=>{throw Error('NO_REVIEWED_D09_POOL');}}});
    const gate=createExecutionGate({authority:sec.auth,verifier:sec.verifier,registry:sec.registry,admission,audit:sec.audit});
    localAdmission=await gate.execute(sec.token('worker'),sec.peer('worker'),JSON.stringify(r));
    if(localAdmission.decision!=='DENY')throw Error('OWNER02_UNEXPECTED_EXECUTION_WITHOUT_D09');
   }else if(registryCode==='UNEXPECTED_ACCEPT')throw Error('FUSE01_UNREVIEWED_REGISTRY_CHANGE');
   const request={scope:handoff,tools02:manifest,rt02:rt,requestedImplementation:proposal.implementation};
   const taskBinding=binding('main',{scopeId:'scope_'+sessionId,projectId:handoff.project_id,taskId:handoff.task_id,
    context:{project_id:handoff.project_id,task_id:handoff.task_id,revision:current.revision,readonly:true,
     snapshot:handoff.instructions,hash:digest({text:handoff.instructions}),artifact_ref:digest(handoff)}});
   const persistence=createPostgresPersistence({connect:async()=>{throw Error('FUSE01_NO_REVIEWED_D09_POOL');}});
   const broker=createD09ModelBroker({persistence,transportConfig:transportConfig('http://127.0.0.1:1/v1/chat/completions'),
    config:config({routeIds:['openai-direct'],maxAttempts:1,allowFallback:false,timeoutMs:500}),bindings:[taskBinding],
    readScope:()=>({projectId:handoff.project_id,taskId:handoff.task_id,validUntil:800000}),readAuthority:()=>({epoch:1,policyVersion:'fixture-v1'}),now:()=>1000});
   const planned=broker.plan('main',query('fuse_'+sessionId,{prompt:handoff.instructions}));
   const noAdmission=planned.decision==='READY_OFFLINE'?await broker.run(planned.handle,'unissued_approval','unissued_grant'):planned;
   attempts.push({decision:planned.decision,status:noAdmission.status??noAdmission.decision,code:noAdmission.code,physical_decision:'DENY',transport:'LOOPBACK_MOCK',outputReleased:noAdmission.outputReleased??false});
   preflight={handoff_hash:digest(handoff),scope,request_hash:digest(request),tools_pin:pin,tools_manifest:manifest,rt_manifest:rt,
    runtime_pins:runtimePins,sec_registry:registryCode,local_admission:localAdmission,d09_model:attempts.at(-1),physical_decision:'DENY',local_effects:0,
    native:prepareNativeHermesTransport(),cr:'FUSE01-CR-001'};
   preflights.push(preflight);
   return {version:'auto01/1',handoff_hash:digest(handoff),status:'FAILED',
    summary:'FUSE01_OWNER_CR_REQUIRED:'+registryCode,
    outputs:[{name:'admission-blocker.json',media_type:'application/json',text:canonicalize(preflight)}],uncertainties:[]};
  }finally{await tools.close();}
 }});
 const artifacts=createArtifactStore({max_entries:512,max_bytes:4194304,max_object_bytes:16384});
 const host=await createInt04OfflineHost({profile:'FUSE01',h,projectId:'prj_alpha',sessionId,model,executors,artifacts,maxReplans:0});
 fs.mkdirSync(path.resolve(import.meta.dirname,'../DATA-02/sandbox'),{recursive:true});
 const directory=fs.mkdtempSync(path.resolve(import.meta.dirname,'../DATA-02/sandbox/fuse-'));
 let data=memoryFixture({directory});
 const archive=[];
 function persist(kind,text){
  const snap=host.snapshot();if(snap.spec)data.world.projects.prj_alpha.spec=structuredClone(snap.spec.ref);
  const r=data.register({record_id:'mem_fuse_'+(archive.length+1),kind,text});
  const receipt=data.persist(r);if(!receipt.ok)throw Error(receipt.code);
  const readback=data.read(r);if(!readback.ok||readback.value.record.text!==text)throw Error('FUSE01_DATA_READBACK');
  archive.push({kind,ref:r.ref,receipt:receipt.value,text_hash:digest(text)});return r;
 }
 return {host,h,model,executors,artifacts,preflights,attempts,archive,
  async converse(text,key='goal'){
   const result=await host.converse({text,idempotencyKey:key,expectedRevision:host.snapshot().revision});
   const snap=host.snapshot();
   persist('GOAL',text);
   if(snap.spec)persist('SPEC',canonicalize({ref:snap.spec.ref,requirements:snap.spec.content.requirements,plan:snap.plan}));
   for(const p of preflights)persist('RESULT',canonicalize(p));
   return result;
  },
  snapshot:()=>({...host.snapshot(),admission_preflights:structuredClone(preflights),effects:effectCalls,positive_e2e:'BLOCKED_OWNER_CR',
   authoritative_qa:'NOT_SUBMITTED',authoritative_complete:false,accepted:false}),
  restoreView(){
   const saved=data.save();data=memoryFixture({directory,saved});
   const snap=host.snapshot(),scopeTask=Object.values(snap.tasks).find(t=>t.revision>0);
   const ports=createCoordinatorPorts({memory:data.memory,readerSession:data.session(),childSession:data.session('act_child'),
    readBindings:()=>({schema:'DATA02_BINDINGS_V1',project_id:'prj_alpha',task_id:scopeTask?.id??'task_fuse',revision:scopeTask?.revision??0,
     spec_ref:snap.spec?.ref.content_hash??data.world.projects.prj_alpha.spec.content_hash,required_refs:archive.map(a=>a.ref),
     child_record_ids:archive.map((_,i)=>'mem_fuse_'+(i+1)),purpose:'BUILD',context_bytes:16384})});
   return ports.host.restoreView();
  },
  foreignRead(){return data.memory.read(data.session('act_beta','prj_beta'),JSON.stringify({ref:archive[0].ref}));}
 };
}
