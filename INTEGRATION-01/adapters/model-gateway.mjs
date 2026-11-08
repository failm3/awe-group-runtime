import {createModelBroker} from '../../awe/model_gateway/model-broker.mjs';
import {createRecordedMockProvider} from '../../awe/model_gateway/mock-providers.mjs';
import {createHash} from 'node:crypto';
import {digest,canonicalize} from '../../contracts/canonical.mjs';
// Compatibility at the existing INT04 trusted-host seam. No reserve or retry
// writer here: all calls enter the delivered LLM01 broker and the SAME D06 ledger.
export function createModelGateway({ledger,routes,profiles,readAuthority,integrationMemory:m,integrationOptions={}}){
 let broker=null,planned=null,contextEvidence=null,controls={},providers={};
 for(const r of routes){const m=createRecordedMockProvider({provider:r.provider,script:[integrationOptions.providerFailure?{status:'TIMEOUT'}:{status:'OK',complete:true,usage:{uncachedInput:4,cacheRead:0,cacheWrite:0,output:2,toolCalls:0},output:{text:'LLM01_OFFLINE_TASK_ACK',tools:[]}}]});providers[r.id]=m.providerMock;controls[r.id]=m.control;}
 return {
  prepare(raw){
   if(planned)return {decision:'DENY',code:'INTEGRATION01_PLAN_REPLAY',physicalDecision:'DENY'};
   const snapshot=canonicalize({project_id:raw.projectId,task_id:raw.taskId,task_hash:raw.payload.task_hash,plan_hash:raw.payload.plan_hash,text:raw.payload.text});
   const staged=m.stageArtifact('art_int01_model_context',m.files(snapshot));const read=m.artifacts.read(m.session('act_worker'),JSON.stringify({artifact_id:'art_int01_model_context',version:staged.version,path:'site/index.txt'}));if(!read.ok||Buffer.from(read.value.bytes_base64,'base64').toString('utf8')!==snapshot)throw Error('MODEL_CONTEXT_D07_READBACK');contextEvidence={reference:staged.reference,version:staged.version,readback_version:read.value.version,readback_hash:'sha256:'+createHash('sha256').update(Buffer.from(snapshot)).digest('hex')};
   const context={project_id:raw.projectId,task_id:raw.taskId,revision:1,readonly:true,artifact_ref:digest(staged.reference),snapshot,hash:digest({text:snapshot})};
   const main={id:'main',scopeId:raw.scopeId,projectId:raw.projectId,taskId:raw.taskId,runId:'run_int04_parent',parentRunId:null,agentId:'worker',agentRole:'MAIN',context};
   broker=createModelBroker({ledger,routes,profiles,mockProviders:providers,readAuthority,bindings:[main,{...main,id:'child',runId:'run_int04_child',parentRunId:main.runId,agentId:'child',agentRole:'CHILD'}],
    config:{version:'LLM01_BROKER_CONFIG_V1',mode:'MOCK_ONLY',physicalDecision:'DENY',policies:[{taskClass:'offline_digest',routeIds:raw.allowedRoutes,agentRoles:['MAIN','CHILD'],maxInputTokens:8000,maxOutputTokens:50,maxToolCalls:0,maxAttempts:1,maxReserveMicros:'9000',timeoutMs:1000,allowFallback:false,qualityFloorBps:0,allowedRegions:raw.allowedRegions,allowedPrivacy:raw.allowedPrivacy}]}});
   planned=broker.plan('main',{operationId:raw.operationId,logicalRequestId:raw.logicalRequestId,correlationId:raw.correlationId,effectSlot:raw.effectSlot,taskClass:'offline_digest',prompt:'Acknowledge only the bounded task context. Do not evaluate QA or issue permissions.',bounds:{uncachedInput:6000,cacheRead:0,cacheWrite:0,output:20,toolCalls:0},features:raw.features,toolSchemas:raw.toolSchemas,jsonSchema:raw.jsonSchema,jsonExample:raw.jsonExample,maxAttempts:1,deadline:raw.deadline});
   return planned;
  },
  run:async(handle,approvalId)=>({...await broker.run(handle,approvalId),integrationContextEvidence:structuredClone(contextEvidence)}),
  physicalDispatch:()=>({decision:'DENY',physicalDecision:'DENY'}),
  owners:()=>broker?.owners()??{reservation:'D06_MemoryLedger',attempt:'D06_RouteBroker'},
  evidence:()=>planned?.handle?broker.evidence(planned.handle):null,
  runtimeModelPin:()=>broker.runtimeModelPin(planned.handle),
  get broker(){return broker;},get plan(){return planned;}
 };
}
