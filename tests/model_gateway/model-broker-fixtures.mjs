import assert from 'node:assert/strict';
import {world,route,success} from '../budget/fixtures.mjs';
import {syntheticProfile,hash} from '../../awe/model_gateway/profiles.mjs';
import {createRecordedMockProvider} from '../../awe/model_gateway/mock-providers.mjs';
import {createModelBroker} from '../../awe/model_gateway/model-broker.mjs';
export function config(patch={}) {
 const policy={taskClass:'coding',routeIds:['r1','r2'],agentRoles:['MAIN','CHILD'],maxInputTokens:10000,maxOutputTokens:50,
   maxToolCalls:2,maxAttempts:2,maxReserveMicros:'20000',timeoutMs:100,allowFallback:false,qualityFloorBps:7500,
   allowedRegions:['fixture-eu'],allowedPrivacy:['SYNTHETIC_NO_RETENTION'],...patch};
 return {version:'LLM01_BROKER_CONFIG_V1',mode:'MOCK_ONLY',physicalDecision:'DENY',policies:[policy]};
}
export function binding(id='main',patch={}) {
 const snapshot='Context for project/task; read only.';
 return {id,scopeId:'scope',projectId:'project',taskId:'task',runId:'run-'+id,parentRunId:id==='main'?null:'run-main',
   agentId:'agent-'+id,agentRole:id==='main'?'MAIN':'CHILD',context:{project_id:'project',task_id:'task',revision:1,readonly:true,
     artifact_ref:hash({artifact:'context'}),snapshot,hash:hash({text:snapshot})},...patch};
}
export function query(id='one',patch={}) {
 return {operationId:'op-'+id,logicalRequestId:'logical-'+id,correlationId:'corr-'+id,effectSlot:'slot-'+id,taskClass:'coding',prompt:'Write reviewed code',
   bounds:{uncachedInput:2000,cacheRead:0,cacheWrite:0,output:20,toolCalls:0},features:{tools:false,stream:false,json:false},
   toolSchemas:{},jsonSchema:null,jsonExample:null,maxAttempts:1,deadline:7000,...patch};
}
export function brokerFixture(options={}) {
 const routes=[route(),route('r2','OpenRouter',{modelId:'synthetic-alternative-v2'})];
 for(const r of routes){r.capabilities.contextTokens=20000;r.price.binding.contextTokens=20000;}
 const w=world({routes,cap:'100000',...options.world});
 const controls={},mockProviders={};w.routes.forEach((r,i)=>{
   const m=createRecordedMockProvider({provider:r.provider,script:options.scripts?.[i]??[success()],deferred:options.deferred??false});
   controls[r.id]=m.control;mockProviders[r.id]=m.providerMock;
 });
 const profiles=w.routes.map((r,i)=>syntheticProfile(r,{quality:{lowerBoundBps:9000-i*500,reliabilityBps:9900,acceptedCostMicros:i?'10':'100'}}));
 let current=w.ledger.authority();
 const args={ledger:w.ledger,routes:w.routes,profiles,mockProviders,config:options.config??config(),bindings:options.bindings??[binding(),binding('child')],readAuthority:()=>current};
 const broker=createModelBroker(args);
 return {...w,broker,controls,args,revoke:()=>current={...current,epoch:2}};
}
export function approvePlan(f,p,id='ap-'+p.request.operationId) {
 assert.equal(p.decision,'READY_OFFLINE',JSON.stringify(p));const q=p.request;
 f.ledger.approve({id,operationId:q.operationId,logicalRequestId:q.logicalRequestId,correlationId:q.correlationId,scopeId:q.scopeId,
   effectSlot:q.effectSlot,planHash:p.d06.planHash,authority:q.authority,maxMicros:p.d06.totalBoundMicros,maxAttempts:q.maxAttempts,expiresAt:7000,allowUnknownCost:false});
 return id;
}
