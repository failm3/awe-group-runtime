import {validateBrokerConfig,validateTaskBinding,exact,brokerId} from '../awe/model_gateway/broker-config.mjs';
import {validateShape} from '../awe/providers/validation.mjs';
import {createOpenAITransport} from './transport.mjs';
import {copy,hash,need,money,usage,quoteCost,safeCode,ProviderError,failResult} from './common.mjs';
const queryFields=['operationId','logicalRequestId','correlationId','effectSlot','taskClass','prompt','bounds','features','toolSchemas','jsonSchema','jsonExample','maxAttempts','deadline'];
// Alternative composition root; the original LLM01 mock/D06 broker is preserved byte for byte.
// This candidate can exercise ONLY loopback transport. Legacy D09 readbacks never grant LIVE dispatch.
export function createD09ModelBroker({persistence,transportConfig,config,bindings,readScope,readAuthority,now=Date.now}) {
 need(persistence&&['admit','claim','markSent','cancel','recordResult','inspect'].every(k=>typeof persistence[k]==='function'),'D09_PORT_REQUIRED');
 need(typeof readScope==='function'&&typeof readAuthority==='function','HOST_SCOPE_AUTHORITY_REQUIRED');
 const cfg=validateBrokerConfig(config),transport=createOpenAITransport(transportConfig,{now}),tc=transport.config();
 need(tc.mode==='LOOPBACK_MOCK','LIVE_ADMISSION_REQUIRED');
 for(const p of cfg.policies){
  need(p.maxAttempts===1&&!p.allowFallback&&p.routeIds.length===1&&p.routeIds[0]===tc.routeId,'D09_SINGLE_ATTEMPT_REQUIRED');
  need(p.allowedRegions.includes(tc.review.region)&&p.allowedPrivacy.includes(tc.review.privacy)&&p.qualityFloorBps<=tc.review.qualityLowerBoundBps,'ROUTE_REVIEW_POLICY_DENIED');
 }
 const fixed=bindings.map(b=>validateTaskBinding(b,{scope:readScope}));
 need(new Set(fixed.map(b=>b.id)).size===fixed.length&&new Set(fixed.map(b=>b.runId)).size===fixed.length,'DUPLICATE_BINDING');
 for(const b of fixed){need(b.context.hash===hash({text:b.context.snapshot}),'CONTEXT_HASH_MISMATCH');if(b.agentRole==='CHILD')need(fixed.some(p=>p.agentRole==='MAIN'&&p.runId===b.parentRunId&&p.scopeId===b.scopeId&&p.projectId===b.projectId&&p.taskId===b.taskId),'CHILD_LINEAGE_UNBOUND');}
 const scopes=new Map(fixed.map(b=>[b.id,b])),tickets=new WeakMap(),all=[],ids=new Map(),unresolved=new Map();
 const quoteExpires=Math.min(tc.price.validUntil,tc.price.fx.validUntil,tc.review.validUntil);
 let active=0;
 function checked(handle){const t=tickets.get(handle);need(t,'HOST_HANDLE_REQUIRED');return t;}
 function authority(){const a=readAuthority();need(a&&!a.then,'AUTHORITY_PORT_INVALID');return copy(a);}
 function barrier(t) {
  need(hash(authority())===t.authorityHash,'AUTHORITY_STALE');
  const s=readScope(t.binding.scopeId);
  need(s&&!s.then&&s.projectId===t.binding.projectId&&s.taskId===t.binding.taskId&&s.validUntil>now(),'SCOPE_STALE');
  need(now()<t.query.deadline&&now()<quoteExpires,'REQUEST_OR_QUOTE_EXPIRED');
  need(t.state!=='RUNNING'||t.wallDeadline===undefined||performance.now()<t.wallDeadline,'BROKER_TIMEOUT');
 }
 const unresolvedFor=t=>[...unresolved.values()].some(x=>x!==t&&x.binding.scopeId===t.binding.scopeId);
 function projection(t) {
  const r=t.wire??null,known=t.accounting?.accounting_status==='SETTLED',notSent=t.accounting?.status==='NOT_SENT'&&t.accounting?.accounting_status==='RELEASED'&&!r?.sent;
  return {version:'LLM02_USAGE_RECEIPT_V1',projectId:t.binding.projectId,taskId:t.binding.taskId,runId:t.binding.runId,parentRunId:t.binding.parentRunId,agentId:t.binding.agentId,agentRole:t.binding.agentRole,
   operationId:t.query.operationId,logicalRequestId:t.query.logicalRequestId,correlationId:t.query.correlationId,attemptId:t.attemptId,
   modelId:tc.modelId,modelRevision:tc.modelRevision,routeId:tc.routeId,provider:tc.provider,protocol:tc.protocol,
   planHash:t.planHash,payloadHash:t.prepared.requestHash,contextHash:t.binding.context.hash,configHash:hash(tc),profileHash:hash(tc.review),policyHash:hash(t.policy),
   providerRequestId:r?.providerRequestId??null,completionId:r?.completionId??null,clientRequestId:t.clientRequestId,responseHash:r?.responseHash??null,
   usage:r?.decoded?.usage??null,usageSource:r?.decoded?'PROVIDER_REPORTED_LOOPBACK_MOCK':'UNKNOWN',
   costMicros:known?t.accounting.actual_micros:notSent?'0':null,costStatus:known?'D09_RECONCILED':notSent?'D09_NOT_SENT':'UNKNOWN',currency:'RUB',reserveMicros:t.reserveMicros,
   financialOwner:'D09_PostgreSQL',accountingStatus:t.accounting?.accounting_status??'UNKNOWN',
   evidence:'LOOPBACK_HTTP_MOCK_NOT_LIVE',accepted:false,physicalDecision:'DENY'};
 }
 function plan(bindingId,raw,continuation=null) {
  try {
   const b=scopes.get(bindingId);need(b,'BINDING_UNKNOWN');const q=copy(raw);exact(q,queryFields);
   for(const k of ['operationId','logicalRequestId','correlationId','effectSlot','taskClass'])brokerId(q[k]);
   need(![...unresolved.values()].some(t=>t.binding.scopeId===b.scopeId),'ACCOUNTING_UNRESOLVED');
   const p=cfg.policies.find(x=>x.taskClass===q.taskClass);need(p&&p.agentRoles.includes(b.agentRole),'TASK_POLICY_DENIED');
   need(typeof q.prompt==='string'&&Buffer.byteLength(q.prompt)<=8000,'PROMPT_INVALID');usage(q.bounds);
   need(q.maxAttempts===1&&q.bounds.output>0&&q.bounds.output<=p.maxOutputTokens&&q.bounds.toolCalls<=Math.min(1,p.maxToolCalls),'REQUEST_LIMIT');
   need(q.features.tools||q.bounds.toolCalls===0,'TOOL_BOUND_UNREQUESTED');
   if(q.features.json)validateShape(q.jsonExample,q.jsonSchema);else need(q.jsonExample===null,'JSON_EXAMPLE_UNREQUESTED');
   const messages=continuation??[{role:'system',content:b.context.snapshot},{role:'user',content:q.prompt}];
   const prepared=transport.prepare({messages,toolSchemas:q.toolSchemas,jsonSchema:q.jsonSchema,maxOutput:q.bounds.output,features:q.features});
   const totalInput=q.bounds.uncachedInput+q.bounds.cacheRead+q.bounds.cacheWrite;
   need(Number.isSafeInteger(totalInput)&&totalInput>=prepared.requestBytes&&totalInput<=p.maxInputTokens&&q.bounds.cacheWrite===0,'INPUT_TOKEN_BOUND_INVALID');
   need(totalInput+q.bounds.output<=tc.review.contextTokens&&q.bounds.output<=tc.review.outputTokens,'MODEL_CONTEXT_OR_OUTPUT_LIMIT');
   // Bound every possible cache split conservatively. A cheap cached-input bound cannot lower reserve.
   const worst={uncachedInput:totalInput,cacheRead:0,cacheWrite:0,output:q.bounds.output,toolCalls:q.bounds.toolCalls};
   need(money(tc.price.rates.uncachedInput)>=money(tc.price.rates.cacheRead),'CACHE_PRICE_ORDER_UNSUPPORTED');
   const reserveMicros=quoteCost(tc.price,worst,now());need(money(reserveMicros)>0n&&money(reserveMicros)<=money(p.maxReserveMicros),'REQUEST_COST_CEILING');
   const auth=authority(),scope=readScope(b.scopeId);
   need(scope&&!scope.then&&scope.projectId===b.projectId&&scope.taskId===b.taskId,'SCOPE_STALE');
   need(Number.isSafeInteger(q.deadline)&&q.deadline>now()&&q.deadline<=scope.validUntil&&q.deadline<=quoteExpires,'DEADLINE_INVALID');
   const body={version:'LLM02_ATTEMPT_PLAN_V1',binding:b,query:q,requestHash:prepared.requestHash,transportConfigHash:hash(tc),policyHash:hash(p),authorityHash:hash(auth),
    reserveMicros,reservationOwner:'D09_PostgreSQL',attemptOwner:'D09_PostgreSQL',retryOwner:'DISABLED_SINGLE_ATTEMPT',maxAttempts:1,physicalDecision:'DENY'};
   const planHash=hash(body),key=b.projectId+':'+q.operationId;
   need(!ids.has(key),'OPERATION_ALREADY_PLANNED');
   need(all.length<tc.maxSessionRequests,'PLAN_SESSION_LIMIT');
   // Preserve IDs across every retry/replay; never grant a new attempt for a reused effect.
   need(!all.some(t=>t.binding.projectId===b.projectId&&(t.query.effectSlot===q.effectSlot||t.query.logicalRequestId===q.logicalRequestId)),'LOGICAL_EFFECT_ALREADY_PLANNED');
   const attemptId='a-'+planHash.slice(7),clientRequestId='c-'+planHash.slice(7),handle=Object.freeze({});
   const t={binding:b,query:q,policy:p,plan:body,planHash,prepared,messages:copy(messages),reserveMicros,attemptId,clientRequestId,authorityHash:hash(auth),state:'PLANNED',cancelled:false};
   tickets.set(handle,t);ids.set(key,t);all.push(t);
   return {decision:'READY_OFFLINE',physicalDecision:'DENY',handle,plan:copy(body),planHash,request:{...copy(q),payloadHash:prepared.requestHash},
    d09:{operation_id:q.operationId,attempt_id:attemptId,effect_slot:q.effectSlot,idempotency_key:'k-'+planHash.slice(7),plan_hash:planHash,payload_hash:prepared.requestHash,reserve_micros:reserveMicros},
    contextHash:b.context.hash,policyHash:hash(p),tokenBoundBasis:'REQUEST_UTF8_BYTES_CONSERVATIVE_MOCK_ONLY'};
  }catch(e){return {decision:'DENY',physicalDecision:'DENY',code:safeCode(e)};}
 }
 function validateReadback(t,r,allowed) {
  need(r&&r.physical_decision==='DENY'&&r.dispatch_authorized===false&&allowed.includes(r.status),'D09_READBACK_INVALID');
  need(r.project_id===t.binding.projectId&&r.attempt_id===t.attemptId&&r.operation_id===t.query.operationId&&hash(r.request)===hash(t.command)&&r.reserve_micros===t.reserveMicros,'D09_READBACK_BINDING_MISMATCH');
  need(['RESERVED','SETTLED','RELEASED','DISPUTED'].includes(r.accounting_status),'D09_ACCOUNTING_INVALID');
  if(r.accounting_status==='SETTLED'){money(r.actual_micros);need(money(r.actual_micros)<=money(t.reserveMicros),'D09_ACTUAL_OVER_ENVELOPE');}
  return copy(r);
 }
 async function port(t,method,command,allowed) {
  let timer;
  try {
   const pending=Promise.resolve().then(()=>persistence[method](command));
   const budget=Math.min(tc.timeoutMs,t.policy.timeoutMs);
   const wait=['cancel','inspect'].includes(method)||t.wallDeadline===undefined?budget:Math.max(1,Math.min(budget,Math.ceil(t.wallDeadline-performance.now()),t.query.deadline-now()));
   const timeout=new Promise((_,reject)=>{timer=setTimeout(()=>reject(new ProviderError('D09_ACK_TIMEOUT')),wait);});
   const r=await Promise.race([pending,timeout]);return validateReadback(t,r,allowed);
  }finally{clearTimeout(timer);}
 }
 const base=t=>({project_id:t.binding.projectId,attempt_id:t.attemptId});
 async function perform(t,approvalId,grantId) {
  try {
   brokerId(approvalId);brokerId(grantId);barrier(t);need(!unresolvedFor(t),'ACCOUNTING_UNRESOLVED');need(active<tc.maxConcurrent,'BROKER_BUSY');
   if(t.cancelled)return failResult('CANCELLED_BEFORE_ADMISSION','CANCELLED');
   t.wallDeadline=performance.now()+Math.min(tc.timeoutMs,t.policy.timeoutMs,t.query.deadline-now());
   active++;t.active=true;t.abort=new AbortController();
   t.command={project_id:t.binding.projectId,task_id:t.binding.taskId,operation_id:t.query.operationId,attempt_id:t.attemptId,effect_slot:t.query.effectSlot,
    approval_id:approvalId,grant_id:grantId,idempotency_key:'k-'+t.planHash.slice(7),plan_hash:t.planHash,payload_hash:t.prepared.requestHash,reserve_micros:t.reserveMicros};
   unresolved.set(t.attemptId,t);t.stage='ADMISSION';
   t.accounting=await port(t,'admit',t.command,['ADMITTED']);t.admissionAcknowledged=true;
   barrier(t);
   if(t.cancelled)throw new ProviderError('CANCELLED_BEFORE_SEND');
   t.stage='CLAIM';t.accounting=await port(t,'claim',base(t),['ADMITTED']);
   const fence=t.accounting.delivery_fence;
   need(typeof fence==='string'&&/^[1-9][0-9]*$/.test(fence)&&BigInt(fence)<=BigInt(Number.MAX_SAFE_INTEGER),'D09_FENCE_INVALID');
   barrier(t);if(t.cancelled)throw new ProviderError('CANCELLED_BEFORE_SEND');
   // This persists send intent only. It is deliberately NOT a native dispatch capability.
   t.stage='SEND_INTENT';t.accounting=await port(t,'markSent',{...base(t),fence:Number(fence)},['SENT']);
   barrier(t);if(t.cancelled)throw new ProviderError('CANCELLED_AFTER_SEND_INTENT');
   t.stage='HTTP';
   t.wire=await transport.send(t.prepared.handle,{clientRequestId:t.clientRequestId,signal:t.abort.signal,
    timeoutMs:Math.max(1,Math.min(tc.timeoutMs,t.policy.timeoutMs,t.query.deadline-now(),Math.ceil(t.wallDeadline-performance.now()))),bounds:copy(t.query.bounds),maxToolCalls:t.query.bounds.toolCalls});
   if(!t.wire.ok)throw new ProviderError(t.wire.code);
   barrier(t);need(!t.cancelled,'CANCELLED_AFTER_SEND');
   t.stage='RESULT';
   const receipt=projection(t),evidenceHash=hash(receipt);
   t.accounting=await port(t,'recordResult',{...base(t),result:'SUCCEEDED',evidence_hash:evidenceHash},['SENT','SETTLED']);
   barrier(t);need(!t.cancelled,'CANCELLED_AFTER_SEND');
   t.state='SUCCEEDED';
   // Provider usage is evidence, never an invoice. D09 remains RESERVED until its reconciler acts.
   return {status:'SUCCEEDED',code:'VALIDATED_PROVIDER_REPLY',outputReleased:true,output:copy(t.wire.decoded.output),receipt:projection(t),accepted:false,physicalDecision:'DENY',reconciliationRequired:true};
  }catch(e){
   const code=e?.outcomeUnknown===true?'D09_COMMIT_OUTCOME_UNKNOWN':safeCode(e);t.failure=code;
   if(t.stage){
    // No release inference from HTTP codes, timeouts, abort or malformed replies.
    // Once an owner call is ambiguous, retain local HOLD and do not repeat it or infer a refund.
    if(t.admissionAcknowledged&&code!=='D09_ACK_TIMEOUT'&&code!=='D09_COMMIT_OUTCOME_UNKNOWN') {
     try{t.accounting=await port(t,'cancel',base(t),['OUTCOME_UNKNOWN','NOT_SENT','SENT','SETTLED']);}catch{t.durableHoldAck=false;}
    }
    if(t.accounting?.status==='NOT_SENT'&&t.accounting.accounting_status==='RELEASED'&&!t.wire?.sent){
     t.state=t.cancelled?'CANCELLED':'DENIED';unresolved.delete(t.attemptId);
     return {...failResult(code,t.cancelled?'CANCELLED':'DENY'),receipt:projection(t),retainedLiability:false,reconciliationRequired:false};
    }
    t.state='OUTCOME_UNKNOWN';
    return {...failResult(code,'OUTCOME_UNKNOWN'),receipt:projection(t),retainedLiability:true,reconciliationRequired:true,durableStatus:t.accounting?.status??'UNKNOWN',durableHoldAcknowledged:t.accounting?.status==='OUTCOME_UNKNOWN'};
   }
   t.state=t.cancelled?'CANCELLED':'DENIED';return failResult(code,t.state==='CANCELLED'?'CANCELLED':'DENY');
  }finally{if(t.active){active--;t.active=false;}}
 }
 return Object.freeze({
  plan:(bindingId,query)=>plan(bindingId,query),
  bindTask(bindingId){need(scopes.has(bindingId),'BINDING_UNKNOWN');return Object.freeze({plan:q=>plan(bindingId,q)});},
  run(handle,approvalId,grantId) {
   try{const t=checked(handle);if(t.state==='RUNNING'&&t.pending)return t.pending;
    if(t.result)return Promise.resolve({...copy(t.result),output:null,outputReleased:false,replayed:true});
    t.state='RUNNING';t.pending=perform(t,approvalId,grantId).then(r=>{t.result=copy(r);return copy(r);});return t.pending;
   }catch(e){return Promise.resolve(failResult(safeCode(e)));}
  },
  cancel(handle) {const t=checked(handle);t.cancelled=true;t.abort?.abort();if(t.state==='PLANNED')t.state='CANCELLED';return {status:t.stage?'CANCEL_REQUESTED':'CANCELLED',physicalDecision:'DENY',output:null};},
  evidence(handle){const t=checked(handle);return {state:t.state,stage:t.stage??null,receipt:projection(t),failure:t.failure??null,liveCalls:0,physicalDecision:'DENY'};},
  async refreshAccounting(handle) {
   const t=checked(handle);need(t.command,'D09_ATTEMPT_MISSING');
   const r=await port(t,'inspect',base(t),['ADMITTED','SENT','SETTLED','NOT_SENT','OUTCOME_UNKNOWN']);t.accounting=r;
   // Reconciliation cannot turn an unknown execution into a successful one or unlock another effect.
   const clear=t.state==='SUCCEEDED'&&r.status==='SETTLED'&&r.accounting_status==='SETTLED';
   if(clear)unresolved.delete(t.attemptId);
   return {receipt:projection(t),hold:!clear,physicalDecision:'DENY'};
  },
  continueTools(previousHandle,toolResults,query) {
   try {
    const t=checked(previousHandle);need(t.state==='SUCCEEDED'&&!t.cancelled&&!t.continuationPlanned&&!unresolved.has(t.attemptId),'CONTINUATION_NOT_READY');barrier(t);
    need(query.prompt===t.query.prompt,'CONTINUATION_PROMPT_MISMATCH');
    const tools=t.wire.decoded.output.tools;need(tools.length>0&&Array.isArray(toolResults)&&toolResults.length===tools.length,'TOOL_RESULTS_REQUIRED');
    const results=copy(toolResults),seen=new Set();
    for(const r of results){exact(r,['id','content']);need(tools.some(x=>x.id===r.id)&&!seen.has(r.id)&&typeof r.content==='string'&&Buffer.byteLength(r.content)<=8000,'TOOL_RESULT_UNBOUND');seen.add(r.id);}
    const assistant={role:'assistant',content:t.wire.decoded.output.text||null,tool_calls:tools.map(x=>({id:x.id,type:'function',function:{name:x.name,arguments:JSON.stringify(x.arguments)}}))};
    const next=plan(t.binding.id,query,[...t.messages,assistant,...results.map(r=>({role:'tool',content:r.content,tool_call_id:r.id}))]);
    if(next.decision==='READY_OFFLINE')t.continuationPlanned=true;
    return next;
   }catch(e){return {decision:'DENY',physicalDecision:'DENY',code:safeCode(e)};}
  },
  runtimeModelPin(handle){const t=checked(handle);barrier(t);need(t.state==='SUCCEEDED'&&!t.cancelled,'MODEL_EXECUTION_NOT_CONFIRMED');return {id:tc.modelId,revision:'rev_'+hash({modelRevision:tc.modelRevision,config:tc}).slice(7),route_id:tc.routeId,route_revision:'route_'+hash(tc).slice(7)};},
  checkRuntimeModel(handle,pin){try{const t=checked(handle);barrier(t);return t.state==='SUCCEEDED'&&!t.cancelled&&hash(pin)===hash({id:tc.modelId,revision:'rev_'+hash({modelRevision:tc.modelRevision,config:tc}).slice(7),route_id:tc.routeId,route_revision:'route_'+hash(tc).slice(7)});}catch{return false;}},
  usageByAgent(bindingId) {
   const b=scopes.get(bindingId);need(b,'BINDING_UNKNOWN');
   const rows=all.filter(t=>t.binding.scopeId===b.scopeId&&t.binding.projectId===b.projectId&&t.binding.taskId===b.taskId&&t.stage);
   const groups=new Map();for(const t of rows){const key=t.binding.runId,rec=projection(t),g=groups.get(key)??{agentId:t.binding.agentId,agentRole:t.binding.agentRole,runId:key,operations:0,calls:0,inputTokens:0,outputTokens:0,knownCostMicros:'0',unknownCosts:0};
    g.operations++;if(t.wire?.sent)g.calls++;if(rec.usage){g.inputTokens+=rec.usage.uncachedInput+rec.usage.cacheRead;g.outputTokens+=rec.usage.output;}if(rec.costMicros===null)g.unknownCosts++;else g.knownCostMicros=String(money(g.knownCostMicros)+money(rec.costMicros));groups.set(key,g);}
   return {owner:'D09_PostgreSQL',currency:'RUB',evidence:'READ_ONLY_LOCAL_PROJECTION_OF_D09_AND_MOCK_REPLY',physicalDecision:'DENY',groups:[...groups.values()].map(g=>({...g,totalCostMicros:g.unknownCosts?null:g.knownCostMicros}))};
  },
  owners:()=>({reservation:'D09_PostgreSQL',attempt:'D09_PostgreSQL',retry:'DISABLED_SINGLE_ATTEMPT',d06:'PURE_QUOTE_ONLY',authorization:'EXTERNAL_TRUSTED_HOST',durableNativeBinding:'NOT_ACCEPTED'}),
  physicalDispatch:()=>({decision:'DENY',code:'LIVE_ADMISSION_REQUIRED'}),
  omniRoute:()=>({decision:'DENY',code:'OMNIROUTE_CONTRACT_NOT_CONFIRMED',physicalDecision:'DENY'})
 });
}
