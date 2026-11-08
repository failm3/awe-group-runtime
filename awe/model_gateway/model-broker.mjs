import {createModelGateway} from './gateway.mjs';
import {copy,hash,validateProfile} from './profiles.mjs';
import {validateBrokerConfig,validateTaskBinding,exact,brokerId} from './broker-config.mjs';
import {recordedAdapter,observedMockCalls} from './mock-providers.mjs';
import {requireThat as need,usage,money} from '../budget/money.mjs';
const errorCode=e=>typeof e?.code==='string'?e.code:'MODEL_BROKER_DENIED';
const physical=Object.freeze({decision:'DENY',code:'E0_PHYSICAL_EGRESS_DISABLED'});

// INT04 E0 composition: existing D06 is the only reserve/attempt/retry writer.
// This object owns plans/opaque handles/read-only evidence, never money, approvals or identity.
export function createModelBroker({ledger,routes,profiles,mockProviders,config,bindings,readAuthority}) {
  const cfg=validateBrokerConfig(config),rs=copy(routes),ps=copy(profiles),mocks={...mockProviders},tickets=new WeakMap(),scopes=new Map();
  need(new Set(bindings.map(x=>x.id)).size===bindings.length,'DUPLICATE_BINDING');
  const fixedBindings=bindings.map(x=>validateTaskBinding(x,ledger));
  need(new Set(fixedBindings.map(x=>x.runId)).size===fixedBindings.length,'DUPLICATE_RUN_BINDING');
  for(const b of fixedBindings) {
    need(b.context.hash===hash({text:b.context.snapshot}),'CONTEXT_HASH_MISMATCH');
    if(b.agentRole==='CHILD')need(fixedBindings.some(p=>p.runId===b.parentRunId&&p.agentRole==='MAIN'&&p.scopeId===b.scopeId&&p.projectId===b.projectId&&p.taskId===b.taskId),'CHILD_LINEAGE_UNBOUND');
    scopes.set(b.id,b);
  }
  const gateways=new Map();
  for(const policy of cfg.policies) {
    const chosen=rs.filter(r=>policy.routeIds.includes(r.id));need(chosen.length===policy.routeIds.length,'POLICY_ROUTE_UNKNOWN');
    const qualified=ps.filter(p=>chosen.some(r=>hash(r)===p.routeHash)).filter(p=>{
      validateProfile(p);return p.quality.lowerBoundBps>=policy.qualityFloorBps;
    });
    need(qualified.length>0,'QUALITY_FLOOR_NOT_MET');
    need(new Set(chosen.map(r=>r.alias)).size===1&&new Set(chosen.map(r=>r.capabilities.protocol)).size===1,'ROUTE_PROTOCOL_ALIAS_CONFLICT');
    const adapters=Object.fromEntries(chosen.map(r=>[r.id,recordedAdapter(mocks[r.id])]));
    gateways.set(policy.taskClass,createModelGateway({ledger,routes:chosen,profiles:qualified,adapters,readAuthority}));
  }
  function checked(handle) {const t=tickets.get(handle);need(t,'HOST_HANDLE_REQUIRED');return t;}
  function executionEvidence(t,result=null) {
    const op=ledger.operation(t.request.operationId);
    if(!op)return {version:'LLM01_EXECUTION_EVIDENCE_V1',evidence:'NO_D06_ATTEMPT',physicalDecision:'DENY',attempts:[]};
    need(op.planHash===t.prepared.d06.planHash,'LEDGER_PLAN_MISMATCH');
    const attempts=op.attempts.map(a=>{
      const route=op.plan.routes.find(r=>r.id===a.routeId),calls=observedMockCalls(mocks[a.routeId],[a.id]);
      need(calls.length<=1,'MOCK_DUPLICATE_DISPATCH');
      for(const c of calls)need(c.payloadHash===t.prepared.plan.payloadHash&&c.modelId===route.modelId&&c.idempotencyKey===a.idempotencyKey,'MOCK_CALL_BINDING_MISMATCH');
      return {attemptId:a.id,routeId:a.routeId,provider:a.provider,modelId:route.modelId,status:a.status,
        requestHash:t.prepared.plan.payloadHash,observedCall:calls[0]??null,usage:a.usage,costMicros:a.settledMicros,
        providerRequestId:a.providerRequestId,unknown:a.status==='IN_FLIGHT',evidence:calls.length?'OBSERVED_D06_SEALED_MOCK_CALL':'NO_MOCK_CALL_OBSERVED'};
    });
    const body={version:'LLM01_EXECUTION_EVIDENCE_V1',projectId:t.binding.projectId,taskId:t.binding.taskId,runId:t.binding.runId,
      parentRunId:t.binding.parentRunId,agentId:t.binding.agentId,agentRole:t.binding.agentRole,contextHash:t.binding.context.hash,
      contextArtifact:t.binding.context.artifact_ref,policyHash:t.policyHash,planHash:op.planHash,status:op.status,
      evidence:'OBSERVED_MOCK_EXECUTION_NOT_LIVE',physicalDecision:'DENY',accepted:false,attempts,
      responseHash:result?.outputReleased&&result.output!==null?hash(result.output):null,
      resultReadback:result?.outputReleased&&result.output!==null?'VALIDATED_REPLY_IN_THIS_CALL':'NO_STORED_OUTPUT_READBACK'};
    return {...body,evidenceHash:hash(body)};
  }
  function plan(bindingId,raw) {
    try {
      const b=scopes.get(bindingId);need(b,'BINDING_UNKNOWN');const q=copy(raw);
      exact(q,['operationId','logicalRequestId','correlationId','effectSlot','taskClass','prompt','bounds','features','toolSchemas','jsonSchema','jsonExample','maxAttempts','deadline']);
      for(const k of ['operationId','logicalRequestId','correlationId','effectSlot','taskClass'])brokerId(q[k]);
      const policy=cfg.policies.find(x=>x.taskClass===q.taskClass);need(policy&&policy.agentRoles.includes(b.agentRole),'TASK_POLICY_DENIED');
      need(typeof q.prompt==='string'&&Buffer.byteLength(q.prompt)<=8000,'PROMPT_INVALID');usage(q.bounds);
      const totalInput=q.bounds.uncachedInput+q.bounds.cacheRead+q.bounds.cacheWrite;
      // E0 uses a conservative UTF8-byte upper bound, not a claim of provider tokenizer parity.
      const payload={format:'LLM01_TASK_MODEL_REQUEST_V1',brokerScope:{bindingId:b.id,projectId:b.projectId,taskId:b.taskId,runId:b.runId,parentRunId:b.parentRunId,agentId:b.agentId,agentRole:b.agentRole},
        taskClass:q.taskClass,policyHash:hash(policy),context:copy(b.context),prompt:q.prompt};
      need(Number.isSafeInteger(totalInput)&&totalInput>=Buffer.byteLength(JSON.stringify(payload))&&totalInput<=policy.maxInputTokens,'INPUT_TOKEN_BOUND_INVALID');
      need(q.bounds.output>0&&q.bounds.output<=policy.maxOutputTokens&&q.bounds.toolCalls<=policy.maxToolCalls,'TOKEN_OR_TOOL_LIMIT');
      need(Number.isSafeInteger(q.maxAttempts)&&q.maxAttempts>0&&q.maxAttempts<=policy.maxAttempts,'ATTEMPT_POLICY_DENIED');
      need(Number.isSafeInteger(q.deadline)&&q.deadline>ledger.now()&&q.deadline<=ledger.scope(b.scopeId).validUntil,'DEADLINE_INVALID');
      const eligible=rs.filter(r=>policy.routeIds.includes(r.id));
      const request={scopeId:b.scopeId,projectId:b.projectId,taskId:b.taskId,kind:b.agentRole,
        operationId:q.operationId,logicalRequestId:q.logicalRequestId,correlationId:q.correlationId,effectSlot:q.effectSlot,
        alias:eligible[0].alias,protocol:eligible[0].capabilities.protocol,modelPins:Object.fromEntries(eligible.map(r=>[r.id,r.modelId])),allowedRoutes:policy.routeIds,
        allowedRegions:policy.allowedRegions,allowedPrivacy:policy.allowedPrivacy,features:q.features,toolSchemas:q.toolSchemas,
        jsonSchema:q.jsonSchema,jsonExample:q.jsonExample,bounds:q.bounds,maxAttempts:q.maxAttempts,deadline:q.deadline,
        authority:ledger.authority(),payload,sdkRetries:0,runtimeRetries:0,unknownCostBoundMicros:null};
      const gateway=gateways.get(q.taskClass),prepared=gateway.prepare(request,{allowFallback:policy.allowFallback});
      need(prepared.decision==='READY_OFFLINE',prepared.code??'ROUTE_DENIED');
      need(money(prepared.d06.totalBoundMicros)<=money(policy.maxReserveMicros),'REQUEST_COST_CEILING');
      const handle=Object.freeze({}),ticket={binding:b,request,prepared,gateway,timeoutMs:policy.timeoutMs,policyHash:hash(policy)};tickets.set(handle,ticket);
      return {decision:'READY_OFFLINE',physicalDecision:'DENY',handle,plan:copy(prepared.plan),request:copy(prepared.request),
        d06:copy(prepared.d06),policyHash:hash(policy),contextHash:b.context.hash,tokenBoundBasis:'SYNTHETIC_UTF8_UPPER_BOUND'};
    }catch(e){return {decision:'DENY',physicalDecision:'DENY',code:errorCode(e)};}
  }
  function runtimeModelPin(handle) {
    const t=checked(handle),op=ledger.operation(t.request.operationId);
    need(hash(readAuthority())===hash(t.request.authority)&&hash(ledger.authority())===hash(t.request.authority),'AUTHORITY_STALE');
    need(op?.status==='SUCCEEDED'&&op.planHash===t.prepared.d06.planHash,'MODEL_EXECUTION_NOT_CONFIRMED');
    const a=op.attempts.at(-1),pin=t.prepared.plan.alternatives.find(x=>x.routeId===a?.routeId);
    need(a?.status==='SETTLED'&&pin,'MODEL_EXECUTION_NOT_CONFIRMED');
    // Exact INT04 C02 mapping, preserving all 256 hash bits. This is content binding, not SEC authority.
    return {id:pin.modelId,revision:'rev_'+pin.profileHash.slice(7),route_id:pin.routeId,route_revision:'route_'+pin.routeHash.slice(7)};
  }
  return Object.freeze({plan,
    bindTask(bindingId) {need(scopes.has(bindingId),'BINDING_UNKNOWN');return Object.freeze({plan:q=>plan(bindingId,q)});},
    async run(handle,approvalId) {
      let t;try{t=checked(handle);const result=await t.gateway.run(t.prepared.handle,approvalId,{timeoutMs:t.timeoutMs});
        return {...result,execution:executionEvidence(t,result)};
      }catch(e){return {status:'DENY',code:errorCode(e),physicalDecision:'DENY',output:null};}
    },
    evidence:handle=>executionEvidence(checked(handle)),
    cancel(handle) {const t=checked(handle);return t.gateway.cancel(t.prepared.handle);},
    runtimeModelPin,
    checkRuntimeModel(handle,pin) {try{return hash(runtimeModelPin(handle))===hash(pin);}catch{return false;}},
    usageByAgent(bindingId) {
      const b=scopes.get(bindingId);need(b,'BINDING_UNKNOWN');const grouped=new Map();
      // Projection of existing D06 state only: no counters, reserve, approval or balance in this broker.
      for(const op of Object.values(ledger.inspect().operations)) {
        const s=op.plan.request.payload?.brokerScope;
        if(op.scopeId!==b.scopeId||!s||s.projectId!==b.projectId||s.taskId!==b.taskId)continue;
        const key=hash({agentRole:s.agentRole,agentId:s.agentId,runId:s.runId});
        const row=grouped.get(key)??{agentId:s.agentId,agentRole:s.agentRole,runId:s.runId,operations:0,calls:0,spentMicros:'0',inputTokens:0,outputTokens:0,unknownCalls:0};
        row.operations++;
        for(const a of op.attempts){row.calls++;if(a.settledMicros!==null)row.spentMicros=String(money(row.spentMicros)+money(a.settledMicros));
          if(a.usage){row.inputTokens+=a.usage.uncachedInput+a.usage.cacheRead+a.usage.cacheWrite;row.outputTokens+=a.usage.output;}else if(a.status==='IN_FLIGHT')row.unknownCalls++;}
        grouped.set(key,row);
      }
      return {owner:'D06_MemoryLedger',currency:'RUB',evidence:'SYNTHETIC_LEDGER_PROJECTION',physicalDecision:'DENY',groups:[...grouped.values()].map(x=>({...x,totalCostMicros:x.unknownCalls?null:x.spentMicros}))};
    },
    owners:()=>({reservation:'D06_MemoryLedger',attempt:'D06_RouteBroker',retry:'D06_RouteBroker',authorization:'EXTERNAL_SEC_INT04_HOST',durable:'NOT_BOUND'}),
    physicalDispatch:()=>({...physical}),
    omniRoute:()=>({decision:'DENY',code:'OMNIROUTE_CONTRACT_NOT_CONFIRMED',physicalDecision:'DENY'})
  });
}
