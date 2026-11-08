import {RouteBroker} from '../providers/route-broker.mjs';
import {copy,hash,rankRoutes,OWNER} from './profiles.mjs';
import {requireThat as need,money,integer} from '../budget/money.mjs';

// Trusted composition root. No URL, credential, arbitrary transport, SDK, automatic loop or secondary reservation.
export function createModelGateway({ledger,routes,profiles,adapters,readAuthority}) {
  const reviewedRoutes=copy(routes),reviewedProfiles=copy(profiles),tickets=new WeakMap();
  need(typeof readAuthority==='function','AUTHORITY_PORT_REQUIRED');
  const broker=new RouteBroker({ledger,routes:reviewedRoutes,adapters});
  function barrier(authority) {
    const current=readAuthority();need(current && !current.then && hash(current)===hash(authority)
      && hash(ledger.authority())===hash(authority),'AUTHORITY_STALE');
  }
  return Object.freeze({
    prepare(input, {allowFallback=false}={}) {
      try {
        const request=copy(input);barrier(request.authority);
        const scope=ledger.scope(request.scopeId);
        need(scope.projectId===request.projectId && scope.taskId===request.taskId,'TENANT_TASK_MISMATCH');
        need(request.sdkRetries===0 && request.runtimeRetries===0,'RETRY_OWNER_CONFLICT');
        need(request.unknownCostBoundMicros===null,'UNKNOWN_COST_DISABLED');
        need(typeof allowFallback==='boolean','FALLBACK_POLICY_INVALID');
        const ranked=rankRoutes({profiles:reviewedProfiles,routes:reviewedRoutes,request,now:ledger.now()});
        const choices=allowFallback?ranked.accepted:ranked.accepted.slice(0,1);
        const {p,r,boundMicros}=choices[0],rejected=ranked.rejected;
        const pinned={...request,allowedRoutes:choices.map(x=>x.r.id),modelPins:Object.fromEntries(choices.map(x=>[x.r.id,x.p.modelId]))};
        const prepared=broker.prepare(pinned);need(prepared.decision==='ALLOW_SIMULATION_ONLY',prepared.code??'D06_DENIED');
        need(prepared.plan.routes.length===choices.length,'CANDIDATE_POLICY_DENIED');
        const quote={version:'LLM01_QUOTE_V1',currency:'RUB',boundMicros,totalBoundMicros:prepared.totalBoundMicros,
          validUntil:Math.min(...choices.map(x=>x.p.validUntil),...prepared.plan.routes.map(x=>x.validUntil)),profileHash:hash(p),routeHash:hash(r),
          policyHash:p.policyHash,source:p.source,priceHash:hash(r.price)};
        const plan={version:'LLM01_ATTEMPT_V1',owner:OWNER,reservationOwner:'D06_MemoryLedger',storageMode:'D06_MEMORY_ONLY',
          operationId:pinned.operationId,logicalRequestId:pinned.logicalRequestId,correlationId:pinned.correlationId,
          projectId:pinned.projectId,taskId:pinned.taskId,modelId:p.modelId,profileId:p.id,quote,
          d06PlanHash:prepared.planHash,payloadHash:hash(pinned.payload),authorityHash:hash(pinned.authority),
          maxAttempts:pinned.maxAttempts,physicalDecision:'DENY',rejected,allowFallback,
          alternatives:choices.filter(x=>prepared.plan.routes.some(y=>y.id===x.r.id)).map(x=>({routeId:x.r.id,modelId:x.p.modelId,profileHash:hash(x.p),policyHash:x.p.policyHash,routeHash:hash(x.r)}))};
        const handle=Object.freeze({});tickets.set(handle,{request:pinned,prepared,plan:copy(plan),holdCode:null});
        return {decision:'READY_OFFLINE',physicalDecision:'DENY',handle,plan:copy(plan),request:copy(pinned),d06:copy(prepared)};
      } catch(e) {return {decision:'DENY',physicalDecision:'DENY',code:e.code??'INVALID_REQUEST'};}
    },
    async run(handle,approvalId,{timeoutMs=null}={}) {
      const t=tickets.get(handle);
      try {
        need(t,'HOST_HANDLE_REQUIRED');
        if(t.holdCode)return {status:'OUTCOME_UNKNOWN',code:t.holdCode,physicalDecision:'DENY',output:null,retainedLiability:true,reconciliationRequired:true};
        if(t.cancelled)return {status:'CANCELLED',physicalDecision:'DENY',output:null};
        barrier(t.request.authority);
        need(ledger.now()<t.plan.quote.validUntil,'QUOTE_STALE');
        if(timeoutMs!==null){integer(timeoutMs,1000);need(timeoutMs>0,'TIMEOUT_POLICY_INVALID');}
        let timer;
        const pending=broker.execute(t.request,approvalId);
        const timeout=timeoutMs===null?null:new Promise(resolve=>{timer=setTimeout(()=>{
          t.holdCode='MODEL_TIMEOUT';
          try{ledger.quarantine(t.request.operationId,'MODEL_TIMEOUT');}catch{ /* D06 retains liability; local hold never grants a recovery right. */ }
          resolve({status:'OUTCOME_UNKNOWN',code:'MODEL_TIMEOUT',physicalDecision:'DENY',retainedLiability:true,reconciliationRequired:true});
        },timeoutMs);});
        let result;try{result=await(timeout?Promise.race([pending,timeout]):pending);}finally{clearTimeout(timer);}
        const actual=t.plan.alternatives.find(x=>x.routeId===result.routeId)??t.plan.alternatives[0];
        let released=result.status==='SUCCEEDED';
        try{barrier(t.request.authority);}catch{released=false;}
        const {output,...metadata}=result;
        const receipt={version:'LLM01_USAGE_V1',operationId:t.plan.operationId,modelId:actual.modelId,routeId:actual.routeId,
          attemptId:result.attemptId??null,planHash:t.plan.d06PlanHash,profileHash:actual.profileHash,policyHash:actual.policyHash,
          payloadHash:t.plan.payloadHash,usage:result.usage??null,costMicros:result.costMicros??null,
          currency:'RUB',evidence:'SYNTHETIC',accepted:false,physicalDecision:'DENY'};
        return {...metadata,output:released?output??null:null,outputReleased:released,receipt,
          ...(result.status==='SUCCEEDED'&&!released?{status:'DENY',code:'POST_REPLY_AUTHORITY_STALE'}:{})};
      } catch(e) {return {status:'DENY',code:e.code??'GATEWAY_DENIED',physicalDecision:'DENY',output:null};}
    },
    cancel(handle) {
      const t=tickets.get(handle);need(t,'HOST_HANDLE_REQUIRED');barrier(t.request.authority);
      if(!ledger.operation(t.request.operationId)){t.cancelled=true;return {status:'CANCELLED',physicalDecision:'DENY',preAdmission:true};}
      return {...ledger.cancel(t.request.operationId),physicalDecision:'DENY'};
    },
    // Hermes may resubmit only this same opaque handle. D06 decides replay/retry time/attempt/circuit/unknown.
    physicalDispatch:()=>({decision:'DENY',code:'E0_PHYSICAL_EGRESS_DISABLED'}),
    owners:()=>({reservation:'D06_MemoryLedger',attempt:OWNER,retry:OWNER,durable:'NOT_BOUND',hermesRetries:0})
  });
}

// Alternative composition, NEVER a mirror of a D06 reservation. No call to D06 in this port.
// D09 current contract is one attempt/effect; no retry or automatic failover method exists.
export function createDurableAdmission({persistence,projectId,taskId}) {
  need(persistence && typeof persistence.admit==='function','D09_PORT_REQUIRED');
  const allowed=['operation_id','attempt_id','effect_slot','approval_id','grant_id','idempotency_key','plan_hash','payload_hash','reserve_micros'];
  return Object.freeze({
    async admit(command) {
      const c=copy(command);need(Object.keys(c).sort().join()===allowed.slice().sort().join(),'D09_COMMAND_FIELDS');
      money(c.reserve_micros);need(money(c.reserve_micros)>0n,'POSITIVE_RESERVE_REQUIRED');
      // Existing D09 validates issuer/session identity, hash bindings, epochs, leases, ceilings, and schema.
      return persistence.admit({...c,project_id:projectId,task_id:taskId});
    },
    physicalDispatch:()=>({decision:'DENY',code:'D09_NATIVE_D06_BINDING_NOT_ACCEPTED'}),
    owners:()=>({reservation:'D09_PostgreSQL',attempt:'D09_PostgreSQL',retry:'DISABLED_SINGLE_ATTEMPT',d06:'NOT_BOUND'})
  });
}
