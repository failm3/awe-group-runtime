import test from 'node:test';
import assert from 'node:assert/strict';
import {world,request,route,success,notSent,assertCaps} from '../budget/fixtures.mjs';
import {createModelGateway,createDurableAdmission} from '../../awe/model_gateway/gateway.mjs';
import {syntheticProfile,validateProfile,hash} from '../../awe/model_gateway/profiles.mjs';
import {createPostgresPersistence} from '../../awe/persistence/postgres.mjs';
function fixture(options={}) {
  const w=world(options);let authority=w.ledger.authority();
  const profiles=options.profiles??w.routes.map(r=>syntheticProfile(r));
  const gateway=createModelGateway({...w,profiles,readAuthority:()=>authority});
  return {...w,gateway,profiles,revoke:()=>authority={...authority,epoch:99}};
}
function approved(f,input=request()) {
  const p=f.gateway.prepare(input);assert.equal(p.decision,'READY_OFFLINE',JSON.stringify(p));
  const id='approval-'+input.operationId;
  f.ledger.approve({id,operationId:input.operationId,logicalRequestId:input.logicalRequestId,correlationId:input.correlationId,
    scopeId:input.scopeId,effectSlot:input.effectSlot,planHash:p.d06.planHash,authority:input.authority,
    maxMicros:p.d06.totalBoundMicros,maxAttempts:input.maxAttempts,expiresAt:7000,allowUnknownCost:false});
  return {...p,id};
}
test('D06 success has exactly one owner, synthetic receipt, unchanged accepted=false',async()=>{
  const f=fixture(),p=approved(f),r=await f.gateway.run(p.handle,p.id);
  assert.equal(r.status,'SUCCEEDED');assert.equal(r.outputReleased,true);assert.equal(r.receipt.accepted,false);
  assert.equal(r.receipt.costMicros,'8');assert.equal(f.controls.r1.calls().length,1);assertCaps(f);
  assert.deepEqual(f.gateway.owners(),{reservation:'D06_MemoryLedger',attempt:'D06_RouteBroker',retry:'D06_RouteBroker',durable:'NOT_BOUND',hermesRetries:0});
});
test('same handle replay and concurrent duplicate do not create a second attempt',async()=>{
  const f=fixture(),p=approved(f);await Promise.all([f.gateway.run(p.handle,p.id),f.gateway.run(p.handle,p.id)]);
  await f.gateway.run(p.handle,p.id);assert.equal(f.controls.r1.calls().length,1);assert.equal(f.ledger.operation('op-one').attempts.length,1);assertCaps(f);
});
test('unknown result retains liability and never tries a second candidate',async()=>{
  const f=fixture({routes:[route(),route('r2','OpenRouter')],scripts:[[{status:'TIMEOUT'}],[success()]]});
  const p=approved(f,request('one',{allowedRoutes:['r1','r2']}));
  assert.equal((await f.gateway.run(p.handle,p.id)).status,'OUTCOME_UNKNOWN');
  assert.equal((await f.gateway.run(p.handle,p.id)).status,'OUTCOME_UNKNOWN');
  assert.equal(f.controls.r1.calls().length,1);assert.equal(f.controls.r2.calls().length,0);assertCaps(f);
});
test('proven not-sent retry remains D06 owned, backoff cannot be bypassed',async()=>{
  const f=fixture({scripts:[[notSent(),success()]]}),p=approved(f);
  assert.equal((await f.gateway.run(p.handle,p.id)).status,'RETRYABLE');
  const early=await f.gateway.run(p.handle,p.id);assert.equal(early.status,'DENY');assert.equal(f.controls.r1.calls().length,1);
  f.ledger.advanceClock(1100);assert.equal((await f.gateway.run(p.handle,p.id)).status,'SUCCEEDED');assert.equal(f.controls.r1.calls().length,2);assertCaps(f);
});
for(const status of ['AUTH_ERROR','REGION_ERROR','INVALID_REQUEST','CONTEXT_ERROR'])test(status+' never auto retries',async()=>{
  const f=fixture({scripts:[[notSent(status),success()]]}),p=approved(f);await f.gateway.run(p.handle,p.id);await f.gateway.run(p.handle,p.id);
  assert.equal(f.controls.r1.calls().length,1);assertCaps(f);
});
for(const [field,value] of [['sdkRetries',1],['runtimeRetries',1],['unknownCostBoundMicros','100'],['projectId','foreign'],['modelPins',{r1:'substitute'}],['protocol','OPENAI_CHAT']])test('request denies '+field,()=>{
  const f=fixture(),p=f.gateway.prepare(request('one',{[field]:value}));assert.equal(p.decision,'DENY');assert.equal(f.controls.r1.calls().length,0);
});
for(const [field,value] of [['mode','LIVE'],['evidence','DOCUMENTATION'],['retryOwner','Hermes'],['sdkRetries',1],['schemaDialect','ANY_JSON_SCHEMA'],['policyHash','bad'],['eligible',false]])test('profile denies '+field,()=>{
  const p=syntheticProfile(route());assert.throws(()=>validateProfile({...p,[field]:value}));
});
test('stronger measured fixture quality outranks lower accepted cost',()=>{
  const routes=[route(),route('r2','OpenRouter')],profiles=routes.map((r,i)=>syntheticProfile(r,{quality:{lowerBoundBps:8000+i*1000,reliabilityBps:9900,acceptedCostMicros:i?'900':'1'}}));
  const f=fixture({routes,profiles}),p=f.gateway.prepare(request('one',{allowedRoutes:['r1','r2']}));
  assert.equal(p.plan.profileId,'profile-r2');assert.deepEqual(p.request.allowedRoutes,['r2']);
});
test('unqualified highest-ranked candidate fails closed instead of hiding privacy denial',()=>{
  const r=route();r.privacyStatus='UNKNOWN';const f=fixture({routes:[r]});assert.equal(f.gateway.prepare(request()).decision,'DENY');
});
test('caller mutation cannot alter selected route, payload, profile or bound',async()=>{
  const f=fixture(),p=approved(f),original=p.plan.payloadHash;p.request.payload.prompt='changed';p.plan.quote.boundMicros='0';f.profiles[0].modelId='evil';
  const r=await f.gateway.run(p.handle,p.id);assert.equal(r.status,'SUCCEEDED');assert.equal(r.receipt.payloadHash,original);assert.equal(r.receipt.costMicros,'8');
});
test('forged handle is denied before any ledger mutation',async()=>{
  const f=fixture(),r=await f.gateway.run({},'fake');assert.equal(r.code,'HOST_HANDLE_REQUIRED');assert.equal(f.controls.r1.calls().length,0);
});
test('stale authority before dispatch prevents mock invocation',async()=>{
  const f=fixture(),p=approved(f);f.revoke();assert.equal((await f.gateway.run(p.handle,p.id)).code,'AUTHORITY_STALE');assert.equal(f.controls.r1.calls().length,0);
});
test('revocation while deferred model runs suppresses output but retains accounting',async()=>{
  const f=fixture({deferred:true}),p=approved(f),pending=f.gateway.run(p.handle,p.id);f.revoke();f.controls.r1.completeNext();const r=await pending;
  assert.equal(r.status,'DENY');assert.equal(r.output,null);assert.equal(r.costMicros,'8');assertCaps(f);
});
test('expired quote denies before reserve',async()=>{
  const f=fixture(),p=approved(f);f.ledger.advanceClock(8000);assert.equal((await f.gateway.run(p.handle,p.id)).code,'QUOTE_STALE');assert.equal(f.controls.r1.calls().length,0);
});
test('D09 mapping uses existing transaction adapter and binds tenant outside command',async()=>{
  const calls=[];const pool={async connect(){return {async query(sql,args){calls.push({sql,args});return {rows:[{result:{physical_decision:'DENY',reserve_micros:'60',dispatch_authorized:false}}]};},release(){}};}};
  const p=createPostgresPersistence(pool),g=createDurableAdmission({persistence:p,projectId:'p1',taskId:'t1'}),h='sha256:'+'a'.repeat(64);
  const c={operation_id:'o1',attempt_id:'a1',effect_slot:'s1',approval_id:'ap1',grant_id:'g1',idempotency_key:'i1',plan_hash:h,payload_hash:h,reserve_micros:'60'};
  const r=await g.admit(c);assert.equal(r.physical_decision,'DENY');assert.equal(calls.filter(x=>x.sql.includes('awe_d09.admit')).length,1);
  assert.equal(JSON.parse(calls.find(x=>x.args).args[0]).project_id,'p1');assert.equal(g.physicalDispatch().decision,'DENY');
  await assert.rejects(g.admit({...c,project_id:'foreign'}));assert.equal(calls.length,6);
});
test('D09 missing COMMIT ACK remains unknown without any automatic second admission',async()=>{
  let admits=0;const p=createPostgresPersistence({async connect(){return {async query(s){if(s.includes('awe_d09.admit'))admits++;if(s==='COMMIT')throw Error('lost');return {rows:[{result:{physical_decision:'DENY'}}]};},release(){}};}});
  const g=createDurableAdmission({persistence:p,projectId:'p1',taskId:'t1'}),h='sha256:'+'a'.repeat(64);
  await assert.rejects(g.admit({operation_id:'o1',attempt_id:'a1',effect_slot:'s1',approval_id:'ap1',grant_id:'g1',idempotency_key:'i1',plan_hash:h,payload_hash:h,reserve_micros:'60'}),e=>e.outcomeUnknown===true);assert.equal(admits,1);
});
test('all public physical dispatch surfaces deny',()=>{assert.equal(fixture().gateway.physicalDispatch().decision,'DENY');});
