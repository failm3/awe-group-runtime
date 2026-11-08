import test from 'node:test';
import assert from 'node:assert/strict';
import {brokerFixture,query,binding,config,approvePlan} from './model-broker-fixtures.mjs';
import {success,notSent} from '../budget/fixtures.mjs';
import {createModelBroker} from '../../awe/model_gateway/model-broker.mjs';
import {validateBrokerConfig} from '../../awe/model_gateway/broker-config.mjs';
import {hash} from '../../awe/model_gateway/profiles.mjs';

test('task class selects quality-first provider and records actual request invocation',async()=>{
 const f=brokerFixture(),p=f.broker.plan('main',query()),a=approvePlan(f,p),r=await f.broker.run(p.handle,a);
 assert.equal(p.plan.modelId,'synthetic-pinned-v1');assert.equal(r.status,'SUCCEEDED');assert.equal(r.execution.attempts.length,1);
 const e=r.execution.attempts[0];assert.equal(e.observedCall.payloadHash,p.plan.payloadHash);assert.equal(e.evidence,'OBSERVED_D06_SEALED_MOCK_CALL');
 assert.equal(e.costMicros,'8');assert.equal(r.execution.contextHash,binding().context.hash);assert.equal(r.execution.accepted,false);
 assert.equal(r.execution.responseHash,hash(r.output));
 assert.equal(r.execution.evidenceHash,hash((({evidenceHash,...body})=>body)(r.execution)));
});
test('class allowlist can select a different provider and model',async()=>{
 const f=brokerFixture({config:config({routeIds:['r2']})}),p=f.broker.plan('main',query());
 assert.equal(p.plan.modelId,'synthetic-alternative-v2');const r=await f.broker.run(p.handle,approvePlan(f,p));assert.equal(r.routeId,'r2');
 assert.equal(r.execution.attempts[0].modelId,'synthetic-alternative-v2');
});
test('MAIN and CHILD use same task/shared owner but separate derived usage',async()=>{
 const f=brokerFixture({scripts:[[success(),success()],[success()]]});
 const main=f.broker.plan('main',query()),child=f.broker.plan('child',query('two'));
 await f.broker.run(main.handle,approvePlan(f,main));await f.broker.run(child.handle,approvePlan(f,child));
 const usage=f.broker.usageByAgent('main');assert.equal(usage.groups.length,2);assert.deepEqual(usage.groups.map(x=>[x.agentRole,x.calls,x.spentMicros]),[['MAIN',1,'8'],['CHILD',1,'8']]);
 assert.equal(f.ledger.inspect().totals.global.spentMicros,'16');assert.equal(f.ledger.inspect().totals.global.attempts,2);
 assert.equal(child.request.projectId,main.request.projectId);assert.equal(child.request.taskId,main.request.taskId);
});
test('shared call limit is enforced by existing D06 even for another agent or new broker instance',async()=>{
 const f=brokerFixture({world:{budgetPatches:{global:{attemptLimit:1}}},scripts:[[success(),success()],[success()]]});
 const p=f.broker.plan('main',query());await f.broker.run(p.handle,approvePlan(f,p));
 const other=createModelBroker(f.args),q=other.plan('child',query('two'));const id=approvePlan(f,q);
 const r=await other.run(q.handle,id);assert.equal(r.status,'DENY');assert.equal(r.code,'ANCESTOR_ATTEMPT_LIMIT');assert.equal(f.ledger.inspect().totals.global.attempts,1);
});
test('cost budget rejects admission without provider invocation',async()=>{
 const f=brokerFixture({world:{budgetPatches:{global:{capMicros:'100',balanceMicros:'100'}}}}),p=f.broker.plan('main',query()),r=await f.broker.run(p.handle,approvePlan(f,p));
 assert.equal(r.status,'DENY');assert.equal(r.code,'CAP_EXCEEDED');assert.equal(r.execution.attempts.length,0);
});
test('controlled fallback uses one reservation, same IDs, backoff, and only proven NOT_SENT',async()=>{
 const f=brokerFixture({config:config({allowFallback:true}),scripts:[[notSent()],[success()]]}),p=f.broker.plan('main',query('one',{maxAttempts:2})),a=approvePlan(f,p);
 assert.equal(p.plan.alternatives.length,2);const first=await f.broker.run(p.handle,a);assert.equal(first.status,'RETRYABLE');
 const early=await f.broker.run(p.handle,a);assert.equal(early.code,'BACKOFF_PENDING');f.ledger.advanceClock(first.retryAt);
 const result=await f.broker.run(p.handle,a);assert.equal(result.status,'SUCCEEDED');assert.equal(result.routeId,'r2');assert.equal(result.receipt.modelId,'synthetic-alternative-v2');
 assert.deepEqual(result.execution.attempts.map(x=>[x.routeId,x.status]),[['r1','NOT_SENT'],['r2','SETTLED']]);
 assert.equal(Object.keys(f.ledger.inspect().operations).length,1);assert.equal(f.ledger.inspect().approvals[a].uses,1);
});
test('fallback disabled keeps retries on the original route',async()=>{
 const f=brokerFixture({scripts:[[notSent(),success()],[success()]]}),p=f.broker.plan('main',query('one',{maxAttempts:2})),a=approvePlan(f,p);
 const r=await f.broker.run(p.handle,a);f.ledger.advanceClock(r.retryAt);const done=await f.broker.run(p.handle,a);
 assert.deepEqual(done.execution.attempts.map(x=>x.routeId),['r1','r1']);
});
for(const status of ['AUTH_ERROR','REGION_ERROR','INVALID_REQUEST','CONTEXT_ERROR'])test(status+' cannot trigger policy bypass/fallback',async()=>{
 const f=brokerFixture({config:config({allowFallback:true}),scripts:[[notSent(status)],[success()]]}),p=f.broker.plan('main',query('one',{maxAttempts:2})),a=approvePlan(f,p);
 await f.broker.run(p.handle,a);const replay=await f.broker.run(p.handle,a);assert.equal(replay.execution.attempts.length,1);assert.equal(replay.execution.attempts[0].routeId,'r1');
});
for(const status of ['TIMEOUT','PARTIAL_STREAM','LOST_RESPONSE','SPLIT_COMMIT','HTTP_429'])test(status+' stays unknown and never uses fallback/new broker',async()=>{
 const f=brokerFixture({config:config({allowFallback:true}),scripts:[[{status}],[success()]]}),p=f.broker.plan('main',query('one',{maxAttempts:2})),a=approvePlan(f,p);
 const r=await f.broker.run(p.handle,a);assert.equal(r.status,'OUTCOME_UNKNOWN');
 const again=createModelBroker(f.args),q=again.plan('main',query('one',{maxAttempts:2})),replay=await again.run(q.handle,a);
 assert.equal(replay.status,'OUTCOME_UNKNOWN');assert.equal(replay.execution.attempts.length,1);assert.equal(replay.execution.attempts[0].routeId,'r1');
 assert.equal(f.ledger.inspect().totals.global.uncertainMicros,p.d06.totalBoundMicros);
});
test('actual hanging mock is bounded by watchdog; late reply cannot release reserve or output',async()=>{
 const f=brokerFixture({deferred:true,config:config({timeoutMs:10,allowFallback:true})}),p=f.broker.plan('main',query('one',{maxAttempts:2})),a=approvePlan(f,p);
 const r=await f.broker.run(p.handle,a);assert.equal(r.code,'MODEL_TIMEOUT');assert.equal(r.status,'OUTCOME_UNKNOWN');
 f.controls.r1.completeNext();await new Promise(resolve=>setImmediate(resolve));
 assert.equal(f.ledger.operation('op-one').status,'QUARANTINED');const again=await f.broker.run(p.handle,a);assert.equal(again.status,'OUTCOME_UNKNOWN');assert.equal(again.output,null);
 const u=f.broker.usageByAgent('main').groups[0];assert.equal(u.unknownCalls,1);assert.equal(u.totalCostMicros,null);
});
for(const [name,patch] of [['input',{bounds:{uncachedInput:10,cacheRead:0,cacheWrite:0,output:20,toolCalls:0}}],['output',{bounds:{uncachedInput:2000,cacheRead:0,cacheWrite:0,output:51,toolCalls:0}}],['calls',{maxAttempts:3}],['unknown_class',{taskClass:'unapproved'}],['deadline',{deadline:0}],['project_spoof',{projectId:'foreign'}],['context_spoof',{context:{snapshot:'evil'}}]])test('request limit/scope denied '+name,()=>{
 const f=brokerFixture(),p=f.broker.bindTask('main').plan(query('one',patch));assert.equal(p.decision,'DENY');assert.equal(Object.keys(f.ledger.inspect().operations).length,0);
});
test('per-request policy cost ceiling fails before approval/reserve',()=>{const f=brokerFixture({config:config({maxReserveMicros:'1'})});assert.equal(f.broker.plan('main',query()).code,'REQUEST_COST_CEILING');});
test('CHILD denied when class only permits MAIN',()=>{const f=brokerFixture({config:config({agentRoles:['MAIN']})});assert.equal(f.broker.plan('child',query()).code,'TASK_POLICY_DENIED');});
for(const [name,b] of [['foreign project',binding('main',{projectId:'other'})],['context hash',binding('main',{context:{...binding().context,hash:hash('wrong')}})],['unbound parent',binding('child',{parentRunId:'other'})]])test('host binding denied '+name,()=>{
 assert.throws(()=>brokerFixture({bindings:name==='unbound parent'?[binding(),b]:[b]}));
});
for(const patch of [{apiKey:'synthetic-no-secret'}, {base_url:'https://example.invalid'}, {mode:'LIVE'}, {physicalDecision:'ALLOW'}])test('configuration cannot enable credentials or physical transport '+Object.keys(patch)[0],()=>{assert.throws(()=>validateBrokerConfig({...config(),...patch}));});
test('quality threshold rejects all unqualified profiles',()=>{assert.throws(()=>brokerFixture({config:config({qualityFloorBps:9999})}));});
test('duplicate concurrent calls/replay produce one observed mock invocation',async()=>{
 const f=brokerFixture(),p=f.broker.plan('main',query()),a=approvePlan(f,p);await Promise.all([f.broker.run(p.handle,a),f.broker.run(p.handle,a)]);
 const result=await f.broker.run(p.handle,a);assert.equal(result.execution.attempts.length,1);assert(result.execution.attempts[0].observedCall);
});
test('operation body collision cannot create a replacement request',async()=>{
 const f=brokerFixture(),p=f.broker.plan('main',query()),a=approvePlan(f,p);await f.broker.run(p.handle,a);
 const q=f.broker.plan('main',query('one',{prompt:'changed'}));const r=await f.broker.run(q.handle,a);assert.equal(r.status,'DENY');assert.equal(r.output,null);
});
test('bound context and policy cannot be changed through public plan copies',async()=>{
 const f=brokerFixture(),p=f.broker.plan('main',query()),a=approvePlan(f,p);p.request.payload.context.snapshot='evil';p.plan.maxAttempts=99;
 const r=await f.broker.run(p.handle,a);assert.equal(r.execution.contextHash,binding().context.hash);assert.equal(r.execution.attempts[0].observedCall.payloadHash,p.plan.payloadHash);
});
test('revocation before invocation prevents call',async()=>{
 const f=brokerFixture(),p=f.broker.plan('main',query()),a=approvePlan(f,p);f.revoke();const r=await f.broker.run(p.handle,a);assert.equal(r.status,'DENY');assert.equal(r.execution.attempts.length,0);
});
test('cancel in flight retains uncertainty and blocks fallback',async()=>{
 const f=brokerFixture({deferred:true}),p=f.broker.plan('main',query()),a=approvePlan(f,p),pending=f.broker.run(p.handle,a);
 assert.equal(f.broker.cancel(p.handle).status,'QUARANTINED');f.controls.r1.completeNext();const r=await pending;assert.equal(r.status,'OUTCOME_UNKNOWN');
});
test('all physical requests and unconfirmed OmniRoute remain denied',()=>{const f=brokerFixture();assert.equal(f.broker.physicalDispatch().decision,'DENY');assert.equal(f.broker.omniRoute().code,'OMNIROUTE_CONTRACT_NOT_CONFIRMED');assert.equal(f.broker.owners().authorization,'EXTERNAL_SEC_INT04_HOST');});
for(const [name,response] of [
 ['missing usage',success({usage:null})],['wrong model',success({modelId:'substituted'})],['wrong request',success({logicalRequestId:'foreign'})],
 ['negative tokens',success({usage:{uncachedInput:-1,cacheRead:0,cacheWrite:0,output:2,toolCalls:0}})],
 ['excessive tokens',success({usage:{uncachedInput:9000,cacheRead:0,cacheWrite:0,output:2,toolCalls:0}})],
 ['malformed output',success({output:{text:3,tools:[]}})],['unrequested tools',success({output:{text:'x',tools:[{id:'t1',name:'unapproved',arguments:{}}]}})]
])test('invalid provider reply '+name+' retains liability and forbids fallback',async()=>{
 const f=brokerFixture({config:config({allowFallback:true}),scripts:[[response],[success()]]}),p=f.broker.plan('main',query('one',{maxAttempts:2})),a=approvePlan(f,p),r=await f.broker.run(p.handle,a);
 assert.equal(r.status,'OUTCOME_UNKNOWN');assert.equal(r.output,null);assert.equal(r.execution.responseHash,null);assert.equal(r.execution.attempts.length,1);
 assert.equal(f.ledger.inspect().totals.global.uncertainMicros,p.d06.totalBoundMicros);
});
test('parallel MAIN/CHILD admissions cannot race a shared attempt ceiling',async()=>{
 const f=brokerFixture({world:{budgetPatches:{global:{attemptLimit:1}}},scripts:[[success(),success()],[success()]]});
 const p=f.broker.plan('main',query()),q=f.broker.plan('child',query('two')),a=approvePlan(f,p),b=approvePlan(f,q);
 const rows=await Promise.all([f.broker.run(p.handle,a),f.broker.run(q.handle,b)]);assert.equal(rows.filter(x=>x.status==='SUCCEEDED').length,1);
 assert.equal(f.ledger.inspect().totals.global.attempts,1);
});
test('cancelled unadmitted ticket never invokes provider',async()=>{const f=brokerFixture(),p=f.broker.plan('main',query()),a=approvePlan(f,p);assert.equal(f.broker.cancel(p.handle).preAdmission,true);const r=await f.broker.run(p.handle,a);assert.equal(r.status,'CANCELLED');assert.equal(r.execution.attempts.length,0);});
test('successful replay does not fabricate an output readback from usage alone',async()=>{const f=brokerFixture(),p=f.broker.plan('main',query()),a=approvePlan(f,p);await f.broker.run(p.handle,a);const r=await f.broker.run(p.handle,a);assert.equal(r.execution.responseHash,null);assert.equal(r.execution.resultReadback,'NO_STORED_OUTPUT_READBACK');});
test('INT04/RT01 model pin maps actual fallback route without truncating either hash',async()=>{
 const f=brokerFixture({config:config({allowFallback:true}),scripts:[[notSent()],[success()]]}),p=f.broker.plan('main',query('one',{maxAttempts:2})),a=approvePlan(f,p);
 assert.throws(()=>f.broker.runtimeModelPin(p.handle));const r=await f.broker.run(p.handle,a);f.ledger.advanceClock(r.retryAt);await f.broker.run(p.handle,a);
 const pin=f.broker.runtimeModelPin(p.handle),alt=p.plan.alternatives[1];assert.deepEqual(pin,{id:'synthetic-alternative-v2',revision:'rev_'+alt.profileHash.slice(7),route_id:'r2',route_revision:'route_'+alt.routeHash.slice(7)});
 assert(f.broker.checkRuntimeModel(p.handle,pin));assert.equal(f.broker.checkRuntimeModel(p.handle,{...pin,route_id:'r1'}),false);f.revoke();assert.equal(f.broker.checkRuntimeModel(p.handle,pin),false);
});
