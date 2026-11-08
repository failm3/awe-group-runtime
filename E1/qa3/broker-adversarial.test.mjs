import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../contracts/index.mjs';
import {createMaintenanceMission} from '../broker/index.mjs';
import {createCloudModelBroker,createOfflineCloudModelBrokerForTests} from '../cloud/broker.mjs';
import {NOW,clone,catalog} from './fixtures.mjs';

let serial=0;
function ack(){return {id:'qa3-provider-request',model:'qa3/synthetic-model',source_id:'qa3-source-a',usage:{prompt_tokens:3,completion_tokens:2,prompt_tokens_details:{cached_tokens:1}},actual_charge:{currency:'USD',amount_micros:'4',evidence_label:'PROVIDER_AUTHENTICATED_BILLING',evidence_digest:digest({synthetic:'qa3-charge'})},choices:[{finish_reason:'stop',message:{content:JSON.stringify({text:'Synthetic bounded review.'})}}]};}
const json=value=>new Response(JSON.stringify(value),{headers:{'content-type':'application/json'}});
function setup(options={}){
 const base=createMaintenanceMission({now:NOW,suffix:'qa3_'+String(++serial).padStart(5,'0')}),registry=clone(base.registry),spec=clone(base.spec),grant=clone(base.grant),cat=catalog();
 for(const e of registry.entries)if(e.descriptor.executor_kind==='llm')e.cloud_routes=[{route_id:cat.routes[0].route_id,route_version:'1.0.0'}];
 spec.budget={currency:'USD',amount_micros:'1000000'};grant.budget_cap=clone(spec.budget);grant.spec_digest=digest(spec);
 const state={now:NOW},events=[],wires=[],bounds=[];
 const policy={schema:'awe.e1.router-cheap.host-policy/1',budget_group_id:'router.cheap.shared/1',key_binding_id:'synthetic_qa3_key',project_id:spec.project_id,mission_id:spec.mission_id,spec_digest:digest(spec),mission_grant_digest:digest(grant),catalog_digest:digest(cat),allowed_route_ids:[cat.routes[0].route_id],issued_at:NOW,expires_at:grant.expires_at,total_cap_micros:'1000000',per_attempt_cap_micros:'1000',max_attempts:15,hard_cap:{kind:'OFFLINE_TEST_DOUBLE',evidence_digest:digest({synthetic:'qa3-cap'}),observed_at:NOW,expires_at:grant.expires_at,cap_micros:'1000000'}};
 const methods=['reserve','markSending','settle','unknown','failBeforeSend'];
 const accounting=Object.fromEntries(methods.map(method=>[method,async request=>{events.push({method,request:clone(request)});return options[method]?options[method](request,{state,registry,policy,cat}):{status:{reserve:'RESERVED',markSending:'SENDING',settle:'CONFIRMED',unknown:'OUTCOME_UNKNOWN',failBeforeSend:'FAILED'}[method]};}]));
 const send=async request=>{wires.push(request);return options.transport?options.transport(request):json(options.ack??ack());};
 const verify=async request=>{bounds.push(request);return options.bound?options.bound(request):true;};
 const factory=()=>createOfflineCloudModelBrokerForTests({accounting,registry,catalog:()=>cat,policy:()=>policy,clock:()=>state.now,timeoutMs:options.timeoutMs??1000},{transport:send,inputTokenBound:verify,label:'OFFLINE_TEST_DOUBLE'});
 const request={scope:{mission_id:spec.mission_id,task_id:'head_control',logical_request_id:'qa3-logical',attempt_id:'qa3-attempt',worker_id:'e1_worker',fence:1},spec,grant,capability_id:'e1.code.review',input:{instruction:'Review the supplied synthetic numeric ordering requirement.'},data_label:'SYNTHETIC',route_id:cat.routes[0].route_id,max_input_tokens:100,max_output_tokens:100};
 return {base,registry,spec,grant,cat,state,policy,events,wires,bounds,accounting,send,verify,factory,broker:factory(),request};
}
const order=s=>s.events.map(x=>x.method);
const assertHeld=(s,r,wire=1)=>{assert.equal(r.decision,'HOLD');assert.equal(r.accounting_status,'UNKNOWN');assert.equal(r.accepted,false);assert.equal(r.effects,0);assert.equal(r.wire_attempts,wire);assert.equal(s.wires.length,wire);assert.equal(order(s).at(-1),'unknown');assert.equal(s.events.filter(x=>x.method==='settle').length,0);};

test('QA3 public cloud factory rejects raw transports, fake tokens and activation configuration',()=>{
 const s=setup();for(const extra of [{transport:s.send,policy:s.policy},{transport:{send:s.send,verifyInputBound:s.verify},policy:s.policy},{transport:{},policy:{},enabled:true},{fetchImpl:s.send}])assert.throws(()=>createCloudModelBroker({accounting:s.accounting,registry:s.registry,...extra}));
 assert.throws(()=>createOfflineCloudModelBrokerForTests({accounting:s.accounting,registry:s.registry},{transport:s.send,inputTokenBound:s.verify,label:'LIVE'}));
});
test('QA3 one bounded mock POST has exact model and schema and is bracketed by durable accounting',async()=>{
 const s=setup(),r=await s.broker.invoke(s.request);assert.equal(r.decision,'PROPOSED');assert.equal(r.evidence_level,'OFFLINE_TEST_DOUBLE');assert.equal(r.accepted,false);assert.equal(r.effects,0);
 assert.deepEqual(order(s),['reserve','markSending','settle']);assert.equal(s.wires.length,1);assert.equal(s.wires[0].url,'https://router.cheap/v1/chat/completions');assert.equal(s.wires[0].method,'POST');assert.equal(s.wires[0].redirect,'error');
 const body=s.wires[0].body;assert.equal(body.model,'qa3/synthetic-model');assert.equal(body.stream,false);assert.equal(body.response_format.json_schema.strict,true);assert.equal(body.tools,undefined);
 assert.deepEqual(s.bounds[0].body,body);assert.equal(r.usage.actual_charge_micros,'4');assert.equal(r.usage.cached_input_tokens,1);assert.equal(s.events[0].request.reserve_micros,150);assert.equal(s.events[2].request.actual_cost_micros,4);
});
test('QA3 privacy labels, credential-like text and protected input additions block before any accounting or wire',async()=>{
 for(const patch of [{data_label:'PERSONAL'},{input:{instruction:'Contact synthetic@example.invalid'}},{input:{instruction:'api_key = QA3_SYNTHETIC_CREDENTIAL'}},{input:{instruction:'Review synthetic code',grant:{budget_cap:999999}}}]){const s=setup(),r=await s.broker.invoke({...s.request,...patch});assert.equal(r.decision,'BLOCK');assert.equal(s.events.length,0);assert.equal(s.wires.length,0);}
});
test('QA3 full serialized request requires host input-token bound before reserving',async()=>{
 const s=setup({bound:request=>{assert.equal(request.body.response_format.json_schema.schema.type,'object');assert.equal(request.body.messages[0].content,s.request.input.instruction);return false;}}),r=await s.broker.invoke(s.request);
 assert.equal(r.reason,'CLOUD_INPUT_BOUND_UNKNOWN');assert.equal(s.bounds.length,1);assert.equal(s.events.length,0);assert.equal(s.wires.length,0);
});
test('QA3 registry revocation and expired policy after reserve release only proven no-send',async()=>{
 for(const kind of ['route','clock','cap']){
  const s=setup({reserve:(request,{registry,state,policy})=>{if(kind==='route')registry.entries.find(x=>x.descriptor.ref.capability_id==='e1.code.review').installed=false;else if(kind==='clock')state.now='2026-11-08T13:00:00.000Z';else policy.hard_cap.kind='UNKNOWN';return {status:'RESERVED'};}}),r=await s.broker.invoke(s.request);
  assert.equal(r.decision,'BLOCK');assert.equal(r.reservation_released,true);assert.equal(r.accounting_status,'FAILED');assert.equal(s.wires.length,0);assert.deepEqual(order(s),['reserve','failBeforeSend']);
 }
});
test('QA3 revocation after durable SENDING retains reserve with UNKNOWN and zero provider wire',async()=>{
 const s=setup({markSending:(request,{policy})=>{policy.allowed_route_ids=[];return {status:'SENDING'};}}),r=await s.broker.invoke(s.request);assertHeld(s,r,0);assert.deepEqual(order(s),['reserve','markSending','unknown']);
});
test('QA3 uncertain reservation or SENDING acknowledgement never blindly dispatches',async()=>{
 for(const method of ['reserve','markSending']){const s=setup({[method]:()=>{throw Object.assign(new Error('QA3_SYNTHETIC_INTERNAL_ERROR'),{code:'A2_DB_TRANSPORT_UNKNOWN'});}}),r=await s.broker.invoke(s.request);assertHeld(s,r,0);assert.equal(s.events.some(x=>x.method==='failBeforeSend'),false);assert.equal(JSON.stringify(r).includes('QA3_SYNTHETIC_INTERNAL_ERROR'),false);}
});
test('QA3 lost wire ACK and timeout have exactly one possible send and sanitized HOLD',async()=>{
 for(const timeout of [false,true]){
  const s=setup({timeoutMs:10,transport:()=>timeout?new Promise(()=>{}):Promise.reject(Object.assign(new Error('QA3_SENSITIVE_PROVIDER_ERROR'),{code:'QA3_SENSITIVE_PROVIDER_ERROR'}))}),r=await s.broker.invoke(s.request);assertHeld(s,r);assert.deepEqual(order(s),['reserve','markSending','unknown']);assert.equal(JSON.stringify(r).includes('QA3_SENSITIVE_PROVIDER_ERROR'),false);
 }
});
test('QA3 redirected, wrong-origin, non-JSON and oversized responses stay UNKNOWN',async()=>{
 const responses=[()=>Object.assign({ok:true,status:200,redirected:true,url:'https://router.cheap/v1/chat/completions'}),()=>({ok:true,status:200,redirected:false,url:'https://attacker.invalid/v1/chat/completions'}),()=>new Response('{}',{headers:{'content-type':'text/plain'}}),()=>new Response('x'.repeat(131073),{headers:{'content-type':'application/json'}}),()=>new Response('{invalid',{headers:{'content-type':'application/json'}})];
 for(const response of responses){const s=setup({transport:response}),r=await s.broker.invoke(s.request);assertHeld(s,r);}
});
test('QA3 missing usage, cache counts, exact source, model or charge evidence cannot invent a settlement',async()=>{
 const mutations=[x=>delete x.usage,x=>delete x.usage.prompt_tokens_details,x=>x.usage.prompt_tokens_details.cached_tokens=4,x=>x.usage.prompt_tokens=101,x=>x.usage.completion_tokens=101,x=>x.model='another-model',x=>x.source_id='unknown-source',x=>x.id='unsafe request id',x=>delete x.actual_charge,x=>delete x.actual_charge.evidence_digest,x=>x.actual_charge.evidence_label='ESTIMATED',x=>x.actual_charge.amount_micros='3',x=>x.actual_charge.amount_micros='0',x=>x.actual_charge.currency='RUB'];
 for(const mutate of mutations){const value=ack();mutate(value);const s=setup({ack:value}),r=await s.broker.invoke(s.request);assertHeld(s,r);}
});
test('QA3 known billed malformed, injected or truncated output settles once then requests repair',async()=>{
 for(const mutate of [x=>x.choices[0].message.content='{bad',x=>x.choices[0].message.content=JSON.stringify({text:'Synthetic output',accepted:true,tools:[{name:'shell'}]}),x=>x.choices[0].finish_reason='length',x=>x.choices[0].finish_reason='tool_calls',x=>x.choices.push(clone(x.choices[0]))]){
  const value=ack();mutate(value);const s=setup({ack:value}),r=await s.broker.invoke(s.request);assert.equal(r.decision,'REPAIR');assert.equal(r.accounting_status,'CONFIRMED');assert.equal(r.wire_attempts,1);assert.equal(r.output,undefined);assert.equal(r.accepted,false);assert.deepEqual(order(s),['reserve','markSending','settle']);assert.equal(s.wires.length,1);
 }
});
test('QA3 lost settlement ACK becomes UNKNOWN with one charge record and no second POST',async()=>{
 const s=setup({settle:()=>{throw new Error('QA3_SETTLE_ACK_LOST');}}),r=await s.broker.invoke(s.request);assertHeld({...s,events:s.events.filter(x=>x.method!=='settle')},r);assert.deepEqual(order(s),['reserve','markSending','settle','unknown']);assert.equal(r.usage.actual_charge_micros,'4');
});
test('QA3 same logical request cannot send twice through new attempt or another broker instance',async()=>{
 const s=setup(),first=await s.broker.invoke(s.request),next={...s.request,scope:{...s.request.scope,attempt_id:'qa3-new-attempt'}};
 assert.equal(first.decision,'PROPOSED');const second=await s.factory().invoke(next);assert.equal(second.decision,'BLOCK');assert.equal(second.reason,'CLOUD_ATTEMPT_REUSED');assert.equal(s.wires.length,1);assert.equal(s.events.filter(x=>x.method==='reserve').length,1);
});
test('QA3 simultaneous same logical request dispatches at most once',async()=>{
 let release,entered;const gate=new Promise(resolve=>release=resolve),reserved=new Promise(resolve=>entered=resolve);
 const s=setup({reserve:async()=>{entered();await gate;return {status:'RESERVED'};}});
 const first=s.broker.invoke(s.request);await reserved;const second=await s.factory().invoke({...s.request,scope:{...s.request.scope,attempt_id:'qa3-other-attempt'}});release();const completed=await first;
 assert.equal(second.reason,'CLOUD_ATTEMPT_REUSED');assert.equal(completed.decision,'PROPOSED');assert.equal(s.wires.length,1);assert.equal(s.events.filter(x=>x.method==='reserve').length,1);
});
