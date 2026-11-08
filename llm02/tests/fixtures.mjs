import http from 'node:http';
import {once} from 'node:events';
import {createPostgresPersistence} from '../../awe/persistence/postgres.mjs';
import {createD09ModelBroker} from '../broker.mjs';
import {config as brokerConfig,binding,query as oldQuery} from '../../tests/model_gateway/model-broker-fixtures.mjs';
import {hash,copy} from '../common.mjs';
export const model='gpt-4.1-mini-2025-04-14';
export const flat={properties:{answer:'string'},required:['answer'],additionalProperties:false};
export const toolSchema={properties:{city:'string'},required:['city'],additionalProperties:false};
export const tick=()=>new Promise(r=>setTimeout(r,5));
export function price(){return {status:'SYNTHETIC_QUOTED',currency:'RUB',budgetCurrency:'RUB',validFrom:0,validUntil:900000,
 rates:{uncachedInput:'1000000',cacheRead:'100000',cacheWrite:'1000000',output:'2000000'},toolCallMicros:'0',
 fees:{status:'SYNTHETIC_PINNED',bps:'0',fixedMicros:'1'},fx:{status:'SYNTHETIC_PINNED',fromCurrency:'RUB',toCurrency:'RUB',numerator:'1',denominator:'1',validFrom:0,validUntil:900000}};}
export function transportConfig(endpoint,patch={}){return {version:'LLM02_TRANSPORT_V1',mode:'LOOPBACK_MOCK',provider:'OpenAI',protocol:'OPENAI_CHAT_SUBSET_V1',endpoint,modelId:model,modelRevision:'2025-04-14',routeId:'openai-direct',timeoutMs:500,maxRequestBytes:50000,maxResponseBytes:50000,maxSessionRequests:10,maxWindowRequests:10,windowMs:60000,maxConcurrent:1,price:price(),review:{evidence:'SYNTHETIC_ONLY',region:'fixture-eu',privacy:'SYNTHETIC_NO_RETENTION',qualityLowerBoundBps:9000,contextTokens:20000,outputTokens:50,validUntil:900000},...patch};}
export const query=(id='one',patch={})=>oldQuery(id,{deadline:700000,...patch});
export function reply(patch={}){return {id:'chatcmpl-fixture',object:'chat.completion',created:1793966400,model,service_tier:'default',choices:[{index:0,message:{role:'assistant',content:'Ответ ✓',refusal:null,annotations:[]},logprobs:null,finish_reason:'stop'}],usage:{prompt_tokens:40,completion_tokens:10,total_tokens:50,prompt_tokens_details:{cached_tokens:0,audio_tokens:0},completion_tokens_details:{reasoning_tokens:3,audio_tokens:0,accepted_prediction_tokens:0,rejected_prediction_tokens:0}},...patch};}
export function toolReply(){return reply({choices:[{index:0,message:{role:'assistant',content:null,refusal:null,tool_calls:[{id:'call-city',type:'function',function:{name:'weather',arguments:'{"city":"Москва"}'}}]},finish_reason:'tool_calls'}]});}
export async function mockServer(script=[]) {
 const calls=[],sockets=new Set();let index=0;
 const server=http.createServer(async(req,res)=>{
  const chunks=[];for await(const c of req)chunks.push(c);
  const bytes=Buffer.concat(chunks),body=JSON.parse(bytes.toString('utf8'));
  calls.push({method:req.method,path:req.url,headers:copy(req.headers),bytes:bytes.toString('utf8'),body});
  const step=script[index++]??{};
  if(step.wait)await new Promise(r=>setTimeout(r,step.wait));
  if(step.drop){req.socket.destroy();return;}
  res.statusCode=step.status??200;
  res.setHeader('Content-Type',step.type??'application/json; charset=utf-8');
  if(step.requestId!==null)res.setHeader('x-request-id',step.requestId??'req-fixture-'+index);
  if(step.redirect)res.setHeader('Location',step.redirect);
  if(step.encoding)res.setHeader('Content-Encoding',step.encoding);
  const text=step.raw??JSON.stringify(step.reply??reply());
  if(step.truncate){res.setHeader('Content-Length',Buffer.byteLength(text)+100);res.flushHeaders();res.write(text.slice(0,10));setTimeout(()=>res.destroy(),10);return;}
  if(step.bytes){res.end(step.bytes);return;}
  if(step.split){const b=Buffer.from(text),at=b.indexOf(Buffer.from('✓'))+1;res.write(b.subarray(0,at));setTimeout(()=>res.end(b.subarray(at)),5);}
  else res.end(text);
 });
 server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});
 server.listen(0,'127.0.0.1');await once(server,'listening');
 return {calls,endpoint:'http://127.0.0.1:'+server.address().port+'/v1/chat/completions',close:async()=>{for(const s of sockets)s.destroy();await new Promise(r=>server.close(r));}};
}
// Scripted pg-compatible pool behind the UNMODIFIED real D09 JS adapter.
// These fixtures exercise command/ACK contracts, not PostgreSQL isolation, SQL, RLS or durability.
export function d09Fixture({cap='100000'}={}) {
 const rows=new Map(),calls=[],sql=[],approvals=new Map(),controls={ackLoss:null,delay:null,badReadback:null,deny:null};let reserved=0n,spent=0n;
 function view(row){return {...copy(row),physical_decision:'DENY',dispatch_authorized:false};}
 const port=createPostgresPersistence({connect:async()=>({query:async(text,values)=>{
  sql.push(text);
  if(text==='COMMIT'&&controls.ackLoss&&calls.at(-1)?.method===controls.ackLoss){controls.ackLoss=null;throw Error('PRIVATE COMMIT ACK lost sk-not-a-real-key');}
  const method=text.match(/^SELECT awe_d09\.([a-z_]+)\(/)?.[1];if(!method)return {rows:[]};
  const cmd=JSON.parse(values[0]);calls.push({method,command:cmd});
  if(controls.delay?.method===method)await new Promise(r=>setTimeout(r,controls.delay.ms));
  if(controls.deny===method)throw Error('private SQL/host detail');
  const key=cmd.project_id+':'+cmd.attempt_id;let row=rows.get(key);
  if(method==='admit') {
   if(row){if(hash(row.request)!==hash(cmd))throw Error('IDEMPOTENCY_CONFLICT');}
   else {
    const ap=approvals.get(cmd.approval_id);if(!ap||ap.plan_hash!==cmd.plan_hash||ap.payload_hash!==cmd.payload_hash||ap.reserve_micros!==cmd.reserve_micros||ap.project_id!==cmd.project_id)throw Error('APPROVAL_MISMATCH');
    if(reserved+spent+BigInt(cmd.reserve_micros)>BigInt(cap))throw Error('BUDGET_DENIED');
    if([...rows.values()].some(r=>r.project_id===cmd.project_id&&(r.operation_id===cmd.operation_id||r.request.effect_slot===cmd.effect_slot)))throw Error('EFFECT_CONFLICT');
    row={project_id:cmd.project_id,attempt_id:cmd.attempt_id,operation_id:cmd.operation_id,request:cmd,reserve_micros:cmd.reserve_micros,actual_micros:null,accounting_status:'RESERVED',status:'ADMITTED',delivery_fence:'0'};rows.set(key,row);reserved+=BigInt(cmd.reserve_micros);
   }
  } else {
   if(!row)throw Error('MISSING');
   if(method==='claim_attempt'){if(row.status!=='ADMITTED')throw Error('LEASE_DENIED');row.delivery_fence=String(BigInt(row.delivery_fence)+1n);}
   if(method==='mark_sent'){if(row.status!=='ADMITTED'||String(cmd.fence)!==row.delivery_fence)throw Error('SEND_DENIED');row.status='SENT';}
   if(method==='cancel_attempt'){
    if(row.status==='ADMITTED'){row.status='NOT_SENT';row.accounting_status='RELEASED';reserved-=BigInt(row.reserve_micros);}
    if(row.status==='SENT')row.status='OUTCOME_UNKNOWN';
   }
   if(method==='record_result'){if(!['SENT','SETTLED','OUTCOME_UNKNOWN'].includes(row.status))throw Error('RESULT_DENIED');row.result=cmd.result;row.evidence_hash=cmd.evidence_hash;}
   if(method==='reconcile_charge'){if(!['SENT','OUTCOME_UNKNOWN'].includes(row.status))throw Error('SETTLEMENT_DENIED');row.actual_micros=cmd.actual_micros;row.accounting_status='SETTLED';if(row.status==='SENT')row.status='SETTLED';reserved-=BigInt(row.reserve_micros);spent+=BigInt(cmd.actual_micros);}
  }
  return {rows:[{result:controls.badReadback?{...view(row),...controls.badReadback}:view(row)}]};
 },release(){}})});
 return {port,calls,sql,rows,controls,approve(p,approvalId='approval-'+p.d09.attempt_id){approvals.set(approvalId,{...copy(p.d09),project_id:p.plan.binding.projectId});return approvalId;},
  balances:()=>({reserved:String(reserved),spent:String(spent)}),
  async settle(p,actual='50'){return port.reconcile({project_id:p.plan.binding.projectId,attempt_id:p.d09.attempt_id,provider:'OpenAI',invoice_id:'fixture-invoice-'+p.d09.attempt_id,actual_micros:actual,input_tokens:40,output_tokens:10,evidence_hash:hash({fixtureInvoice:p.planHash})});}
 };
}
export async function fixture(options={}) {
 const server=await mockServer(options.script),d09=options.d09??d09Fixture(options.budget);
 let auth={epoch:1,policyVersion:'fixture-v1'},clock=1000;
 const tc=transportConfig(server.endpoint,options.transport),cfg=brokerConfig({routeIds:['openai-direct'],maxAttempts:1,allowFallback:false,timeoutMs:500,...options.policy});
 const args={persistence:d09.port,transportConfig:tc,config:cfg,bindings:options.bindings??[binding(),binding('child')],readScope:()=>({projectId:'project',taskId:'task',validUntil:800000}),readAuthority:()=>auth,now:()=>clock};
 try {const broker=createD09ModelBroker(args);return {server,d09,broker,args,close:server.close,revoke:()=>auth={...auth,epoch:2},advance:n=>clock+=n};}catch(e){await server.close();throw e;}
}
export const approve=(f,p)=>{if(p.decision!=='READY_OFFLINE')throw Error(JSON.stringify(p));return f.d09.approve(p);};
