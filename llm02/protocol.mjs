import {encodeChat,decodeChat} from '../awe/model_gateway/codecs.mjs';
import {validateShape} from '../awe/providers/validation.mjs';
import {copy,exact,need,integer,usage,opaqueId,bytesHash} from './common.mjs';
const name=x=>typeof x==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(x);
function flatSchema(s) {
 need(s&&s.properties&&Array.isArray(s.required),'SCHEMA_UNSUPPORTED');
 const keys=Object.keys(s.properties);
 need(keys.length<=32&&keys.every(name)&&s.required.length===keys.length&&new Set(s.required).size===keys.length&&keys.every(k=>s.required.includes(k)),'STRICT_SCHEMA_REQUIRES_ALL_PROPERTIES');
 const example=Object.fromEntries(keys.map(k=>[k,s.properties[k]==='integer'?0:s.properties[k]==='boolean'?false:'']));
 validateShape(example,s);return example;
}
function validateMessages(messages) {
 need(Array.isArray(messages)&&messages.length>0&&messages.length<=32,'MESSAGES_INVALID');
 const pending=new Set(),seen=new Set();
 for(let i=0;i<messages.length;i++) {
  const m=messages[i];need(m&&['system','user','assistant','tool'].includes(m.role),'MESSAGE_ROLE_INVALID');
  if(m.role==='tool') {
   exact(m,['role','content','tool_call_id']);need(pending.delete(m.tool_call_id),'TOOL_RESULT_UNBOUND');
   need(typeof m.content==='string','TOOL_RESULT_INVALID');continue;
  }
  need(pending.size===0,'TOOL_RESULT_MISSING');
  if(m.role==='assistant'&&m.tool_calls) {
   exact(m,['role','content','tool_calls']);need(m.content===null||typeof m.content==='string','MESSAGE_INVALID');
   need(Array.isArray(m.tool_calls)&&m.tool_calls.length===1,'PARALLEL_TOOLS_UNSUPPORTED');
   for(const t of m.tool_calls){exact(t,['id','type','function']);exact(t.function,['name','arguments']);need(t.type==='function'&&opaqueId(t.id)&&!seen.has(t.id)&&name(t.function.name)&&typeof t.function.arguments==='string','TOOL_INVALID');seen.add(t.id);pending.add(t.id);JSON.parse(t.function.arguments);}
  } else {exact(m,['role','content']);need(typeof m.content==='string'&&(m.role!=='system'||i===0),'MESSAGE_INVALID');}
 }
 need(pending.size===0,'TOOL_RESULT_MISSING');
 need(['user','tool'].includes(messages.at(-1).role),'FINAL_MESSAGE_INVALID');
}
export function compileChat(raw) {
 exact(raw,['model','messages','toolSchemas','jsonSchema','maxOutput','features']);
 const {model,messages,toolSchemas,jsonSchema,maxOutput,features}=raw;
 const ms=copy(messages),schemas=copy(toolSchemas);validateMessages(ms);
 exact(features,['tools','json','stream']);need(Object.values(features).every(x=>typeof x==='boolean')&&!features.stream,'STREAM_UNSUPPORTED');
 need(!(features.json&&features.tools),'COMBINED_JSON_TOOL_TURN_UNSUPPORTED');
 need(Object.keys(schemas).length<=32&&Object.keys(schemas).every(name),'TOOL_SCHEMA_INVALID');
 need(features.tools===(Object.keys(schemas).length>0)&&features.json===(jsonSchema!==null),'FEATURE_SCHEMA_MISMATCH');
 const tools=Object.fromEntries(Object.entries(schemas).map(([k,s])=>[k,{schema:s,example:flatSchema(s)}]));
 if(jsonSchema)flatSchema(jsonSchema);
 // Reuse the latest LLM01 codec; transcript validation is stricter and supports assistant tool calls.
 const b=encodeChat({model,messages:[{role:'user',content:''}],tools,maxOutput,stream:false,jsonSchema},'OpenAI').body;
 b.messages=ms;b.store=false;b.n=1;b.service_tier='default';
 if(features.tools){b.parallel_tool_calls=false;b.tool_choice='auto';}
 const bytes=JSON.stringify(b);
 return {body:b,bytes,requestHash:bytesHash(bytes),toolSchemas:schemas,jsonSchema:copy(jsonSchema),features:copy(features)};
}
function normalizeBilledUsage(raw) {
 need(raw&&typeof raw==='object','USAGE_MISSING');
 need(Object.keys(raw).every(k=>['prompt_tokens','completion_tokens','total_tokens','prompt_tokens_details','completion_tokens_details'].includes(k)),'USAGE_COMPONENT_UNKNOWN');
 for(const k of ['prompt_tokens','completion_tokens','total_tokens'])integer(raw[k]);
 need(Number.isSafeInteger(raw.prompt_tokens+raw.completion_tokens)&&raw.total_tokens===raw.prompt_tokens+raw.completion_tokens,'USAGE_TOTAL_MISMATCH');
 const pd=raw.prompt_tokens_details,cd=raw.completion_tokens_details;
 need(pd&&Object.hasOwn(pd,'cached_tokens')&&cd&&Object.hasOwn(cd,'reasoning_tokens'),'USAGE_DETAILS_UNKNOWN');
 for(const [d,allowed] of [[pd,['cached_tokens','audio_tokens','cache_write_tokens','image_tokens','text_tokens']],[cd,['reasoning_tokens','audio_tokens','accepted_prediction_tokens','rejected_prediction_tokens','text_tokens']]]) {
  for(const [k,v] of Object.entries(d)){integer(v);need(allowed.includes(k),'USAGE_COMPONENT_UNKNOWN');}
 }
 // Multimodal, predicted output and cache writes need a different reviewed price/protocol binding.
 for(const [d,k] of [[pd,'audio_tokens'],[pd,'cache_write_tokens'],[pd,'image_tokens'],[cd,'audio_tokens'],[cd,'accepted_prediction_tokens'],[cd,'rejected_prediction_tokens']])need((d[k]??0)===0,'BILLING_COMPONENT_UNSUPPORTED');
 need(pd.cached_tokens<=raw.prompt_tokens&&cd.reasoning_tokens<=raw.completion_tokens,'USAGE_BUCKET_OVERLAP');
 return {uncachedInput:raw.prompt_tokens-pd.cached_tokens,cacheRead:pd.cached_tokens,cacheWrite:0,output:raw.completion_tokens,toolCalls:0};
}
export function decodeProviderReply(raw,{model,toolSchemas,jsonSchema,bounds,maxToolCalls}) {
 const r=copy(raw);need(r.object==='chat.completion'&&opaqueId(r.id)&&r.model===model,'MODEL_OR_COMPLETION_MISMATCH');
 integer(r.created);need(r.choices?.length===1&&r.choices[0].index===0&&r.choices[0].message?.role==='assistant','CHOICE_INVALID');
 need(r.service_tier===undefined||r.service_tier==='default','SERVICE_TIER_SUBSTITUTED');
 const u=normalizeBilledUsage(r.usage),m=r.choices[0].message;
 need(!m.audio&&!m.function_call&&!m.reasoning_content&&(!m.annotations||m.annotations.length===0),'CONTENT_DIALECT_UNSUPPORTED');
 const calls=m.tool_calls??[];need(Array.isArray(calls)&&calls.length<=1&&calls.length<=maxToolCalls,'TOOL_COUNT_EXCEEDED');
 for(const t of calls)need(opaqueId(t.id)&&name(t.function?.name),'TOOL_INVALID');
 const decoded=decodeChat(r,{model,toolSchemas,jsonSchema});
 u.toolCalls=decoded.output.tools.length;usage(u);
 for(const k of Object.keys(u))need(u[k]<=bounds[k],'USAGE_EXCEEDS_BOUND');
 return {...decoded,usage:u,evidence:'PROVIDER_REPORTED_USAGE_NOT_INVOICE'};
}
