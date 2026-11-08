import {copy,hash} from './profiles.mjs';
import {requireThat as need,integer} from '../budget/money.mjs';
import {validateShape} from '../providers/validation.mjs';
// Pure, bounded protocol codecs. Not HTTP clients and not an assertion of live parity.
export function encodeChat(raw,provider) {
  const {model,messages,tools={},maxOutput,stream=false,jsonSchema=null,reasoning=null}=copy(raw);
  need(Object.keys(raw).every(k=>['model','messages','tools','maxOutput','stream','jsonSchema','reasoning'].includes(k)),'PARAMETER_UNSUPPORTED');
  need(['router.cheap','OpenRouter','OpenAI'].includes(provider),'PROVIDER_UNSUPPORTED');
  integer(maxOutput);need(maxOutput>0 && typeof model==='string' && model.length>0,'REQUEST_INVALID');
  const m=copy(messages);need(Array.isArray(m)&&m.length>0,'MESSAGES_REQUIRED');
  for(const v of m)need(['system','user','assistant','tool'].includes(v.role) && typeof v.content==='string'
    && Object.keys(v).every(k=>['role','content','tool_call_id'].includes(k)),'MESSAGE_DIALECT_UNSUPPORTED');
  need(typeof stream==='boolean','STREAM_INVALID');
  const body={model,messages:m,max_completion_tokens:maxOutput,stream};
  if(stream)body.stream_options={include_usage:true};
  if(Object.keys(tools).length)body.tools=Object.entries(tools).map(([name,t])=>{
    validateShape(t.example,t.schema);
    return {type:'function',function:{name,strict:true,parameters:toJsonSchema(t.schema)}};
  });
  if(jsonSchema)body.response_format={type:'json_schema',json_schema:{name:'result',strict:true,schema:toJsonSchema(jsonSchema)}};
  if(reasoning!==null){need(['low','medium','high'].includes(reasoning),'REASONING_UNSUPPORTED');body.reasoning_effort=reasoning;}
  if(provider==='OpenRouter')body.provider={allow_fallbacks:false,require_parameters:true};
  return {protocol:'OPENAI_CHAT_SUBSET_V1',body,requestHash:hash(body),physicalDecision:'DENY'};
}
export function encodeResponses(raw,provider) {
  need(['OpenAI','OpenRouter','router.cheap'].includes(provider),'PROVIDER_UNSUPPORTED');
  const chat=encodeChat({...raw,stream:false},provider);
  need(raw.stream!==true,'RESPONSES_STREAM_NOT_IMPLEMENTED');
  const b=chat.body,body={model:b.model,input:b.messages,max_output_tokens:b.max_completion_tokens,store:false,stream:false};
  if(b.tools)body.tools=b.tools.map(t=>({type:'function',...t.function}));
  if(b.response_format)body.text={format:{type:'json_schema',...b.response_format.json_schema}};
  if(b.reasoning_effort)body.reasoning={effort:b.reasoning_effort};
  if(b.provider)body.provider=b.provider;
  return {protocol:'OPENAI_RESPONSES_SUBSET_V1',body,requestHash:hash(body),physicalDecision:'DENY'};
}
export function encodeMessages(raw) {
  const chat=encodeChat({...raw,stream:false},'OpenAI');need(raw.stream!==true,'MESSAGES_STREAM_NOT_IMPLEMENTED');
  need(raw.reasoning===undefined||raw.reasoning===null,'ANTHROPIC_REASONING_REQUIRES_MODEL_BINDING');
  need(raw.jsonSchema===undefined||raw.jsonSchema===null,'ANTHROPIC_STRUCTURED_BINDING_NOT_IMPLEMENTED');
  const b=chat.body;need(b.messages.every(x=>['system','user','assistant'].includes(x.role)),'ANTHROPIC_TOOL_RESULTS_NOT_IMPLEMENTED');
  need(b.messages.slice(1).every(x=>x.role!=='system'),'MID_CONVERSATION_SYSTEM_UNSUPPORTED');
  const body={model:b.model,messages:b.messages.filter(x=>x.role!=='system'),max_tokens:b.max_completion_tokens,stream:false};
  if(b.messages[0].role==='system')body.system=b.messages[0].content;
  need(body.messages.length>0,'MESSAGES_REQUIRED');
  if(b.tools)body.tools=b.tools.map(t=>({name:t.function.name,input_schema:t.function.parameters,strict:true}));
  return {protocol:'ANTHROPIC_MESSAGES_SUBSET_V1',body,requestHash:hash(body),physicalDecision:'DENY'};
}
export function decodeResponses(raw,{model,toolSchemas={}}) {
  const r=copy(raw);need(r.status==='completed' && r.model===model && typeof r.id==='string','RESPONSE_INCOMPLETE_OR_SUBSTITUTED');
  need(Array.isArray(r.output),'RESPONSE_OUTPUT_REQUIRED');let text='';const tools=[],ids=new Set();
  for(const item of r.output) {
    if(item.type==='message') {
      need(item.role==='assistant' && item.status==='completed' && Array.isArray(item.content),'MESSAGE_INCOMPLETE');
      for(const c of item.content){need(c.type==='output_text' && typeof c.text==='string','RESPONSE_CONTENT_UNSUPPORTED');text+=c.text;}
    } else if(item.type==='function_call') {
      need(item.status==='completed' && typeof item.call_id==='string' && item.call_id.length>0 && !ids.has(item.call_id) && Object.hasOwn(toolSchemas,item.name),'TOOL_INVALID');
      ids.add(item.call_id);let args;try{args=JSON.parse(item.arguments);}catch{need(false,'TOOL_ARGUMENTS_INVALID');}
      validateShape(args,toolSchemas[item.name]);tools.push({id:item.call_id,name:item.name,arguments:args});
    } else need(false,'RESPONSE_ITEM_UNSUPPORTED'); // reasoning/encrypted items require a separately pinned binding
  }
  const usage=normalizeUsage('OPENAI_RESPONSES',r.usage);usage.toolCalls=tools.length;
  return {providerRequestId:r.id,modelId:model,output:{text,tools},usage,complete:true,evidence:'SYNTHETIC_CODEC_ONLY'};
}
export function decodeMessages(raw,{model,toolSchemas={}}) {
  const r=copy(raw);need(r.model===model && typeof r.id==='string' && r.type==='message' && r.role==='assistant'
    && ['end_turn','tool_use'].includes(r.stop_reason),'MESSAGE_INCOMPLETE_OR_SUBSTITUTED');
  need(Array.isArray(r.content),'CONTENT_REQUIRED');let text='';const tools=[],ids=new Set();
  for(const c of r.content) {
    if(c.type==='text'){need(typeof c.text==='string','CONTENT_INVALID');text+=c.text;}
    else if(c.type==='tool_use') {
      need(typeof c.id==='string' && c.id.length>0 && !ids.has(c.id) && Object.hasOwn(toolSchemas,c.name),'TOOL_INVALID');ids.add(c.id);
      validateShape(c.input,toolSchemas[c.name]);tools.push({id:c.id,name:c.name,arguments:c.input});
    } else need(false,'ANTHROPIC_CONTENT_UNSUPPORTED');
  }
  need((r.stop_reason==='tool_use')===(tools.length>0),'FINISH_REASON_MISMATCH');
  const usage=normalizeUsage('ANTHROPIC_MESSAGES',r.usage);usage.toolCalls=tools.length;
  return {providerRequestId:r.id,modelId:model,output:{text,tools},usage,complete:true,evidence:'SYNTHETIC_CODEC_ONLY'};
}
function toJsonSchema(s) {
  validateShape(Object.fromEntries(s.required.map(k=>[k,s.properties[k]==='integer'?0:s.properties[k]==='boolean'?false:''])),s);
  return {type:'object',required:copy(s.required),properties:Object.fromEntries(Object.entries(s.properties).map(([k,type])=>[k,{type}])),additionalProperties:false};
}
export function normalizeUsage(protocol,raw) {
  const u=copy(raw);let total,cached,write,output,reasoning;
  if(protocol==='ANTHROPIC_MESSAGES') {
    total=u.input_tokens;cached=u.cache_read_input_tokens;write=u.cache_creation_input_tokens;output=u.output_tokens;reasoning=0;
  } else if(['OPENAI_CHAT','OPENAI_RESPONSES'].includes(protocol)) {
    const chat=protocol==='OPENAI_CHAT';total=chat?u.prompt_tokens:u.input_tokens;
    const d=(chat?u.prompt_tokens_details:u.input_tokens_details);
    need(d && Object.hasOwn(d,'cached_tokens'),'USAGE_DETAILS_UNKNOWN');cached=d.cached_tokens;write=0;
    output=chat?u.completion_tokens:u.output_tokens;
    reasoning=(chat?u.completion_tokens_details:u.output_tokens_details)?.reasoning_tokens??0;
  } else need(false,'PROTOCOL_UNSUPPORTED');
  for(const n of [total,cached,write,output,reasoning])integer(n);
  need(reasoning<=output,'REASONING_DOUBLE_COUNT_RISK');
  need(protocol==='ANTHROPIC_MESSAGES'||cached<=total,'CACHE_BUCKET_OVERLAP');
  return {uncachedInput:protocol==='ANTHROPIC_MESSAGES'?total:total-cached,cacheRead:cached,cacheWrite:write,output,toolCalls:0};
}
export function decodeChat(raw,{model,toolSchemas={},jsonSchema=null}) {
  const r=copy(raw);need(r.model===model && typeof r.id==='string' && r.id.length>0,'MODEL_OR_RECEIPT_MISMATCH');
  need(r.choices?.length===1,'CHOICES_UNSUPPORTED');const c=r.choices[0],m=c.message;
  need(['stop','tool_calls'].includes(c.finish_reason) && m && !m.refusal,'INCOMPLETE_OR_REFUSED');
  const tools=[],seen=new Set();
  for(const t of m.tool_calls??[]) {
    need(t.type==='function' && typeof t.id==='string' && t.id.length>0 && !seen.has(t.id) && Object.hasOwn(toolSchemas,t.function.name),'TOOL_INVALID');
    seen.add(t.id);let args;try{args=JSON.parse(t.function.arguments);}catch{need(false,'TOOL_ARGUMENTS_INVALID');}
    validateShape(args,toolSchemas[t.function.name]);tools.push({id:t.id,name:t.function.name,arguments:args});
  }
  need((c.finish_reason==='tool_calls')===(tools.length>0),'FINISH_REASON_MISMATCH');
  need(typeof m.content==='string'||m.content===null&&tools.length>0,'CONTENT_INVALID');
  let json=null;if(jsonSchema){try{json=JSON.parse(m.content);}catch{need(false,'JSON_INVALID');}validateShape(json,jsonSchema);}
  const usage=normalizeUsage('OPENAI_CHAT',r.usage);usage.toolCalls=tools.length;
  return {providerRequestId:r.id,modelId:r.model,usage,output:{text:m.content??'',tools,...(jsonSchema?{json}:{})},complete:true,evidence:'SYNTHETIC_CODEC_ONLY'};
}
// Chunk transport segmentation must already be decoded as UTF-8 SSE records. Tool deltas/reasoning streams are unsupported, fail closed.
export function decodeTextStream(events,{model}) {
  const rows=copy(events);need(Array.isArray(rows)&&rows.length>=3,'STREAM_INCOMPLETE');let text='',usage=null,finished=false,done=false,id=null;
  for(let i=0;i<rows.length;i++) {
    const r=rows[i];
    if(r==='[DONE]'){need(i===rows.length-1 && finished && usage,'STREAM_INCOMPLETE');done=true;continue;}
    need(!done && r.model===model && typeof r.id==='string' && (id===null||id===r.id),'STREAM_MODEL_MISMATCH');id=r.id;
    if(r.choices?.length===0){need(finished && !usage && r.usage,'STREAM_USAGE_ORDER');usage=normalizeUsage('OPENAI_CHAT',r.usage);continue;}
    need(!finished && r.choices?.length===1,'STREAM_ORDER');const c=r.choices[0];
    need(c.index===0 && c.delta && Object.keys(c.delta).every(k=>['role','content'].includes(k)),'STREAM_DIALECT_UNSUPPORTED');
    need(c.delta.role===undefined||c.delta.role==='assistant','STREAM_ROLE_INVALID');
    if(c.delta.content!==undefined){need(typeof c.delta.content==='string','STREAM_CONTENT_INVALID');text+=c.delta.content;}
    if(c.finish_reason!==null && c.finish_reason!==undefined){need(c.finish_reason==='stop','STREAM_INCOMPLETE');finished=true;}
  }
  need(done,'STREAM_INCOMPLETE');return {text,usage,providerRequestId:id,modelId:model,complete:true};
}
