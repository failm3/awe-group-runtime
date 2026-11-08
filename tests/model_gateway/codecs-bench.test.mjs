import test from 'node:test';
import assert from 'node:assert/strict';
import {encodeChat,decodeChat,normalizeUsage,decodeTextStream} from '../../awe/model_gateway/codecs.mjs';
import {benchmarkCases,materializeCorpus,scoreExact,acceptedResultCost,wilson} from '../../awe/model_gateway/bench.mjs';
const schema={required:['key'],properties:{key:'string'},additionalProperties:false};
const input={model:'fixture-v1',messages:[{role:'system',content:'Exact 🧪 e\u0301'},{role:'user',content:'Keep unicode and zero'}],tools:{lookup:{schema,example:{key:'x'}}},maxOutput:100,stream:true,jsonSchema:schema,reasoning:'high'};
const response=()=>({id:'fixture-r1',model:'fixture-v1',choices:[{finish_reason:'stop',message:{content:'{"key":"x"}'}}],usage:{prompt_tokens:10,prompt_tokens_details:{cached_tokens:4},completion_tokens:8,completion_tokens_details:{reasoning_tokens:5}}});
for(const provider of ['router.cheap','OpenRouter','OpenAI'])test('pure '+provider+' codec retains request semantics',()=>{
  const r=encodeChat(input,provider);assert.deepEqual(r.body.messages,input.messages);assert.equal(r.body.tools[0].function.strict,true);
  assert.deepEqual(r.body.tools[0].function.parameters.properties,{key:{type:'string'}});assert.equal(r.body.reasoning_effort,'high');assert.equal(r.physicalDecision,'DENY');
  if(provider==='OpenRouter')assert.deepEqual(r.body.provider,{require_parameters:true,allow_fallbacks:false});
});
test('OpenAI usage subtracts cached input and includes reasoning once',()=>{
  assert.deepEqual(normalizeUsage('OPENAI_CHAT',response().usage),{uncachedInput:6,cacheRead:4,cacheWrite:0,output:8,toolCalls:0});
  assert.deepEqual(normalizeUsage('OPENAI_RESPONSES',{input_tokens:10,input_tokens_details:{cached_tokens:4},output_tokens:8,output_tokens_details:{reasoning_tokens:5}}),{uncachedInput:6,cacheRead:4,cacheWrite:0,output:8,toolCalls:0});
});
test('Anthropic usage preserves three disjoint input buckets',()=>{
  assert.deepEqual(normalizeUsage('ANTHROPIC_MESSAGES',{input_tokens:10,cache_read_input_tokens:4,cache_creation_input_tokens:5,output_tokens:8}),{uncachedInput:10,cacheRead:4,cacheWrite:5,output:8,toolCalls:0});
});
for(const [name,patch] of [['model',{model:'substituted'}],['truncated',{choices:[{finish_reason:'length',message:{content:'x'}}]}],['usage',{usage:{prompt_tokens:1,completion_tokens:1}}],['refusal',{choices:[{finish_reason:'stop',message:{refusal:'no',content:null}}]}],['json',{choices:[{finish_reason:'stop',message:{content:'{"extra":1}'}}]}]])test('invalid reply '+name+' is rejected',()=>{
  assert.throws(()=>decodeChat({...response(),...patch},{model:'fixture-v1',jsonSchema:schema}));
});
test('tool arguments are parsed as JSON and checked against exact schema',()=>{
  const r=response();r.choices=[{finish_reason:'tool_calls',message:{content:null,tool_calls:[{id:'t1',type:'function',function:{name:'lookup',arguments:'{"key":"🧪"}'}}]}}];
  const out=decodeChat(r,{model:'fixture-v1',toolSchemas:{lookup:schema}});assert.deepEqual(out.output.tools[0].arguments,{key:'🧪'});assert.equal(out.usage.toolCalls,1);
  r.choices[0].message.tool_calls[0].function.arguments='{"key":1}';assert.throws(()=>decodeChat(r,{model:'fixture-v1',toolSchemas:{lookup:schema}}));
});
test('duplicate tool IDs and unknown tools denied',()=>{
  const r=response(),t={id:'t1',type:'function',function:{name:'lookup',arguments:'{"key":"x"}'}};r.choices=[{finish_reason:'tool_calls',message:{content:null,tool_calls:[t,t]}}];
  assert.throws(()=>decodeChat(r,{model:'fixture-v1',toolSchemas:{lookup:schema}}));r.choices[0].message.tool_calls=[t];assert.throws(()=>decodeChat(r,{model:'fixture-v1',toolSchemas:{}}));
});
const chunk=(content,finish_reason=null)=>({id:'stream1',model:'fixture-v1',choices:[{index:0,delta:content===null?{}:{content},finish_reason}]});
const stream=()=>[chunk('exact 🧪 '),chunk('reply','stop'),{id:'stream1',model:'fixture-v1',choices:[],usage:response().usage},'[DONE]'];
test('stream joins content exactly and requires terminal usage plus DONE',()=>{const r=decodeTextStream(stream(),{model:'fixture-v1'});assert.equal(r.text,'exact 🧪 reply');assert.equal(r.usage.output,8);});
for(const [name,fn] of [['no DONE',r=>r.slice(0,-1)],['missing usage',r=>[...r.slice(0,2),'[DONE]']],['duplicate terminal',r=>[...r,r.at(-1)]],['model changed',r=>{r[1].model='bad';return r;}],['partial tool',r=>{r[0].choices[0].delta={tool_calls:[{}]};return r;}]])test('stream denies '+name,()=>{assert.throws(()=>decodeTextStream(fn(stream()),{model:'fixture-v1'}));});
for(const u of [{prompt_tokens:1,prompt_tokens_details:{cached_tokens:2},completion_tokens:1},{prompt_tokens:1,prompt_tokens_details:{cached_tokens:0},completion_tokens:1,completion_tokens_details:{reasoning_tokens:2}},{prompt_tokens:-1,prompt_tokens_details:{cached_tokens:0},completion_tokens:1}])test('overlapping or invalid usage denied '+JSON.stringify(u),()=>{assert.throws(()=>normalizeUsage('OPENAI_CHAT',u));});
test('bench contains 40 pinned reproducible tasks across 8 categories',()=>{
  const cases=benchmarkCases();assert.equal(cases.length,40);assert.equal(new Set(cases.map(x=>x.id)).size,40);assert.equal(new Set(cases.map(x=>x.category)).size,8);assert.deepEqual(cases,benchmarkCases());
  for(const c of cases.filter(x=>x.oracle.kind==='exact')){assert(scoreExact(c,c.oracle.expected));assert.equal(scoreExact(c,{}),false);}
});
for(const c of benchmarkCases().filter(x=>x.oracle.kind==='corpus'))test('corpus deterministic '+c.id,()=>{const a=materializeCorpus(c),b=materializeCorpus(c);assert.deepEqual(a,b);assert.equal(a.text.indexOf('\nCANONICAL:'),a.offset);assert.equal(a.text.split(a.canonical).length,2);});
test('unsupported code/agent scoring cannot be replaced by worker PASS',()=>{assert.throws(()=>scoreExact(benchmarkCases()[0],{pass:true}));});
test('cost per accepted result includes failed attempts and multiple accepted receipts once',()=>{
  const row=(taskId,receiptId,costMicros,accepted=false)=>({taskId,receiptId,costMicros,accepted,acceptanceSource:accepted?'INDEPENDENT_QA':'NOT_ACCEPTED'});
  const r=acceptedResultCost([row('a','1','20'),row('a','2','40',true),row('b','3','60'),row('a','4','10',true)]);
  assert.deepEqual(r,{spentMicros:'130',accepted:1,costPerAcceptedMicros:'130',status:'COMPUTED'});
  assert.equal(acceptedResultCost([row('a','1',null,true)]).status,'COST_UNKNOWN');
  assert.equal(acceptedResultCost([row('a','1','5')]).costPerAcceptedMicros,null);
  assert.throws(()=>acceptedResultCost([row('a','1','5'),row('a','1','5')]));
  assert.throws(()=>acceptedResultCost([{...row('a','1','5',true),acceptanceSource:'NOT_ACCEPTED'}]));
});
test('exact micros beyond Number range and conservative division',()=>{const r=acceptedResultCost([{taskId:'a',receiptId:'x',costMicros:'999999999999999999999999999999',accepted:true,acceptanceSource:'INDEPENDENT_QA'}]);assert.equal(r.spentMicros,'999999999999999999999999999999');});
test('Wilson uncertainty prevents small-sample certainty',()=>{const r=wilson(40,40);assert(r.low<0.92 && r.high<=1);assert.throws(()=>wilson(1,0));});
