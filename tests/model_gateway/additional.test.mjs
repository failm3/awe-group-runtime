import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,readdirSync} from 'node:fs';
import {encodeChat,encodeResponses,encodeMessages,decodeResponses,decodeMessages} from '../../awe/model_gateway/codecs.mjs';
import {DOCUMENTED_MODELS} from '../../awe/model_gateway/catalog.mjs';
import {validateProfile,syntheticProfile} from '../../awe/model_gateway/profiles.mjs';
import {route,request,world} from '../budget/fixtures.mjs';
import {createModelGateway} from '../../awe/model_gateway/gateway.mjs';
const input={model:'fixture-v1',messages:[{role:'system',content:'Exact instructions'},{role:'user',content:'hello'}],maxOutput:100};
const usage={input_tokens:4,input_tokens_details:{cached_tokens:0},output_tokens:2};
test('Responses codec pins stateless payload and exact model/settings',()=>{const r=encodeResponses(input,'OpenRouter');assert.equal(r.body.store,false);assert.equal(r.body.model,input.model);assert.deepEqual(r.body.provider,{allow_fallbacks:false,require_parameters:true});assert.deepEqual(r.body.input,input.messages);});
test('Messages codec preserves system separately without merging or rewriting content',()=>{const r=encodeMessages(input);assert.equal(r.body.system,'Exact instructions');assert.deepEqual(r.body.messages,[input.messages[1]]);assert.equal(r.body.max_tokens,100);});
for(const k of ['seed','temperature','provider','base_url','previous_response_id'])test('unsupported request parameter '+k+' is not silently dropped',()=>{assert.throws(()=>encodeChat({...input,[k]:1},'OpenAI'));});
test('unimplemented reasoning and streaming fail closed for Messages',()=>{assert.throws(()=>encodeMessages({...input,reasoning:'high'}));assert.throws(()=>encodeMessages({...input,stream:true}));});
test('unimplemented streaming fails closed for Responses',()=>{assert.throws(()=>encodeResponses({...input,stream:true},'OpenAI'));});
const rr=()=>({id:'r1',model:'fixture-v1',status:'completed',usage,output:[{type:'message',status:'completed',role:'assistant',content:[{type:'output_text',text:'exact'}]}]});
test('Responses text reply preserves body and normalizes usage',()=>{const r=decodeResponses(rr(),{model:'fixture-v1'});assert.equal(r.output.text,'exact');assert.equal(r.usage.uncachedInput,4);});
test('Responses reasoning items are denied until pinned encrypted-state binding exists',()=>{const r=rr();r.output.push({type:'reasoning'});assert.throws(()=>decodeResponses(r,{model:'fixture-v1'}));});
test('Responses unfinished, substituted and refusal replies fail closed',()=>{for(const patch of [{status:'incomplete'},{model:'other'},{output:[{type:'refusal'}]}])assert.throws(()=>decodeResponses({...rr(),...patch},{model:'fixture-v1'}));});
const mr=()=>({id:'m1',model:'fixture-v1',type:'message',role:'assistant',stop_reason:'end_turn',usage:{input_tokens:4,output_tokens:2,cache_read_input_tokens:0,cache_creation_input_tokens:0},content:[{type:'text',text:'exact'}]});
test('Messages text and cache buckets normalize without fabricated savings',()=>{const r=decodeMessages(mr(),{model:'fixture-v1'});assert.equal(r.output.text,'exact');assert.equal(r.usage.cacheWrite,0);});
test('Messages incomplete, unknown block, model substitution denied',()=>{for(const patch of [{stop_reason:'max_tokens'},{content:[{type:'thinking',thinking:'opaque'}]},{model:'other'}])assert.throws(()=>decodeMessages({...mr(),...patch},{model:'fixture-v1'}));});
for(const p of DOCUMENTED_MODELS)test('documentation candidate cannot be promoted into executable profile '+p.id,()=>{assert.equal(p.physicalDecision,'DENY');assert.equal(p.eligible,false);assert.throws(()=>validateProfile(p));});
test('profile drift and feature overclaim denied before admission',()=>{
  const w=world(),p=syntheticProfile(w.routes[0]);p.contextTokens=999999;const g=createModelGateway({...w,profiles:[p],readAuthority:()=>w.ledger.authority()});
  assert.equal(g.prepare(request()).decision,'DENY');assert.equal(w.controls.r1.calls().length,0);
});
test('source modules contain no network, child process, external SDK, secret store or credential reads',()=>{
  for(const file of readdirSync('awe/model_gateway').filter(x=>x.endsWith('.mjs'))){
    const s=readFileSync('awe/model_gateway/'+file,'utf8');assert(!/from ['"](?:node:(?:https?|net|tls|child_process)|openai|@anthropic)/.test(s),file);
    assert(!/\bfetch\s*\(|process\.env|api_key\s*:|Authorization\s*:|new WebSocket/.test(s),file);
  }
});
