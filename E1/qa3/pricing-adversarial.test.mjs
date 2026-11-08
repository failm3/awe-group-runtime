import test from 'node:test';
import assert from 'node:assert/strict';
import {sourceCost,priceBounds,nativeMicros} from '../cloud/pricing.mjs';
import {cloudQuote,validateCloudCatalog} from '../cloud/registry.mjs';
import {MODEL_POLICY} from '../broker/schemas.mjs';
import {NOW,clone,fraction,source,catalog} from './fixtures.mjs';

test('QA3 mock-only process blocks network and child-process dispatch',async()=>{
 assert.equal(globalThis.__QA3_OFFLINE_GUARD_ACTIVE__,true,'Run QA3 with run-offline.mjs or the documented offline preload.');
 await assert.rejects(async()=>fetch('https://example.invalid'),{code:'QA3_OFFLINE_EFFECT_DENIED'});
 const {spawn}=await import('node:child_process');assert.throws(()=>spawn('wsl.exe',[]),{code:'QA3_OFFLINE_EFFECT_DENIED'});
});
test('QA3 rational cost rounds once after cache subtraction and source multiplier',()=>{
 const result=sourceCost(source(),{input_tokens:3,cached_input_tokens:1,output_tokens:2});
 assert.equal(result.total.n*4n,result.total.d*13n);assert.equal(result.rounded_micros,4n);
});
test('QA3 reservation bounds expensive cache and independently maximizes all eligible sources',()=>{
 const cheap=source({source_id:'cheap-high-factor',input_micros_per_token:fraction(1,100),cached_input_micros_per_token:fraction(1,100),output_micros_per_token:fraction(1,100),coefficient:fraction(100)});
 const expensive=source({source_id:'expensive-cache',cached_input_micros_per_token:fraction(5,3)});
 const quote=priceBounds({sources:[cheap,expensive]},3,2);
 assert.equal(quote.reserve_micros,'10');
 assert.equal(quote.maximum_source_coefficient.numerator,'100');assert.equal(quote.sources.length,2);
});
test('QA3 exact large fractional arithmetic never under-reserves through floating-point conversion',()=>{
 const s=source({input_micros_per_token:fraction('9007199254740993','9007199254740992'),cached_input_micros_per_token:fraction(0),output_micros_per_token:fraction(0),coefficient:fraction(1)});
 assert.equal(sourceCost(s,{input_tokens:1,output_tokens:0}).rounded_micros,2n);
 assert.throws(()=>nativeMicros('9007199254740992'));
});
test('QA3 missing prices, source factors, evidence and invalid usage are rejected',()=>{
 for(const mutate of [s=>delete s.output_micros_per_token,s=>s.coefficient=fraction(0),s=>s.coefficient=fraction(1,0),s=>s.price_evidence_digest='unproven',s=>s.input_micros_per_token=fraction(-1),s=>s.cached_input_micros_per_token=fraction('01')]){const s=source();mutate(s);assert.throws(()=>sourceCost(s,{input_tokens:1,output_tokens:1}));}
 for(const usage of [{input_tokens:1,cached_input_tokens:2,output_tokens:0},{input_tokens:-1,output_tokens:0},{input_tokens:0.5,output_tokens:1},{input_tokens:Number.MAX_SAFE_INTEGER+1,output_tokens:0}])assert.throws(()=>sourceCost(source(),usage));
});
test('QA3 quote enforces exact model route and immutable observed source snapshot',()=>{
 const original=catalog(),q=cloudQuote({catalog:original,route_id:original.routes[0].route_id,max_input_tokens:100,max_output_tokens:100,now:NOW});
 assert.equal(q.model_id,'qa3/synthetic-model');assert.ok(BigInt(q.reserve_micros)>0n);assert.ok(Object.isFrozen(q.sources));
 original.routes[0].sources[0].coefficient=fraction(999);assert.equal(q.sources[0].coefficient.numerator,'3');
 assert.throws(()=>cloudQuote({catalog:original,route_id:'gpt-image-2',max_input_tokens:100,max_output_tokens:100,now:NOW}));
});
test('QA3 stale, future, unbounded or incomplete catalog cannot create a quote',()=>{
 const mutations=[x=>x.expires_at=NOW,x=>x.observed_at='2026-11-08T12:00:01.000Z',x=>x.expires_at='2026-11-10T12:00:00.000Z',x=>x.endpoint='https://attacker.invalid/v1/chat/completions',x=>x.official_source='https://router.cheap.attacker.invalid/',x=>x.routes[0].features.actual_billed_charge='UNKNOWN',x=>x.routes[0].input_token_bound='ESTIMATE',x=>delete x.routes[0].sources[0].coefficient,x=>x.routes.push(clone(x.routes[0])),x=>x.routes[0].sources.push(clone(x.routes[0].sources[0]))];
 for(const mutate of mutations){const value=catalog();mutate(value);assert.throws(()=>validateCloudCatalog(value,NOW));}
 const c=catalog();for(const [i,o] of [[0,1],[1,0],[1,2049],[8192,1],[1.2,2]])assert.throws(()=>cloudQuote({catalog:c,route_id:c.routes[0].route_id,max_input_tokens:i,max_output_tokens:o,now:NOW}));
});
test('QA3 local Ollama policy remains explicitly pinned and cloud fallback disabled',()=>{
 assert.equal(MODEL_POLICY.endpoint,'http://127.0.0.1:11434');assert.equal(MODEL_POLICY.model,'qwen3:4b-instruct');assert.equal(MODEL_POLICY.digest,'0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0');assert.equal(MODEL_POLICY.cloud_fallback,false);assert.deepEqual(MODEL_POLICY.context_tokens,[4096,8192]);
});
