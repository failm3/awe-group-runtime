import {digest} from '../contracts/index.mjs';
export const NOW='2026-11-08T12:00:00.000Z';
export const clone=value=>structuredClone(value);
export const fraction=(numerator,denominator=1)=>({numerator:String(numerator),denominator:String(denominator)});
export function source(overrides={}){return {source_id:'qa3-source-a',input_micros_per_token:fraction(1,3),cached_input_micros_per_token:fraction(1,6),output_micros_per_token:fraction(2,3),coefficient:fraction(3,2),price_evidence_digest:digest({synthetic:'qa3-price-observation'}),...overrides};}
export function catalog(){return {
 version:'awe.e1.router-cheap.catalog/1',provider:'router.cheap',endpoint:'https://router.cheap/v1/chat/completions',currency:'USD',official_source:'https://router.cheap',source_digest:digest({synthetic:'qa3-catalog'}),observed_at:NOW,expires_at:'2026-11-09T11:59:59.000Z',
 routes:[{route_id:'router.cheap.chat.qa3-synthetic',route_version:'1.0.0',model_id:'qa3/synthetic-model',context_tokens:8192,max_output_tokens:2048,input_token_bound:'HOST_VERIFIED_UPPER_BOUND',input_bound_evidence_digest:digest({synthetic:'qa3-input-bound'}),features:Object.fromEntries(['chat_completions','strict_json_schema','non_streaming','source_identity','provider_request_id','usage','actual_billed_charge','bounded_input_tokens'].map(x=>[x,'CONFIRMED'])),sources:[source()]}]
};}
