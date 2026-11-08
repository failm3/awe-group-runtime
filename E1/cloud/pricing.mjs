import {immutable, need} from '../contracts/index.mjs';

const DECIMAL = /^(0|[1-9][0-9]{0,35})$/;
export function unsigned(value, code = 'CLOUD_PRICE_UNKNOWN') {
  need(typeof value === 'string' && DECIMAL.test(value), code);
  return BigInt(value);
}
export function rational(value, {positive = false} = {}) {
  need(value && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length === 2 && Object.hasOwn(value, 'numerator') && Object.hasOwn(value, 'denominator'), 'CLOUD_PRICE_UNKNOWN');
  const n = unsigned(value.numerator), d = unsigned(value.denominator);
  need(d > 0n && (!positive || n > 0n), 'CLOUD_PRICE_UNKNOWN');
  return {n, d};
}
const add = (a, b) => ({n: a.n * b.d + b.n * a.d, d: a.d * b.d});
const mul = (a, b) => ({n: a.n * b.n, d: a.d * b.d});
const units = (a, count) => ({n: a.n * BigInt(count), d: a.d});
const max = (a, b) => a.n * b.d >= b.n * a.d ? a : b;
export const ceil = a => (a.n + a.d - 1n) / a.d;
export const greater = (a, b) => a.n * b.d > b.n * a.d;
const encoded = a => ({numerator: a.n.toString(), denominator: a.d.toString()});
export function validateSource(source) {
  need(source && typeof source.source_id === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/.test(source.source_id), 'CLOUD_SOURCE_UNKNOWN');
  for (const key of ['input_micros_per_token', 'cached_input_micros_per_token', 'output_micros_per_token']) rational(source[key]);
  rational(source.coefficient, {positive: true});
  need(typeof source.price_evidence_digest === 'string' && /^sha256:[a-f0-9]{64}$/.test(source.price_evidence_digest), 'CLOUD_PRICE_PROVENANCE');
  return source;
}
/** Prices are exact USD-micros per token; rounding occurs once on the sum. */
export function sourceCost(source, {input_tokens, cached_input_tokens = 0, output_tokens}, worstCase = false) {
  validateSource(source);
  need([input_tokens, cached_input_tokens, output_tokens].every(x => Number.isSafeInteger(x) && x >= 0) && cached_input_tokens <= input_tokens, 'CLOUD_USAGE_UNKNOWN');
  const input = rational(source.input_micros_per_token), cache = rational(source.cached_input_micros_per_token), output = rational(source.output_micros_per_token);
  const base = worstCase
    ? add(units(max(input, cache), input_tokens), units(output, output_tokens))
    : add(add(units(input, input_tokens - cached_input_tokens), units(cache, cached_input_tokens)), units(output, output_tokens));
  const total = mul(base, rational(source.coefficient, {positive: true}));
  return {base, total, rounded_micros: ceil(total)};
}
export function priceBounds(route, max_input_tokens, max_output_tokens) {
  need(Array.isArray(route.sources) && route.sources.length > 0 && route.sources.length <= 64, 'CLOUD_SOURCE_UNKNOWN');
  let maximum = {n: 0n, d: 1n}, maximumFactor = {n: 0n, d: 1n};
  const sources = route.sources.map(source => {
    const cost = sourceCost(source, {input_tokens: max_input_tokens, output_tokens: max_output_tokens}, true);
    maximum = max(maximum, cost.total); maximumFactor = max(maximumFactor, rational(source.coefficient, {positive: true}));
    return {source_id: source.source_id, coefficient: source.coefficient, price_evidence_digest: source.price_evidence_digest, worst_case_micros: cost.rounded_micros.toString(), prices: {input: source.input_micros_per_token, cache: source.cached_input_micros_per_token, output: source.output_micros_per_token}};
  });
  return immutable({currency: 'USD', reserve_micros: ceil(maximum).toString(), maximum_source_coefficient: encoded(maximumFactor), sources});
}
export function nativeMicros(value) {
  const amount = typeof value === 'bigint' ? value : unsigned(value, 'CLOUD_BUDGET_UNKNOWN');
  need(amount >= 0n && amount <= BigInt(Number.MAX_SAFE_INTEGER), 'CLOUD_NATIVE_AMOUNT_BOUND');
  return Number(amount);
}
