import {canonicalize, digest, integer, requireThat} from './common.mjs';

// A byte is a synthetic token ONLY in this explicit fixture protocol. No provider accuracy claim.
export function syntheticTokenizer({id = 'synthetic-utf8', version = '1', scale = 1, uncertainty = 0} = {}) {
  requireThat(integer(scale) && scale > 0 && (uncertainty === null || integer(uncertainty)), 'TOKENIZER_INVALID');
  return Object.freeze({id, version, count(text) {
    const tokens = Buffer.byteLength(text, 'utf8') * scale;
    return {tokens, upper_bound: uncertainty === null ? null : tokens + uncertainty,
      method: id, version, uncertainty_tokens: uncertainty, accuracy: 'SYNTHETIC_ONLY'};
  }});
}

export function checkProfile(profile, route, adapter, now) {
  requireThat(profile && profile.status === 'VERIFIED_SYNTHETIC', 'PROFILE_UNKNOWN');
  for (const key of ['id', 'version', 'provider', 'endpoint', 'deployment', 'model_revision', 'region', 'source_ref'])
    requireThat(typeof profile[key] === 'string' && profile[key].length > 0, 'PROFILE_UNKNOWN');
  requireThat(Number.isSafeInteger(now) && integer(profile.checked_at) && integer(profile.expires_at)
    && profile.checked_at <= now && now < profile.expires_at, 'PROFILE_UNKNOWN');
  requireThat(route && ['provider', 'endpoint', 'deployment', 'model_revision', 'region'].every(k => route[k] === profile[k]), 'PROFILE_UNKNOWN');
  requireThat(profile.protocol === 'awe-synthetic-chat-v1' && profile.reasoning_accounting === 'ADDITIVE'
    && profile.attachments === 'INLINE_SYNTHETIC_BYTES', 'MODEL_SWITCH_UNSUPPORTED');
  requireThat(profile.caps && ['window', 'input', 'output'].every(k => integer(profile.caps[k]) && profile.caps[k] > 0)
    && typeof profile.tools === 'boolean', 'PROFILE_UNKNOWN');
  requireThat(adapter && profile.tokenizer && adapter.id === profile.tokenizer.id && adapter.version === profile.tokenizer.version, 'PROFILE_UNKNOWN');
  return digest(profile);
}

export function countRequest(payload, adapter) {
  const serialized = canonicalize(payload), count = adapter.count(serialized);
  requireThat(count && count.method === adapter.id && count.version === adapter.version && integer(count.tokens)
    && (count.upper_bound === null || (integer(count.upper_bound) && count.upper_bound >= count.tokens)), 'TOKEN_COUNT_UNCERTAIN');
  // Component estimates are diagnostic: arbitrary tokenizers need not be additive.
  const components = Object.fromEntries(Object.entries(payload).map(([key, value]) => {
    const part = adapter.count(canonicalize(value)); requireThat(integer(part.tokens), 'TOKEN_COUNT_UNCERTAIN');
    return [key, {estimated_tokens: part.tokens, serialized_bytes: Buffer.byteLength(canonicalize(value))}];
  }));
  return {...count, serialized_bytes: Buffer.byteLength(serialized), payload_hash: digest(payload), components,
    component_sum_is_authoritative: false, actual_provider_tokens: null};
}

export function budgetDecision(profile, counted, reserves, reservation_ref) {
  requireThat(reserves && ['output', 'reasoning', 'safety', 'next_tool'].every(k => integer(reserves[k])), 'RESERVES_INVALID');
  const generation = reserves.output + reserves.reasoning;
  const total = counted.upper_bound === null ? null : counted.upper_bound + generation + reserves.safety + reserves.next_tool;
  requireThat(integer(generation) && (total === null || integer(total)), 'RESERVES_INVALID');
  let code = 'FITS_SYNTHETIC_BOUND';
  if (counted.upper_bound === null) code = 'TOKEN_COUNT_UNCERTAIN';
  else if (generation > profile.caps.output) code = 'OUTPUT_CAP_EXCEEDED';
  else if (counted.upper_bound > profile.caps.input || total > profile.caps.window) code = 'CONTEXT_TOO_LARGE';
  return {decision: code === 'FITS_SYNTHETIC_BOUND' ? 'ALLOW_OFFLINE' : code === 'TOKEN_COUNT_UNCERTAIN' ? 'WAIT' : 'DENY', code,
    units: 'synthetic_tokens', caps: profile.caps, input_upper_bound: counted.upper_bound, reserves,
    generation_reserve: generation, planned_total: total, formula: 'Tin_upper + output + reasoning + safety + next_tool <= window; Tin_upper <= input; output + reasoning <= output_cap',
    reservation_ref, method: counted.method, version: counted.version, payload_hash: counted.payload_hash,
    actual_usage: null, actual_cost_micros: null};
}
