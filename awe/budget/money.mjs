// Integer accounting only. These local E0 types do not change D-01 wire DTOs.
export class BudgetError extends Error {
  constructor(code) { super(code); this.code = code; }
}
export const fail = code => { throw new BudgetError(code); };
export const requireThat = (condition, code) => { if (!condition) fail(code); };
export function money(value, {signed = false} = {}) {
  requireThat(typeof value === 'string' && (signed ? /^-?(0|[1-9][0-9]{0,29})$/ : /^(0|[1-9][0-9]{0,29})$/).test(value)
    && value !== '-0', 'INVALID_MONEY');
  return BigInt(value);
}
export function integer(value, max = Number.MAX_SAFE_INTEGER) {
  requireThat(Number.isSafeInteger(value) && value >= 0 && value <= max, 'INVALID_INTEGER');
  return value;
}
export const ceilDiv = (a, b) => { requireThat(b > 0n, 'INVALID_DIVISOR'); return (a + b - 1n) / b; };
export const BUCKETS = ['uncachedInput', 'cacheRead', 'cacheWrite', 'output'];
export function usage(value) {
  requireThat(value && Object.keys(value).sort().join() === [...BUCKETS, 'toolCalls'].sort().join(), 'INVALID_USAGE');
  for (const key of [...BUCKETS, 'toolCalls']) integer(value[key]);
  return value;
}
// Disjoint billed output already includes reasoning. No second reasoning charge.
export function quoteCost(profile, tokens, now) {
  usage(tokens);
  requireThat(profile?.status === 'SYNTHETIC_QUOTED', 'COST_UNKNOWN');
  integer(profile.validFrom); integer(profile.validUntil);
  requireThat(profile.validFrom <= now && now < profile.validUntil, 'QUOTE_STALE');
  requireThat(profile.currency && profile.budgetCurrency && profile.fx?.status === 'SYNTHETIC_PINNED', 'FX_UNKNOWN');
  requireThat(profile.fx.fromCurrency === profile.currency && profile.fx.toCurrency === profile.budgetCurrency, 'FX_PAIR_MISMATCH');
  integer(profile.fx.validFrom); integer(profile.fx.validUntil);
  requireThat(profile.fx.validFrom <= now && now < profile.fx.validUntil, 'FX_STALE');
  const numerator = money(profile.fx.numerator), denominator = money(profile.fx.denominator);
  requireThat(numerator > 0n && denominator > 0n, 'FX_UNKNOWN');
  requireThat(profile.fees?.status === 'SYNTHETIC_PINNED', 'FEES_UNKNOWN');
  let cost = 0n;
  for (const bucket of BUCKETS) {
    requireThat(profile.rates?.[bucket] !== null && profile.rates?.[bucket] !== undefined, 'COST_UNKNOWN');
    cost += ceilDiv(BigInt(tokens[bucket]) * money(profile.rates[bucket]), 1000000n);
  }
  requireThat(profile.toolCallMicros !== null && profile.toolCallMicros !== undefined, 'COST_UNKNOWN');
  cost += BigInt(tokens.toolCalls) * money(profile.toolCallMicros);
  // Explicit complete cash-equivalent fee envelope, including tax/top-up allocation.
  cost = ceilDiv(cost * (10000n + money(profile.fees.bps)), 10000n) + money(profile.fees.fixedMicros);
  return ceilDiv(cost * numerator, denominator).toString();
}
