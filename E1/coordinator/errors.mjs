export class CoordinatorError extends Error {
  constructor(code, detail = undefined) { super(code); this.name = 'CoordinatorError'; this.code = code; if (detail !== undefined) this.detail = detail; }
}
export function check(condition, code) { if (!condition) throw new CoordinatorError(code); }
export function integer(value, code, max = Number.MAX_SAFE_INTEGER) {
  const text = String(value);
  check(/^(0|[1-9][0-9]{0,17})$/.test(text), code);
  check(BigInt(text) <= BigInt(max), code);
  return text;
}
