export class StateError extends Error {
  constructor(code, details = []) {
    super(code);
    this.name = 'StateError';
    this.code = code;
    this.details = details;
  }
}
export const requireState = (condition, code, details) => {
  if (!condition) throw new StateError(code, details);
};
export const copy = value => structuredClone(value);
export const terminal = state => ['COMPLETE', 'CANCELLED', 'FAILED'].includes(state);
export function increment(value) {
  requireState(Number.isSafeInteger(value) && value < Number.MAX_SAFE_INTEGER, 'COUNTER_EXHAUSTED');
  return value + 1;
}
