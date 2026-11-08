export class InfraError extends Error {
  constructor(code, state = 'DENY') {
    super(code);
    this.name = 'InfraError';
    this.code = code;
    this.state = state;
  }
  toJSON() { return {code: this.code, state: this.state}; }
}
export const deny = code => { throw new InfraError(code); };
export const hold = code => { throw new InfraError(code, 'HOLD'); };
export function exactKeys(value, required, optional = []) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) deny('C1_INVALID_SHAPE');
  const keys = Reflect.ownKeys(value);
  if (keys.some(key => typeof key !== 'string' || !required.concat(optional).includes(key)) ||
      required.some(key => !Object.hasOwn(value, key)) ||
      keys.some(key => !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'))) deny('C1_INVALID_SHAPE');
}
export function deepFreeze(value) {
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}
