import {createHash} from 'node:crypto';
import {canonicalize} from '../../contracts/canonical.mjs';
export {canonicalize, digest} from '../../contracts/canonical.mjs';
export const POLICY = 'D08_E0_EXACT_ARTIFACT_V1';
export const bytesHash = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
export const copy = value => structuredClone(value);
export function need(ok, code) { if (!ok) throw new Error(code); }
export function frozen(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(frozen); Object.freeze(value); }
  return value;
}
export function fields(value, keys) {
  canonicalize(value);
  need(value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === [...keys].sort().join(','), 'MALFORMED_REQUEST');
}
export const physical = () => ({decision:'DENY', code:'E0_PHYSICAL_EGRESS_DISABLED'});
