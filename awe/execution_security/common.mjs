import {createHash} from 'node:crypto';
export {canonicalize,digest} from '../../contracts/canonical.mjs';
export {parseIntent,copy,freeze,requireKeys} from '../policy/json.mjs';
export const VERSION='sec01.v1';
export class SecurityError extends Error {constructor(code){super(code);this.code=code;}}
export function need(ok,code){if(!ok)throw new SecurityError(code);}
export const hashBytes=bytes=>'sha256:'+createHash('sha256').update(bytes).digest('hex');
export function id(value){need(typeof value==='string'&&/^[A-Za-z0-9_.:-]{1,128}$/.test(value),'ID_INVALID');return value;}
export function micros(value){need(typeof value==='string'&&/^(0|[1-9][0-9]{0,29})$/.test(value),'MICROS_INVALID');return BigInt(value);}
export function hash(value){need(typeof value==='string'&&/^sha256:[a-f0-9]{64}$/.test(value),'HASH_INVALID');return value;}
export function integer(value,min=0){need(Number.isSafeInteger(value)&&value>=min,'INTEGER_INVALID');return value;}
// Never reflect worker bytes, SQL errors, keys, tokens or causes into an agent response.
export function denial(error){return Object.freeze({decision:'DENY',physical_decision:'DENY',code:error instanceof SecurityError?error.code:'SECURITY_DEPENDENCY_FAILURE'});}
