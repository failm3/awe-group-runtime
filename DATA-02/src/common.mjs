import {canonicalize, digest} from '../../contracts/canonical.mjs';
import {createHash} from 'node:crypto';
import {parseIntent, requireKeys, freeze} from '../../awe/policy/json.mjs';
export {canonicalize, digest, freeze};
export const copy=x=>JSON.parse(canonicalize(x));
export const hashBytes=b=>'sha256:'+createHash('sha256').update(b).digest('hex');
export class DataError extends Error { constructor(code){super(code);this.code=code;} }
export function need(ok,code='INPUT_INVALID'){if(!ok)throw new DataError(code);}
export function exact(x,keys){requireKeys(x,keys);return x;}
export function input(text,keys){return exact(parseIntent(text),keys);}
export function integer(x,min=0,max=Number.MAX_SAFE_INTEGER){need(Number.isSafeInteger(x)&&!Object.is(x,-0)&&x>=min&&x<=max);}
export function hash(x){need(typeof x==='string'&&/^sha256:[a-f0-9]{64}$/.test(x));}
export function time(x){need(typeof x==='string'&&Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x);}
const inherited=new Set(['DENIED','STATE_UNAVAILABLE','STATE_CHANGED','PROVENANCE_REJECTED','NOT_AVAILABLE','INVALID_INPUT','INVALID_ID','INVALID_TIME']);
export function result(fn){
  try{return freeze({ok:true,value:copy(fn())});}
  catch(e){return freeze({ok:false,code:e instanceof DataError?e.code:inherited.has(e.message)?e.message:'DEPENDENCY_UNAVAILABLE'});}
}
export function sync(fn,code){try{const x=fn();need(x&&typeof x.then!=='function',code);return copy(x);}catch{throw new DataError(code);}}
