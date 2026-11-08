import {createHash} from 'node:crypto';
export const CANONICALIZATION='awe-canonical-json-v1';
// Restricted JSON: safe integers, well-formed Unicode, no normalization, UTF-16 key order.
export function canonicalize(value) {
  const visit=(v,depth)=>{
    if(depth>32) throw new TypeError('DEPTH_LIMIT');
    if(v===null || typeof v==='boolean') return JSON.stringify(v);
    if(typeof v==='number') {
      if(!Number.isSafeInteger(v)||Object.is(v,-0)) throw new TypeError('SAFE_INTEGER_REQUIRED');
      return String(v);
    }
    if(typeof v==='string') {
      if(!v.isWellFormed()) throw new TypeError('INVALID_UNICODE');
      return JSON.stringify(v);
    }
    if(Array.isArray(v)) {
      if(Object.keys(v).length!==v.length) throw new TypeError('DENSE_ARRAY_REQUIRED');
      return '['+Array.from({length:v.length},(_,i)=>visit(v[i],depth+1)).join(',')+']';
    }
    if(typeof v!=='object'||Object.getPrototypeOf(v)!==Object.prototype) throw new TypeError('PLAIN_JSON_REQUIRED');
    const keys=Object.keys(v).sort();
    for(const key of keys) {
      if(!key.isWellFormed() || ['__proto__','prototype','constructor'].includes(key)) throw new TypeError('UNSAFE_KEY');
      if(!Object.hasOwn(Object.getOwnPropertyDescriptor(v,key),'value')) throw new TypeError('DATA_PROPERTY_REQUIRED');
    }
    if(Reflect.ownKeys(v).length!==keys.length) throw new TypeError('ENUMERABLE_JSON_REQUIRED');
    return '{'+keys.map(k=>JSON.stringify(k)+':'+visit(v[k],depth+1)).join(',')+'}';
  };
  const result=visit(value,0);
  if(Buffer.byteLength(result)>65536) throw new TypeError('PAYLOAD_TOO_LARGE');
  return result;
}
export const digest = value => 'sha256:'+createHash('sha256').update(canonicalize(value),'utf8').digest('hex');
