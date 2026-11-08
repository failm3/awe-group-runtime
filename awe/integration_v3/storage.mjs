import {canonicalize,need} from '../qa/common.mjs';

// Internal storage envelope, not a D01 wire DTO. Preserve all D01 validation
// rules for leaves/keys and the 32-level limit; bound the aggregate checkpoint
// separately to 2 MiB. Frozen 64 KiB D01 messages remain unchanged.
export function storageEnvelope(value) {
  function visit(v,depth) {
    need(depth<=32,'STORAGE_DEPTH_LIMIT');
    if(v===null || typeof v!=='object')return canonicalize(v);
    if(Array.isArray(v)) {
      need(Object.keys(v).length===v.length,'DENSE_ARRAY_REQUIRED');
      return '['+v.map(x=>visit(x,depth+1)).join(',')+']';
    }
    need(Object.getPrototypeOf(v)===Object.prototype,'PLAIN_JSON_REQUIRED');
    const keys=Object.keys(v).sort();need(Reflect.ownKeys(v).length===keys.length,'ENUMERABLE_JSON_REQUIRED');
    for(const k of keys) {
      need(!['__proto__','prototype','constructor'].includes(k),'UNSAFE_KEY');
      need(Object.hasOwn(Object.getOwnPropertyDescriptor(v,k),'value'),'DATA_PROPERTY_REQUIRED');
    }
    return '{'+keys.map(k=>canonicalize(k)+':'+visit(v[k],depth+1)).join(',')+'}';
  }
  const text=visit(value,0);need(Buffer.byteLength(text)<=2*1024*1024,'STORAGE_ENVELOPE_TOO_LARGE');return text;
}
