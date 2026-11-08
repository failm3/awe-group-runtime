import {createHash} from 'node:crypto';
export const VERSION='tr01/1.0.0';
export const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export function canonical(value){
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
 const text=JSON.stringify(value);ensure(text!==undefined,'TR_CANONICAL');return text;
}
export const digest=value=>'sha256:'+sha(canonical(value));
export const copy=value=>JSON.parse(JSON.stringify(value));
export function ensure(ok,code){if(!ok)throw Error(code);}
export function bounded(value,max=262144){
 const text=JSON.stringify(value);ensure(text!==undefined&&Buffer.byteLength(text)<=max,'TR_SIZE');
 const walk=(v,depth=0)=>{ensure(depth<24,'TR_DEPTH');if(v&&typeof v==='object'){
  ensure(Array.isArray(v)||Object.getPrototypeOf(v)===Object.prototype,'TR_OBJECT');
  for(const [k,x] of Object.entries(v)){ensure(!['__proto__','constructor','prototype'].includes(k),'TR_POISON_KEY');walk(x,depth+1);}
 }else ensure(v===null||['string','boolean'].includes(typeof v)||(typeof v==='number'&&Number.isFinite(v)),'TR_JSON');};
 walk(value);return JSON.parse(text);
}
export const id=v=>typeof v==='string'&&/^[\p{L}\p{N}_.:@/-]{1,160}$/u.test(v);
export const hash=v=>typeof v==='string'&&/^sha256:[a-f0-9]{64}$/.test(v);
export function httpsUrl(value){const u=new URL(value);ensure(u.protocol==='https:'&&!u.username&&!u.password&&!u.port,'TR_URL');return u;}
export function urlKey(value){
 const u=new URL(value);ensure(['https:','http:'].includes(u.protocol)&&!u.username&&!u.password,'TR_URL');
 return u.protocol+'//'+u.hostname.toLowerCase().replace(/^www\./,'')+(u.port?':'+u.port:'')+(u.pathname.replace(/\/$/,'')||'')+u.search+u.hash;
}
export function exactKeys(o,keys){ensure(o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).every(k=>keys.includes(k)),'TR_FIELDS');}
