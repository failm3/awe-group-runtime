import {readFileSync} from 'node:fs';
import {canonicalize} from './canonical.mjs';
const catalog=JSON.parse(readFileSync(new URL('./v1/catalog.json',import.meta.url)));
const documents=new Map(['common',...catalog.schemas].map(name=>[name+'.schema.json',JSON.parse(readFileSync(new URL('./v1/'+name+'.schema.json',import.meta.url)))]));
export const supportedSchemas=Object.freeze([...catalog.schemas]);
const keywords=new Set(['$schema','$id','$defs','$ref','type','properties','required','additionalProperties','const','enum','oneOf','items','minItems','maxItems','uniqueItems','minimum','maximum','minLength','maxLength','pattern','format']);
function resolve(reference) {
  const [file,fragment='']=reference.split('#');
  let schema=documents.get(file);
  if(!schema) throw new Error('UNRESOLVED_LOCAL_REF '+reference);
  if(fragment) for(const token of fragment.slice(1).split('/')) schema=schema?.[token.replaceAll('~1','/').replaceAll('~0','~')];
  if(!schema) throw new Error('UNRESOLVED_LOCAL_REF '+reference);
  return schema;
}
export function inspectSchemas() {
  const errors=[];
  function inspect(s,path) {
    for(const key of Object.keys(s)) if(!keywords.has(key)) errors.push(path+': unsupported '+key);
    if(s.$ref) { try {resolve(s.$ref);} catch(e) {errors.push(e.message);} }
    for(const key of ['properties','$defs']) for(const [name,child] of Object.entries(s[key]??{})) inspect(child,path+'/'+key+'/'+name);
    if(s.items) inspect(s.items,path+'/items');
    for(const [i,child] of (s.oneOf??[]).entries()) inspect(child,path+'/oneOf/'+i);
  }
  for(const [name,s] of documents) inspect(s,name);
  return errors;
}
export function validateShape(name,value) {
  if(!supportedSchemas.includes(name)) return ['UNKNOWN_CONTRACT'];
  try {canonicalize(value);} catch(e) {return ['INVALID_JSON:'+e.message];}
  const errors=[];
  function walk(s,v,path,out) {
    if(s.$ref) return walk(resolve(s.$ref),v,path,out);
    if(s.oneOf) {
      const matched=s.oneOf.filter(branch=>{const local=[];walk(branch,v,path,local);return local.length===0;}).length;
      if(matched!==1) out.push(path+':ONE_OF');
    }
    if(Object.hasOwn(s,'const')&&v!==s.const) out.push(path+':CONST');
    if(s.enum&&!s.enum.includes(v)) out.push(path+':ENUM');
    if(s.type) {
      const matches=s.type==='null'?v===null:s.type==='array'?Array.isArray(v):s.type==='object'?v!==null&&typeof v==='object'&&!Array.isArray(v):s.type==='integer'?Number.isSafeInteger(v):typeof v===s.type;
      if(!matches) {out.push(path+':TYPE');return;}
    }
    if(s.type==='object') {
      for(const key of s.required??[]) if(!Object.hasOwn(v,key)) out.push(path+'/'+key+':REQUIRED');
      for(const [key,child] of Object.entries(v)) {
        if(s.properties?.[key]) walk(s.properties[key],child,path+'/'+key,out);
        else if(s.additionalProperties===false) out.push(path+'/'+key+':UNKNOWN_FIELD');
      }
    }
    if(s.type==='array') {
      if(v.length<(s.minItems??0)||v.length>(s.maxItems??Infinity)) out.push(path+':ITEM_COUNT');
      if(s.uniqueItems&&new Set(v.map(x=>canonicalize(x))).size!==v.length) out.push(path+':DUPLICATE');
      v.forEach((x,i)=>walk(s.items,x,path+'/'+i,out));
    }
    if(typeof v==='string') {
      const length=Array.from(v).length;
      if(length<(s.minLength??0)||length>(s.maxLength??Infinity)) out.push(path+':LENGTH');
      if(s.pattern&&!new RegExp(s.pattern,'u').test(v)) out.push(path+':PATTERN');
      if(s.format==='date-time'&&(!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[.]\d{3}Z$/.test(v)||!Number.isFinite(Date.parse(v))||new Date(v).toISOString()!==v)) out.push(path+':UTC_TIMESTAMP');
    }
    if(typeof v==='number'&&(v<(s.minimum??-Infinity)||v>(s.maximum??Infinity))) out.push(path+':RANGE');
  }
  walk(documents.get(name+'.schema.json'),value,'$',errors);
  return errors;
}
