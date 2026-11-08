import {canonicalize,digest,parseIntent,copy,freeze,requireKeys,need,id,hash,micros,integer} from './common.mjs';
import {RISKS} from './authority.mjs';
import {relativePath} from './isolation.mjs';
import {FIXED_CODE_DIGEST} from './synthetic-executor.mjs';
import {LOCAL_PROFILE,validateLocalManifest,validateLocalInput} from './local-reviewed.mjs';
export const INPUT_SCHEMA=Object.freeze({type:'object',required:['text'],properties:{text:{type:'string',maxLength:4096},path:{type:'string'},url:{type:'string'}},additionalProperties:false});
export function createPinnedToolRegistry({verifier}){
 const tools=new Map();
 const key=m=>digest([m.project_id,m.tool_id,m.version]);
 return Object.freeze({
  control:Object.freeze({register(identity,peer,text){const m=parseIntent(text);
   const local=m.implementation===LOCAL_PROFILE;
   requireKeys(m,['v','project_id','tool_id','version','code_digest','schema_hash','risk','resources','paths','domains','cost_micros','max_input_bytes','max_output_bytes','implementation',...(local?['local_binding']:[])]);
   verifier.authenticate(identity,peer,m.project_id,'REGISTRY');
   need(m.v==='sec01.tool.v1'&&(local||m.implementation==='FIXED_SYNTHETIC_DIGEST'),'TOOL_IMPLEMENTATION_DENIED');
   id(m.project_id);id(m.tool_id);id(m.version);hash(m.code_digest);
   if(local)validateLocalManifest(m);else {need(m.code_digest===FIXED_CODE_DIGEST,'CODE_PIN_MISMATCH');need(m.schema_hash===digest(INPUT_SCHEMA),'SCHEMA_PIN_MISMATCH');}
   need(RISKS.includes(m.risk),'RISK_INVALID');micros(m.cost_micros);integer(m.max_input_bytes,1);integer(m.max_output_bytes,1);
   need(m.max_input_bytes<=8192&&m.max_output_bytes<=8192,'TOOL_LIMIT_INVALID');
   for(const list of [m.resources,m.paths,m.domains])need(Array.isArray(list)&&list.length<=32&&new Set(list).size===list.length,'TOOL_LIST_INVALID');
   need(m.resources.length>0,'RESOURCE_REQUIRED');m.resources.forEach(id);m.paths.forEach(relativePath);
   need(m.domains.every(d=>typeof d==='string'&&/^[a-z0-9]+(?:[.-][a-z0-9]+)+$/.test(d)&&!d.endsWith('.local')&&d!=='metadata.google.internal'),'DOMAIN_INVALID');
   need(m.domains.length===0||m.risk==='NETWORK','RISK_MISMATCH');
   need(!tools.has(key(m)),'TOOL_IMMUTABLE');
   const actor=verifier.authenticate(identity,peer,m.project_id,'REGISTRY');
   tools.set(key(m),{manifest:freeze(copy(m)),issuer:actor.principal_id,generation:actor.generation,revoked:false});return digest(m);
  },revoke(projectId,toolId,version){const r=tools.get(digest([projectId,toolId,version]));need(r,'TOOL_UNKNOWN');r.revoked=true;}}),
  resolve(r){const row=tools.get(digest([r.project_id,r.tool_id,r.tool_version]));need(row&&!row.revoked,'TOOL_UNKNOWN');
   const actor=verifier.principal(row.issuer,r.project_id);need(actor.generation===row.generation&&actor.role==='REGISTRY','TOOL_ISSUER_REVOKED');
   const m=row.manifest;need(r.manifest_hash===digest(m)&&r.tool_digest===m.code_digest&&r.schema_hash===m.schema_hash,'TOOL_PIN_MISMATCH');
   need(m.resources.includes(r.resource_id),'TOOL_RESOURCE_DENIED');return m;
  },
  validateInput(m,payload){if(m.implementation===LOCAL_PROFILE){validateLocalInput(payload,m);return;}need(payload&&typeof payload==='object'&&!Array.isArray(payload)&&Object.keys(payload).every(k=>['text','path','url'].includes(k))&&typeof payload.text==='string'&&payload.text.length<=4096,'TOOL_INPUT_INVALID');
   need(Buffer.byteLength(canonicalize(payload))<=m.max_input_bytes,'TOOL_INPUT_TOO_LARGE');}
 });
}
