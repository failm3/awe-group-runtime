import {digest} from '../../contracts/canonical.mjs';
import {parseIntent,copy,freeze,requireKeys} from '../policy/json.mjs';
export {digest,parseIntent,copy,freeze};
export const need=(ok,code)=>{if(!ok)throw Error(code);};
export const exact=(v,keys)=>requireKeys(v,keys);
export const same=(a,b)=>digest(a)===digest(b);
export const hash=v=>need(typeof v==='string'&&/^sha256:[a-f0-9]{64}$/.test(v),'HASH_INVALID');
export const id=v=>need(typeof v==='string'&&/^[a-z][a-z0-9_-]{0,71}$/.test(v),'ID_INVALID');
export const uint=v=>need(Number.isSafeInteger(v)&&v>=0,'INTEGER_INVALID');
export const deny=code=>freeze({decision:'DENY',code,physical_decision:'DENY'});
export const terminal=new Set(['WORK_COMPLETED','FAILED','CANCELLED','OUTCOME_UNKNOWN']);
export function launchRequest(text) {
 const r=parseIntent(text);
 exact(r,['version','grant','actor_id','child_id','context','model','tools','admission','runtime_pin']);
 need(r.version==='rt01/1','VERSION_UNSUPPORTED');id(r.actor_id);id(r.child_id);
 exact(r.context,['project_id','task_id','revision','readonly','hash','artifact_ref']);
 id(r.context.project_id);id(r.context.task_id);uint(r.context.revision);hash(r.context.hash);hash(r.context.artifact_ref);
 need(r.context.readonly===true,'READONLY_CONTEXT_REQUIRED');
 exact(r.model,['id','revision','route_id','route_revision']);
 for(const v of Object.values(r.model))id(v);
 need(Array.isArray(r.tools)&&r.tools.length<=128,'TOOLS_INVALID');
 for(const t of r.tools){exact(t,['id','digest']);id(t.id);hash(t.digest);}
 need(new Set(r.tools.map(t=>t.id)).size===r.tools.length,'DUPLICATE_TOOL');
 exact(r.runtime_pin,['config_revision','fence','lease_epoch']);for(const n of Object.values(r.runtime_pin))uint(n);
 exact(r.admission,['project_id','task_id','operation_id','attempt_id','effect_slot','approval_id','grant_id','idempotency_key','plan_hash','payload_hash','reserve_micros']);
 for(const [k,v]of Object.entries(r.admission))if(k.endsWith('_hash'))hash(v);else if(k==='reserve_micros')need(typeof v==='string'&&/^(0|[1-9][0-9]{0,29})$/.test(v),'MICROS_INVALID');else id(v);
 return freeze(r);
}
export function eventRequest(text) {
 const e=parseIntent(text);exact(e,['version','project_id','task_id','actor_id','run_id','child_id','seq','event_id','kind','model','payload']);
 need(e.version==='rt01/1','VERSION_UNSUPPORTED');for(const k of ['project_id','task_id','actor_id','run_id','child_id','event_id'])id(e[k]);
 uint(e.seq);need(e.seq>0,'SEQUENCE_INVALID');
 need(['HEARTBEAT','RESULT','ERROR','CANCELLED','TOOL_PROPOSAL'].includes(e.kind),'EVENT_KIND_INVALID');
 return freeze(e);
}
export async function bounded(action,ms) {
 let timer;try{return await Promise.race([Promise.resolve().then(action),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('PORT_TIMEOUT')),ms);})]);}
 finally{clearTimeout(timer);}
}
