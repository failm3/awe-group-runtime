import {copy,freeze,need,digest} from './protocol.mjs';
// Fixed deterministic synthetic producer. This does not import or launch Hermes.
export function createSyntheticTransport({fault=null,autoWork=false}={}) {
 const records=new Map();let launches=0;
 const get=handle=>{need(records.has(handle),'SYNTHETIC_HANDLE_LOST');return records.get(handle);};
 const emit=(handle,kind,payload={},changes={})=>{
  const r=get(handle),q=r.request,g=q.grant;
  const event={version:'rt01/1',project_id:g.scope.project_id,task_id:g.scope.task_id,actor_id:q.actor_id,run_id:g.run_id,child_id:q.child_id,
   seq:r.events.length+1,event_id:'evt_'+g.run_id+'_'+(r.events.length+1),kind,model:q.model,payload,...changes};
  r.events.push(JSON.stringify(event));return copy(event);
 };
 const broken=stage=>{if(fault===stage)throw Error('SYNTHETIC_'+stage.toUpperCase());if(fault==='hang_'+stage)return new Promise(()=>{});};
 const api=Object.freeze({mode:'RT01_SYNTHETIC_ONLY',
  async launchChild(request,bytes) {
   const handle='synthetic_'+request.grant.run_id;need(!records.has(handle),'SYNTHETIC_DUPLICATE');
   records.set(handle,{request:copy(request),events:[],bytes});launches++;
   await broken('launch');
   if(autoWork)emit(handle,'RESULT',{artifact_ref:digest({synthetic:true,bytes}),artifact_hash:digest({text:bytes})});return handle;
  },
  async streamEvents(handle,cursor){await broken('stream');return get(handle).events.filter(text=>!Number.isSafeInteger(JSON.parse(text).seq)||JSON.parse(text).seq>cursor);},
  async cancel(handle){await broken('cancel');emit(handle,'CANCELLED');return {accepted:true};},
  async reconcile(handle){await broken('reconcile');get(handle);return {connected:true};}
 });
 return {api,control:Object.freeze({emit,append:(handle,text)=>get(handle).events.push(text),
  inspect:()=>freeze({launches,physical_dispatches:0,handles:[...records.keys()]}),
  handle:runId=>'synthetic_'+runId,lose:handle=>records.delete(handle)})};
}
