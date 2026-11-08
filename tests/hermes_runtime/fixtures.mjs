import {mkdirSync,mkdtempSync} from 'node:fs';
import {join} from 'node:path';
import {runtimeFixture} from '../runtime/fixtures.mjs';
import {createHermesRuntime,planHash} from '../../awe/hermes_runtime/adapter.mjs';
import {openJournal} from '../../awe/hermes_runtime/journal.mjs';
import {createSyntheticTransport} from '../../awe/hermes_runtime/synthetic.mjs';
import {createD03ReadPort} from '../../awe/hermes_runtime/d03-port.mjs';
import {sourceRoot,configHash,manifestHash} from '../../awe/hermes_runtime/profile.mjs';
import {digest,copy,need} from '../../awe/hermes_runtime/protocol.mjs';
export async function fixture(t,options={}) {
 const f=await runtimeFixture(),root=join(sourceRoot,'RT-01/sandbox/tests');mkdirSync(root,{recursive:true});
 const dir=mkdtempSync(join(root,'case-')),path=join(dir,'journal.jsonl');
 let journal=openJournal(path);t.after(()=>{journal.close();});
 const synthetic=createSyntheticTransport(options.transport),session=Object.freeze({});
 const control={revoked:false,modelLive:true,toolLive:true,badContext:false,resultLost:false,admissionLost:false};
 const records=new Map(),counts={begin:0,result:0,cancel:0};
 const attempts={async begin(command){counts.begin++;need(!records.has(command.attempt_id),'D09_DUPLICATE');records.set(command.attempt_id,copy(command));
  need(!control.admissionLost,'D09_ACK_LOST');return {attempt_id:command.attempt_id,physical_decision:'DENY'};},
 async result(){counts.result++;need(!control.resultLost,'D09_RESULT_ACK_LOST');return {physical_decision:'DENY'};},
 async cancel(){counts.cancel++;return {physical_decision:'DENY'};}};
 const state=createD03ReadPort({service:f.h.service,reader:f.h.state});
 const read=state.read;let stateTransform=s=>s;
 const args={state:{read:scope=>stateTransform(read(scope))},security:{authorizeLaunch:r=>r.actor_id==='act_worker'&&!control.revoked,current:()=>!control.revoked,
  authenticate:(s,r)=>s===session&&r.actor_id==='act_worker'},context:{read:()=>control.badContext?'corrupted':'AWE synthetic context'},
  artifacts:{verify:()=>true},models:{check:()=>control.modelLive},tools:{check:()=>control.toolLive},attempts,journal,transport:options.process??synthetic.api,clock:f.h.now,supervisor:'act_supervisor',timeoutMs:options.timeoutMs??30};
 let host=createHermesRuntime(args);
 const request=(run='run_parent',changes={})=>{
  const g=f.grant(run,{config_hash:configHash,manifest_hash:manifestHash,max_children:2,max_physical_attempts:5});
  const req={version:'rt01/1',grant:g,actor_id:'act_worker',child_id:'child_'+run,
   context:{project_id:g.scope.project_id,task_id:g.scope.task_id,revision:1,readonly:true,hash:digest({text:'AWE synthetic context'}),artifact_ref:digest({context:'synthetic'})},
   model:{id:'synthetic_model',revision:'rev_one',route_id:'synthetic_route',route_revision:'route_one'},tools:[{id:f.tool.id,digest:f.tool.digest}],
   admission:{project_id:g.scope.project_id,task_id:g.scope.task_id,operation_id:'op_effect_'+run,attempt_id:'attempt_'+run,effect_slot:'slot_'+run,approval_id:'approval_'+run,
    grant_id:'grant_'+run,idempotency_key:'key_'+run,plan_hash:digest({}),payload_hash:digest({text:'AWE synthetic context'}),reserve_micros:'0'},runtime_pin:read(g.scope).runtime_pin,...changes};
  req.admission.plan_hash=planHash(req);return copy(req);
 };
 const api={...f,args,dir,path,synthetic,counts,control,session,request,
  get host(){return host;},get journal(){return journal;},
  launch:(r=request())=>host.launchChild(JSON.stringify(r)),
  child:(run='run_child',changes={})=>{const r=request(run);r.grant={...r.grant,parent_run_id:'run_parent',depth:1,max_children:0,max_physical_attempts:2,...changes};r.admission.plan_hash=planHash(r);return r;},
  emit:(kind='RESULT',payload={artifact_ref:digest({result:1}),artifact_hash:digest({text:'synthetic result'})},run='run_parent',changes={})=>synthetic.control.emit(synthetic.control.handle(run),kind,payload,changes),
  transform:fn=>{stateTransform=fn;},
  restart(){journal.close();journal=openJournal(path);args.journal=journal;host=createHermesRuntime(args);return host;}
 };return api;
}
