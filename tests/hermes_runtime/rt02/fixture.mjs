import {fixture} from '../fixtures.mjs';
import {createExecutorAdapter,EXECUTION_CONTRACT,programManifest} from '../../../awe/hermes_runtime/executor-adapter.mjs';
import {digest} from '../../../awe/hermes_runtime/protocol.mjs';
import {planHash} from '../../../awe/hermes_runtime/adapter.mjs';
export async function executionFixture(t,{executor='javascript',program='sum',input={values:[1,2,3]},limits}={}){
 const f=await fixture(t),{transport,artifacts,...ports}=f.args;ports.timeoutMs=1000;
 const context=JSON.stringify({contract:'rt02.program/1',executor,program,input});ports.context={read:()=>context};
 let adapter=createExecutorAdapter(ports,{contract:EXECUTION_CONTRACT,...(limits?{limits}:{})});t.after(()=>adapter.close());
 const request=(run='run_parent')=>{
  const q=f.request(run),tool=programManifest(executor,program);q.grant.capabilities=[tool.tool_id];q.tools=[{id:tool.tool_id,digest:tool.digest}];
  q.context.hash=digest({text:context});q.admission.payload_hash=q.context.hash;q.admission.plan_hash=planHash(q);return q;
 };
 return {...f,ports,context,request,get adapter(){return adapter;},launch:(q=request())=>adapter.runtime.launchChild(JSON.stringify(q)),
  async restart(checkpoint){await adapter.close();f.restart();ports.journal=f.journal;adapter=createExecutorAdapter(ports,{contract:EXECUTION_CONTRACT,...(checkpoint?{startupCheckpoint:checkpoint}:{})});return adapter;}};
}
