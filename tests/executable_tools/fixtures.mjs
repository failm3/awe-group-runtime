import {createExecutableTools} from '../../awe/executable_tools/host.mjs';
import {digest,CONTRACT} from '../../awe/executable_tools/protocol.mjs';
export const scope={project_id:'prj_tools02',task_id:'task_tools02',operation_id:'op_control'};
export function fixture(options={}){
 const seen=new Set(),calls=[];let current=true;
 const admission={
  current:b=>current&&b.actor_id==='act_worker'&&b.run_id==='run_tools02'&&b.scope.project_id===scope.project_id&&b.scope.task_id===scope.task_id,
  async execute(binding,effect){if(!admission.current(binding))throw Error('TOOLS_FIXTURE_ADMISSION');
   const key=binding.scope.operation_id;if(seen.has(key))throw Error('TOOLS_OPERATION_REPLAY');seen.add(key);calls.push(binding);
   await effect();return {status:'COMMITTED',request_digest:digest(binding)};}
 };
 const reviewer={identity:'act_qa',review:async report=>({decision:'APPROVE_SYNTHETIC_TEMPLATE',report_digest:digest(report)})};
 const tools=createExecutableTools({scope,admission:options.admission??admission,reviewer:options.reviewer===undefined?reviewer:options.reviewer,generator_id:options.generator_id??'act_generator',limits:options.limits??{timeout_ms:5000,max_output_bytes:8192}});
 let sequence=0;
 return {tools,admission,reviewer,calls,revoke:()=>{current=false;},request(capability,input={},patch={}){
  const pin=tools.resolve(capability)[0];return {contract:CONTRACT,run_id:'run_tools02',actor_id:'act_worker',scope:{...scope,operation_id:'op_'+(++sequence)},pin,input,input_hash:digest(input),...patch};
 },execute(capability,input={},patch={}){return tools.execute(JSON.stringify(this.request(capability,input,patch)));}};
}
