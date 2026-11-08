import {ensure,exact,parse,digest,freeze,copy,identifier,CONTRACT,denial} from './protocol.mjs';
/** RT01 Tr01Port shape, with exact executable pins. Metadata discovery alone fails. */
export const createRt01ToolPort=tools=>Object.freeze({check:pins=>tools.check(pins)});
/** Host-to-worker facade: no factory, registration, admission or filesystem handles. */
export function bindAgentTools(tools,binding){
 exact(binding,['run_id','actor_id','project_id','task_id','pins']);
 ensure(['run_id','actor_id','project_id','task_id'].every(k=>identifier(binding[k]))&&tools.check(binding.pins),'TOOLS_AGENT_BINDING');
 const b=freeze(copy(binding));
 return Object.freeze({contract:CONTRACT,async execute(text){try{
  const q=parse(text);exact(q,['contract','operation_id','pin','input']);ensure(q.contract===CONTRACT&&identifier(q.operation_id),'TOOLS_CONTRACT');
  ensure(b.pins.some(p=>p.id===q.pin?.id&&p.digest===q.pin?.digest),'TOOLS_AGENT_PIN');
  return tools.execute(JSON.stringify({contract:CONTRACT,run_id:b.run_id,actor_id:b.actor_id,scope:{project_id:b.project_id,task_id:b.task_id,operation_id:q.operation_id},pin:q.pin,input:q.input,input_hash:digest(q.input)}));
 }catch(e){return denial(e);}}});
}
/** RT TOOL_PROPOSAL is a proposal. The host supplies the reviewed input and distinct
 * effect operation, then goes through the same existing admission port. */
export function matchRt01Proposal(proposal,command){
 exact(proposal,['operation_id','tool_id','tool_digest','input_hash']);
 ensure(proposal.operation_id===command.scope.operation_id&&proposal.tool_id===command.pin.id&&proposal.tool_digest===command.pin.digest&&proposal.input_hash===digest(command.input),'TOOLS_RT_PROPOSAL');return true;
}
/** Additive mapping of TR01 metadata proposal to an executable pin; never a permit. */
export function prepareExecutableReview(tools,binding,pin){
 ensure(binding?.contract==='tr01/1.0.0'&&binding.status==='BOUND_E0_ONLY'&&binding.physical_decision==='DENY'&&binding.runtime_dispatch===false,'TOOLS_TR_BINDING');
 const manifest=tools.manifest(pin),p=binding.proposal;
 ensure(p?.tool_id===pin.id&&p.artifact_digest===manifest.artifact_digest,'TOOLS_TR_ARTIFACT');
 return freeze({contract:'tr01-tools02-review/1',proposal:copy(p),pin:copy(pin),manifest,metadata_manifest_digest:p.manifest_digest,executable_manifest_digest:pin.digest,physical_decision:'DENY',execution_authority:false});
}
