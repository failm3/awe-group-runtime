import {digest} from '../contracts/canonical.mjs';
import {validateHistory} from '../awe/context/protocol.mjs';
import {need,text} from './contracts.mjs';

// D05 protocol and immutable source IDs; no worker conversation in head history.
export function appendMessage(history,id,kind,value){
 text(value,8192);need(['user','assistant'].includes(kind),'AUTO01_MESSAGE_KIND');
 const next=[...history,{id,kind,text:value,critical:kind==='user'}];
 return validateHistory(next,[],[]);
}
export function headContext(record){
 const history=validateHistory(record.history,[],[]);
 return {history,original_request:record.original_request??null,draft:record.drafts.at(-1)?.content??null,spec:record.spec?.content??null,plan:record.plan?.content??null,
  results:Object.values(record.results).map(r=>({node_id:r.node_id,status:r.status,summary:r.summary,artifacts:r.artifacts})),
  failures:record.failures,questions:record.questions};
}
export function handoffFor({record,node,task,executor,inputs}){
 const requirementIds=new Set(node.requirement_ids);
 const handoff={version:'auto01/1',session_id:record.id,project_id:record.project_id,task_id:task.id,
  spec:record.spec.ref,plan_hash:record.plan.hash,node_hash:digest(node),node_id:node.id,
  revision:task.revision,fence:task.fence,executor_id:executor.id,capability:node.capability,
  instructions:node.instructions,requirements:record.spec.content.requirements.filter(r=>requirementIds.has(r.id)),
  constraints:record.spec.content.constraints,resources:record.spec.content.resources,
  completion_criteria:record.spec.content.completion_criteria.filter(c=>c.requirement_ids.some(id=>requirementIds.has(id))),inputs,deliverable:node.deliverable,
  limits:{max_output_bytes:16384,max_attempts:1,network:false,physical_decision:'DENY'},trust:'SCOPED_MOCK_INPUT'};
 need(Buffer.byteLength(JSON.stringify(handoff))<=24576,'AUTO01_CONTEXT_LIMIT');return handoff;
}
