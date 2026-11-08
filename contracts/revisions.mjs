// Pure value checks only. Storage immutability/CAS belong to D-03.
export function validateSpecSuccessor(previous,next) {
 if(previous.spec.spec_id!==next.spec.spec_id) return {ok:false,reason:'SPEC_ID_CHANGED'};
 if(previous.spec.revision===next.spec.revision) {
   return previous.spec.content_hash===next.spec.content_hash?{ok:true,reason:'SAME_REVISION'}:{ok:false,reason:'IMMUTABLE_REVISION'};
 }
 if(next.spec.revision!==previous.spec.revision+1) return {ok:false,reason:'NON_SEQUENTIAL_REVISION'};
 const ref=next.supersedes;
 if(!ref||ref.spec_id!==previous.spec.spec_id||ref.revision!==previous.spec.revision||ref.content_hash!==previous.spec.content_hash||next.spec.content_hash===previous.spec.content_hash) return {ok:false,reason:'SUPERSESSION_REQUIRED'};
 return {ok:true,reason:'NEW_REVISION_REQUIRES_NEW_QA'};
}
export function approvalBindingMatches(approval,action) {
 return approval.action===action.action&&approval.resource===action.resource&&approval.payload_hash===action.payload_hash
   &&approval.scope.project_id===action.scope.project_id&&approval.scope.task_id===action.scope.task_id&&approval.scope.operation_id===action.scope.operation_id
   &&approval.spec.spec_id===action.spec.spec_id&&approval.spec.revision===action.spec.revision&&approval.spec.content_hash===action.spec.content_hash
   &&approval.policy_revision===action.policy_revision;
}
