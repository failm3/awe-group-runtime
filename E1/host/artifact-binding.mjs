import {digest,need,validateBoundValue} from '../contracts/index.mjs';

/** Check stored producer commitments before the independent semantic oracle. */
export function verifyPersistedTaskArtifact(task){
  need(task?.result&&typeof task.result_hash==='string'&&digest(task.result)===task.result_hash,'E1_STORED_RESULT_DIGEST');
  need(task.result.artifact_digest===digest(task.result.output),'E1_STORED_ARTIFACT_DIGEST');
  need(task.result.output_schema_digest===task.document.capability.output_schema.digest,'E1_STORED_SCHEMA_BINDING');
  need(digest(task.output_schema)===task.document.capability.output_schema.digest,'E1_STORED_SCHEMA_DIGEST');
  validateBoundValue(task.output_schema,task.result.output);
  return task.result.artifact_digest;
}

/** Global model-attempt PKs must remain unique across separate missions. */
export function modelRequestIds(mission_id,task_id){
  const binding=digest({mission_id,task_id}).slice(7);
  return {logical_request_id:'request_'+binding,attempt_id:'attempt_'+binding};
}
