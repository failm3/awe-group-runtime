import {digest} from '../../contracts/index.mjs';
import {MODEL_POLICY} from '../../broker/schemas.mjs';
import {LOCAL_MODEL_QUIESCENCE} from '../../coordinator/index.mjs';
import {publicationFixture,runtime,id} from './helpers.mjs';
// Explicit synthetic operator attestations for boundary tests, NOT observations
// of Ollama and never usable as evidence for an actual model attempt.
export function syntheticProof(scope,project_id,{age_ms=0}={}){
  const base=Date.now()+10-age_ms,at=offset=>new Date(base+offset).toISOString();
  const ref=(kind,schema,status,offset)=>({schema,ref:'artifact:synthetic-quiescence/'+kind,digest:digest({kind,attempt_id:scope.attempt_id,synthetic:true}),observed_at:at(offset),status});
  const proof={...LOCAL_MODEL_QUIESCENCE,project_id,mission_id:scope.mission_id,task_id:scope.task_id,logical_request_id:scope.logical_request_id,attempt_id:scope.attempt_id,worker_id:scope.worker_id,fence:String(scope.fence),effect_class:'NONE',observed_at:at(1100),proof_ref:'artifact:synthetic-quiescence/operator-attestation',
    cancellation:ref('cancel','awe.e1.local-cancel-proof-ref/1','COMPLETED',0),
    idle_observations:[ref('idle-one','awe.e1.local-idle-proof-ref/1','IDLE',10),ref('idle-two','awe.e1.local-idle-proof-ref/1','IDLE',1020)],
    runner_absence:ref('runner-absence','awe.e1.local-runner-absence-proof-ref/1','ABSENT',1050)};
  return {...scope,proof,proof_digest:digest(proof)};
}
export async function unknownFixture(options={}){
  const source=publicationFixture({project_id:id('quiesce_project'),task_count:1,llm:true,...options}),rt=await runtime([source]);
  await rt.admitAll();const claim=await rt.coordinator.claim({worker_id:'e1_worker',capabilities:['common.research'],lease_ms:3000});
  const scope={mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence,logical_request_id:id('logical'),attempt_id:id('attempt')};
  await rt.coordinator.reserve({...scope,capability_id:'common.research',capability_version:'1.0.0',route_id:MODEL_POLICY.route_id,reserve_micros:options.task_cost??'0',quota_units:1,request_hash:digest({synthetic_quiescence_test:true})});await rt.coordinator.markSending(scope);await rt.coordinator.unknown({...scope,reason:'SYNTHETIC_BOUNDARY_TEST_NO_PROVIDER_CALL'});
  return {source,rt,scope,request:syntheticProof(scope,source.spec.project_id)};
}
