import {canonicalize,digest} from '../contracts/index.mjs';
import {check} from './errors.mjs';

export const LOCAL_MODEL_QUIESCENCE=Object.freeze({
  schema:'awe.e1.local-model-quiescence/1',resource_id:'awe_e1_a2a3_20261108',
  route_id:'ollama.local.qwen3-4b-instruct',model_id:'qwen3:4b-instruct',
  model_digest:'0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0',
  attestor_id:'e1_local_operator',statement:'PHYSICALLY_QUIESCENT_OUTCOME_STILL_UNKNOWN'
});
const fields=['schema','resource_id','project_id','mission_id','task_id','logical_request_id','attempt_id','worker_id','fence','route_id','model_id','model_digest','effect_class','attestor_id','observed_at','proof_ref','cancellation','idle_observations','runner_absence','statement'];
const exact=(value,keys)=>check(value&&Object.keys(value).sort().join(',')===[...keys].sort().join(','),'A2_QUIESCENCE_PROOF_SCHEMA');
const ref=value=>typeof value==='string'&&/^artifact:[a-z][a-z0-9._/-]{0,127}$/.test(value);
const hash=value=>typeof value==='string'&&/^sha256:[a-f0-9]{64}$/.test(value);
const time=value=>{check(typeof value==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value,'A2_QUIESCENCE_PROOF_TIME');return Date.parse(value);};

/** This validates an operator attestation, not provider state. The host must
 * independently read/verify the referenced evidence before calling this method.
 * The worker/broker RPC surface deliberately has no quiescence operation.
 */
export function validateLocalModelQuiescence(request,project_id) {
  canonicalize(request.proof);const proof=request.proof;exact(proof,fields);
  for(const [key,value] of Object.entries(LOCAL_MODEL_QUIESCENCE))check(proof[key]===value,'A2_QUIESCENCE_PROOF_PIN');
  check(proof.effect_class==='NONE'&&proof.project_id===project_id,'A2_QUIESCENCE_PROOF_SCOPE');
  for(const key of ['mission_id','task_id','logical_request_id','attempt_id','worker_id'])check(proof[key]===request[key],'A2_QUIESCENCE_PROOF_SCOPE');
  check(typeof proof.fence==='string'&&/^[1-9][0-9]{0,15}$/.test(proof.fence)&&proof.fence===String(request.fence),'A2_QUIESCENCE_PROOF_SCOPE');
  check(ref(proof.proof_ref)&&hash(request.proof_digest)&&request.proof_digest===digest(proof),'A2_QUIESCENCE_PROOF_DIGEST');
  const observed=time(proof.observed_at);
  function evidence(item,schema,status) {
    exact(item,['schema','ref','digest','observed_at','status']);check(item.schema===schema&&item.status===status&&ref(item.ref)&&hash(item.digest),'A2_QUIESCENCE_EVIDENCE_REF');return time(item.observed_at);
  }
  const cancelled=evidence(proof.cancellation,'awe.e1.local-cancel-proof-ref/1','COMPLETED');
  check(Array.isArray(proof.idle_observations)&&proof.idle_observations.length===2,'A2_QUIESCENCE_EVIDENCE_REF');
  const first=evidence(proof.idle_observations[0],'awe.e1.local-idle-proof-ref/1','IDLE'),second=evidence(proof.idle_observations[1],'awe.e1.local-idle-proof-ref/1','IDLE');
  const absent=evidence(proof.runner_absence,'awe.e1.local-runner-absence-proof-ref/1','ABSENT');
  check(cancelled<=first&&first+1000<=second&&cancelled<=absent&&Math.max(second,absent)<=observed,'A2_QUIESCENCE_PROOF_TIME');
  const references=[proof.cancellation,...proof.idle_observations,proof.runner_absence];
  check(new Set(references.map(item=>item.ref)).size===4&&new Set(references.map(item=>item.digest)).size===4,'A2_QUIESCENCE_EVIDENCE_REF');
  check(Buffer.byteLength(canonicalize(proof))<=8192,'A2_QUIESCENCE_PROOF_SIZE');
  return proof;
}
