import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../../contracts/index.mjs';
import {MODEL_POLICY} from '../../broker/schemas.mjs';
import {LOCAL_MODEL_QUIESCENCE,validateLocalModelQuiescence} from '../../coordinator/index.mjs';
import {syntheticProof} from './quiescence-fixtures.mjs';
test('local resource-only proof pins the current model and rejects malformed attestation',()=>{
  assert.equal(LOCAL_MODEL_QUIESCENCE.route_id,MODEL_POLICY.route_id);assert.equal(LOCAL_MODEL_QUIESCENCE.model_id,MODEL_POLICY.model);assert.equal(LOCAL_MODEL_QUIESCENCE.model_digest,MODEL_POLICY.digest);
  const scope={mission_id:'synthetic_mission',task_id:'head_control',worker_id:'e1_worker',fence:1,logical_request_id:'logical',attempt_id:'attempt'},request=syntheticProof(scope,'synthetic_project');
  validateLocalModelQuiescence(request,'synthetic_project');
  for(const mutate of [p=>p.attestor_id='worker',p=>p.resource_id='historical_e0',p=>p.route_id='cloud',p=>p.model_digest='0'.repeat(64),p=>p.effect_class='LOCAL_WRITE',p=>p.cancellation.status='REQUESTED',p=>p.idle_observations[1]=p.idle_observations[0],p=>p.runner_absence.status='UNKNOWN',p=>p.extra='bypass']){
    const bad=structuredClone(request);mutate(bad.proof);bad.proof_digest=digest(bad.proof);assert.throws(()=>validateLocalModelQuiescence(bad,'synthetic_project'),error=>error.code.startsWith('A2_QUIESCENCE_'));
  }
  assert.throws(()=>validateLocalModelQuiescence({...request,proof_digest:'sha256:'+'0'.repeat(64)},'synthetic_project'),{code:'A2_QUIESCENCE_PROOF_DIGEST'});
});
