import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../../contracts/index.mjs';
import {admissionPort} from '../../coordinator/admission.mjs';
import {createCoordinator,validateCloudBudgetProvision,validateCloudTaskPolicy} from '../../coordinator/index.mjs';
import {makeBridge,publicationFixture} from '../coordinator/helpers.mjs';
import {ledgerFixture,syntheticFunding} from './fixtures.mjs';

test('cloud routes require explicit versioned owner-bound policy; local remains default',async()=>{
  const source=publicationFixture({project_id:'prj_cloud_policy',task_count:1,llm:true}),policy={budget_cap_micros:'0',quota_cap:2,max_parallel:1,resource_limits:{},capabilities:{}};
  const local=makeBridge([source],policy),payload=await admissionPort(local.bridge)({mission_id:source.spec.mission_id},local.context);
  assert.deepEqual(payload.tasks[0].model_routes,['ollama.local.qwen3-4b-instruct']);assert.equal(payload.tasks[0].cloud_policy,undefined);
  const cloud=makeBridge([source],{...policy,capabilities:{'common.research':{model_routes:['router.cheap.chat.unfunded']}}});
  await assert.rejects(()=>admissionPort(cloud.bridge)({mission_id:source.spec.mission_id},cloud.context),{code:'A2_MODEL_ROUTE_POLICY'});
});
test('funding requires hard actual-charge and per-request cap proof; synthetic scope is explicit',()=>{
  const value=syntheticFunding(['prj_cloud_policy']);validateCloudBudgetProvision(value);
  for(const mutate of [v=>v.provider_limit_evidence.enforcement='QUOTED_BASE_PRICE',v=>v.provider_limit_evidence.request_hard_cap_supported=false,v=>v.grant.project_ids=['actual_issue3'],v=>v.grant.budget_cap_micros='121',v=>v.provider_limit_evidence.key_binding_id='different_key']){
    const copy=structuredClone(value);mutate(copy);copy.grant_digest=digest(copy.grant);copy.provider_limit_evidence_digest=digest(copy.provider_limit_evidence);assert.throws(()=>validateCloudBudgetProvision(copy));
  }
});
test('host-only budget installation cannot be minted with an ordinary JSON capability',async()=>{
  const db={kind:'NATIVE_POSTGRESQL_PSQL_SESSION',role:'coordinator',command(){throw new Error('unexpected');},provisionCloudBudget(){throw new Error('unexpected');}},coordinator=createCoordinator({db,project_id:'prj_cloud_policy',cloudBudgetAuthority:{kind:'TRUSTED_CLOUD_BUDGET_AUTHORITY'}});
  await assert.rejects(()=>coordinator.provisionCloudBudget(syntheticFunding(['prj_cloud_policy']),{}),{code:'A2_CLOUD_HOST_AUTH_REQUIRED'});
});
test('task policy freezes source snapshot, authenticated mission grant and key binding',()=>{
  const f=ledgerFixture(),source=f.sources[0],policy=f.policyFor(source).capabilities['common.research'].cloud_policy;
  validateCloudTaskPolicy(policy,{grant_digest:digest(source.grant),model_routes:[f.quote.route_id]});
  for(const mutate of [p=>p.owner_grant_digest=digest({forged:true}),p=>p.routes[0].snapshot.sources[0].coefficient.numerator='999',p=>p.routes[0].route_id='router.cheap.chat.other']){
    const copy=structuredClone(policy);mutate(copy);assert.throws(()=>validateCloudTaskPolicy(copy,{grant_digest:digest(source.grant),model_routes:[f.quote.route_id]}));
  }
});
