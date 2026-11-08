import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../contracts/index.mjs';
import {createCloudBudgetAuthority,cloudBudgetProvisionPort,validateCloudBudgetProvision,validateCloudTaskPolicy} from '../coordinator/cloud-policy.mjs';
import {NOW,clone} from './fixtures.mjs';
export function funding(){
 const grant={schema:'awe.e1.cloud-funding-grant/1',budget_group_id:'router.cheap.shared/1',key_binding_id:'synthetic_qa3_key',owner_id:'e1_owner',project_ids:['prj_qa3_synthetic'],budget_cap_micros:'1000',per_attempt_cap_micros:'700',attempts_cap:'2',owner_grant_digest:digest({synthetic:'qa3-owner-grant'}),evidence_mode:'EXPLICIT_SYNTHETIC',funding_ref:'synthetic:qa3-funding',issued_at:NOW,expires_at:'2026-11-08T13:00:00.000Z'};
 const proof={schema:'awe.e1.provider-hard-charge-limit/1',provider:'router.cheap',key_binding_id:grant.key_binding_id,currency:'USD',enforcement:'HARD_ACTUAL_CHARGE',request_hard_cap_supported:true,evidence_mode:'EXPLICIT_SYNTHETIC',account_binding_digest:digest({synthetic:'qa3-account'}),limit_ref:'synthetic:qa3-limit',actual_charge_cap_micros:'1000',max_request_actual_charge_micros:'700',issued_at:NOW,expires_at:grant.expires_at};
 return {grant,grant_digest:digest(grant),provider_limit_evidence:proof,provider_limit_evidence_digest:digest(proof)};
}
const repin=v=>{v.grant_digest=digest(v.grant);v.provider_limit_evidence_digest=digest(v.provider_limit_evidence);return v;};
test('QA3 JSON funding descriptions and forged authority objects cannot provision',async()=>{
 const request=funding();assert.equal(validateCloudBudgetProvision(request),request);
 for(const authority of [{kind:'TRUSTED_CLOUD_BUDGET_AUTHORITY'},null,{}])await assert.rejects(cloudBudgetProvisionPort(authority,request,{}),{code:'A2_CLOUD_HOST_AUTH_REQUIRED'});
});
test('QA3 authenticated funding requires both exact owner grant and verified hard provider charge cap',async()=>{
 const context=Object.freeze({}),request=funding();
 for(const [owner,cap] of [[false,true],[true,false],[false,false]]){
  const authority=createCloudBudgetAuthority({authenticateHost:async c=>c===context?{role:'HOST_COORDINATOR',principal_id:'e1_host'}:null,verifyOwnerFunding:async()=>owner,verifyProviderLimit:async()=>cap});
  await assert.rejects(cloudBudgetProvisionPort(authority,request,context));
  await assert.rejects(cloudBudgetProvisionPort(authority,request,{}),{code:'A2_CLOUD_HOST_AUTH_REQUIRED'});
 }
});
test('QA3 nominal base-priced or missing request cap never equals hard actual-charge proof',()=>{
 for(const mutation of [p=>p.enforcement='BASE_PRICE_LIMIT',p=>p.request_hard_cap_supported=false,p=>delete p.request_hard_cap_supported,p=>p.actual_charge_cap_micros='999',p=>p.max_request_actual_charge_micros='699',p=>p.key_binding_id='synthetic_wrong_key',p=>p.evidence_mode='AUTHENTICATED_HOST']){
  const v=funding();mutation(v.provider_limit_evidence);repin(v);assert.throws(()=>validateCloudBudgetProvision(v));
 }
});
test('QA3 funding prevents forged digests, impossible limits and synthetic-to-live scope substitution',()=>{
 for(const mutation of [v=>v.grant_digest=digest({wrong:1}),v=>v.provider_limit_evidence_digest=digest({wrong:1}),v=>v.grant.budget_cap_micros='0',v=>v.grant.per_attempt_cap_micros='1001',v=>v.grant.attempts_cap='0',v=>v.grant.project_ids=['prj_code_maintenance'],v=>v.grant.key_binding_id='real_key',v=>v.grant.funding_ref='live-looking-reference',v=>v.provider_limit_evidence.limit_ref='live-looking-reference',v=>v.grant.project_ids.push(v.grant.project_ids[0])]){
  const v=funding();mutation(v);if(!['grant_digest','provider_limit_evidence_digest'].some(k=>v[k]!==funding()[k]))repin(v);assert.throws(()=>validateCloudBudgetProvision(v));
 }
});
test('QA3 cloud task policy binds exact owner grant, allowed routes and immutable quote digest',()=>{
 const owner=digest({synthetic:'qa3-owner'}),snapshot={provider:'router.cheap',route_id:'router.cheap.chat.qa3-synthetic',reserve_micros:'700'};
 const value={schema:'awe.e1.cloud-task-policy/1',budget_group_id:'router.cheap.shared/1',key_binding_id:'synthetic_qa3_key',funding_grant_digest:funding().grant_digest,owner_grant_digest:owner,routes:[{route_id:snapshot.route_id,snapshot,snapshot_digest:digest(snapshot)}]};
 assert.deepEqual(validateCloudTaskPolicy(value,{grant_digest:owner,model_routes:[snapshot.route_id]}),value);
 for(const mutate of [v=>v.owner_grant_digest=digest({wrong:1}),v=>v.routes[0].snapshot.reserve_micros='0',v=>v.routes.push(clone(v.routes[0]))]){const v=clone(value);mutate(v);assert.throws(()=>validateCloudTaskPolicy(v,{grant_digest:owner,model_routes:[snapshot.route_id]}));}
 assert.throws(()=>validateCloudTaskPolicy(value,{grant_digest:owner,model_routes:['router.cheap.chat.other']}));
});
