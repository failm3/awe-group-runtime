import {randomBytes} from 'node:crypto';
import {digest} from '../../contracts/index.mjs';
import {cloudQuote} from '../../cloud/registry.mjs';
import {syntheticCatalog} from '../cloud/fixtures.mjs';
import {publicationFixture,makeBridge,descriptor,resultFor} from '../coordinator/helpers.mjs';
import {createCoordinator,createPsqlSession,createCloudBudgetAuthority} from '../../coordinator/index.mjs';

export const unique = label => label + '_' + randomBytes(5).toString('hex');
export function syntheticFunding(project_ids, {key_binding_id=unique('synthetic_cloud'), owner_id='id_owner', budget_cap_micros='120',per_attempt_cap_micros='40',attempts_cap='8',lifetime_ms=600000}={}) {
  const issued_at=new Date(Date.now()-1000).toISOString(),expires_at=new Date(Date.now()+lifetime_ms).toISOString();
  const grant={schema:'awe.e1.cloud-funding-grant/1',budget_group_id:'router.cheap.shared/1',key_binding_id,owner_id,owner_grant_digest:digest({label:'EXPLICIT_SYNTHETIC_OWNER_FUNDING',key_binding_id}),project_ids,issued_at,expires_at,budget_cap_micros,per_attempt_cap_micros,attempts_cap,evidence_mode:'EXPLICIT_SYNTHETIC',funding_ref:'synthetic:bounded-test-only'};
  const provider_limit_evidence={schema:'awe.e1.provider-hard-charge-limit/1',provider:'router.cheap',key_binding_id,account_binding_digest:digest({label:'EXPLICIT_SYNTHETIC_ACCOUNT',key_binding_id}),currency:'USD',enforcement:'HARD_ACTUAL_CHARGE',request_hard_cap_supported:true,actual_charge_cap_micros:budget_cap_micros,max_request_actual_charge_micros:per_attempt_cap_micros,evidence_mode:'EXPLICIT_SYNTHETIC',limit_ref:'synthetic:fake-provider-hard-charge-limit',issued_at,expires_at};
  return {grant,grant_digest:digest(grant),provider_limit_evidence,provider_limit_evidence_digest:digest(provider_limit_evidence)};
}

/** Explicit fake key/funding/proof. No provider transport or real key exists. */
export function ledgerFixture({projects=1,budget_cap_micros='120',per_attempt_cap_micros='40',attempts_cap='8',lifetime_ms=600000}={}) {
  const sources=Array.from({length:projects},()=>publicationFixture({project_id:unique('prj_cloud'),task_count:1,task_cost:'10000',llm:true,lifetime_ms}));
  const funding=syntheticFunding(sources.map(source=>source.spec.project_id),{owner_id:sources[0].spec.owner_id,budget_cap_micros,per_attempt_cap_micros,attempts_cap,lifetime_ms});
  const catalog=syntheticCatalog();catalog.observed_at=new Date(Date.now()-1000).toISOString();catalog.expires_at=new Date(Date.now()+lifetime_ms).toISOString();
  const quote=cloudQuote({catalog,route_id:catalog.routes[0].route_id,max_input_tokens:30,max_output_tokens:10,now:new Date().toISOString()});
  const host_context=Object.freeze({});
  const authority=createCloudBudgetAuthority({authenticateHost:context=>context===host_context?{role:'HOST_COORDINATOR',principal_id:'synthetic_host'}:null,verifyOwnerFunding:({grant,grant_digest})=>grant.evidence_mode==='EXPLICIT_SYNTHETIC'&&grant_digest===funding.grant_digest,verifyProviderLimit:({evidence,evidence_digest})=>evidence.evidence_mode==='EXPLICIT_SYNTHETIC'&&evidence_digest===funding.provider_limit_evidence_digest});
  const policyFor=source=>({budget_cap_micros:'20000',quota_cap:20,max_parallel:2,resource_limits:{cpu:2},capabilities:{'common.research':{resource_keys:['cpu'],max_claims:2,model_routes:[quote.route_id],cloud_policy:{schema:'awe.e1.cloud-task-policy/1',key_binding_id:funding.grant.key_binding_id,budget_group_id:'router.cheap.shared/1',funding_grant_digest:funding.grant_digest,owner_grant_digest:digest(source.grant),routes:[{route_id:quote.route_id,snapshot_digest:quote.route_snapshot_digest,snapshot:quote.route_snapshot}]}}}});
  const opened=[];
  async function open(index=0,{role='coordinator'}={}) {
    const source=sources[index],db=await createPsqlSession(descriptor(),{role}),{bridge,context}=makeBridge([source],policyFor(source));
    const coordinator=createCoordinator({db,admission:bridge,project_id:source.spec.project_id,cloudBudgetAuthority:authority});
    const rt={source,db,coordinator,context,admit:()=>coordinator.admit({mission_id:source.spec.mission_id},context)};opened.push(rt);return rt;
  }
  async function fund(rt) {return rt.coordinator.provisionCloudBudget(funding,host_context);}
  async function claim(rt,{worker_id='e1_worker1',lease_ms=30000}={}) {return rt.coordinator.claim({mission_id:rt.source.spec.mission_id,worker_id,capabilities:['common.research'],lease_ms});}
  function scope(claim) {return {mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence,logical_request_id:unique('cloud_logical'),attempt_id:unique('cloud_attempt'),capability_id:'common.research',capability_version:'1.0.0',route_id:quote.route_id,reserve_micros:Number(quote.reserve_micros),quota_units:1,request_hash:digest({label:'EXPLICIT_SYNTHETIC_REQUEST',claim}),cloud:{route_snapshot_digest:quote.route_snapshot_digest,quote_digest:quote.quote_digest,input_tokens_bound:30,cached_input_tokens_bound:30,output_tokens_bound:10,worst_case_micros:quote.reserve_micros,request_charge_cap_micros:quote.reserve_micros}};}
  function settlement(scope,{actual_charged_micros='16',provider_request_id=unique('fake_provider_request')}={}) {return {...scope,actual_cost_micros:Number(actual_charged_micros),provider_ref:provider_request_id,usage:{input_tokens:12,cached_input_tokens:3,output_tokens:4,wire_attempts:1},cloud:{route_snapshot_digest:quote.route_snapshot_digest,quote_digest:quote.quote_digest,provider_request_id,source_id:'synthetic_source',actual_charged_micros,base_cost_micros:'10',source_coefficient:{numerator:'5',denominator:'3'},source_factor_ref:'synthetic_source',source_factor_digest:catalog.routes[0].sources[0].price_evidence_digest,charge_evidence_digest:digest({label:'EXPLICIT_SYNTHETIC_FAKE_PROVIDER_CHARGED_COST',provider_request_id,actual_charged_micros}),charge_evidence_label:'EXPLICIT_SYNTHETIC_FAKE_PROVIDER_CHARGED_COST'}};}
  return {sources,funding,catalog,quote,host_context,authority,policyFor,open,fund,claim,scope,settlement,async close(){await Promise.allSettled(opened.map(rt=>rt.db.close()));}};
}
export {descriptor,resultFor};
