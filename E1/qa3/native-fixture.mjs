import fs from 'node:fs';
import {randomBytes} from 'node:crypto';
import {digest} from '../contracts/index.mjs';
import {createMaintenanceMission} from '../broker/index.mjs';
import {createOfflineAuthority,createMissionIngress} from '../mission/ingress.mjs';
import {authorityPorts} from '../mission/authority.mjs';
import {createAdmissionBridge,createCoordinator,createPsqlSession,createCloudBudgetAuthority} from '../coordinator/index.mjs';
import {cloudQuote} from '../cloud/registry.mjs';
import {catalog} from './fixtures.mjs';

export const unique=prefix=>prefix+'_'+randomBytes(6).toString('hex');
export function nativeFixture({projects=1,total=600,per=150,attempts=8}={}){
 const now=new Date().toISOString(),until=new Date(Date.now()+600000).toISOString(),cat=catalog();cat.observed_at=now;cat.expires_at=until;
 const quote=cloudQuote({catalog:cat,route_id:cat.routes[0].route_id,max_input_tokens:100,max_output_tokens:100,now});
 const sources=Array.from({length:projects},()=>{
  const id=unique('prj_qa3'),base=createMaintenanceMission({now,suffix:'qa3_'+randomBytes(5).toString('hex')}),registry=structuredClone(base.registry),spec=structuredClone(base.spec),grant=structuredClone(base.grant),domain=structuredClone(base.domainManifest),plan=structuredClone(base.bootstrapPlan);
  for(const item of registry.entries)if(item.descriptor.executor_kind==='llm')item.cloud_routes=[{route_id:quote.route_id,route_version:quote.route_version}];
  spec.project_id=id;for(const fact of spec.facts_refs)fact.project_id=id;spec.budget={currency:'USD',amount_micros:'10000'};domain.project_id=id;spec.domain_manifest.digest=digest(domain);
  grant.project_id=id;grant.budget_cap=structuredClone(spec.budget);grant.spec_digest=digest(spec);
  plan.project_id=id;plan.spec_digest=digest(spec);plan.grant_digest=digest(grant);plan.budget=structuredClone(spec.budget);
  plan.tasks=[plan.tasks.find(task=>task.task_id==='head_control')];const task=plan.tasks[0];task.capability=registry.descriptors.find(cap=>cap.ref.capability_id==='e1.code.review').ref;task.budget=structuredClone(spec.budget);task.effect.project_id=id;task.criterion_ids=spec.criteria.map(x=>x.criterion_id);
  const principals=base.principals.map(p=>({...p,projects:[id]})),authority=createOfflineAuthority(principals),contexts=Object.fromEntries(principals.map(p=>[p.principal_id,authority.issueContext(p.principal_id,id)]));
  const ingress=createMissionIngress({authority,capabilities:registry.descriptors,domainManifests:[domain],projectId:id});ingress.mission.create({spec,grant},contexts.e1_owner);ingress.plan.propose({plan},contexts.e1_head);const validation=ingress.plan.validate({mission_id:spec.mission_id,plan_digest:digest(plan)},contexts.e1_coordinator);const publication=ingress.plan.publish({mission_id:spec.mission_id,plan_digest:digest(plan),validation_digest:validation.validation.digest},contexts.e1_coordinator);
  return {project:id,spec,grant,domain,plan,registry,principals,authority,contexts,validation:validation.validation,publication};
 });
 const key=unique('synthetic_qa3'),fundingGrant={schema:'awe.e1.cloud-funding-grant/1',budget_group_id:'router.cheap.shared/1',key_binding_id:key,owner_id:'e1_owner',project_ids:sources.map(x=>x.project),budget_cap_micros:String(total),per_attempt_cap_micros:String(per),attempts_cap:String(attempts),owner_grant_digest:digest({synthetic:'qa3-funding-owner',key}),evidence_mode:'EXPLICIT_SYNTHETIC',funding_ref:'synthetic:qa3-funding',issued_at:now,expires_at:until};
 const proof={schema:'awe.e1.provider-hard-charge-limit/1',provider:'router.cheap',key_binding_id:key,currency:'USD',enforcement:'HARD_ACTUAL_CHARGE',request_hard_cap_supported:true,evidence_mode:'EXPLICIT_SYNTHETIC',account_binding_digest:digest({synthetic:'qa3-isolated-account',key}),limit_ref:'synthetic:qa3-provider-limit',actual_charge_cap_micros:String(total),max_request_actual_charge_micros:String(per),issued_at:now,expires_at:until};
 const funding={grant:fundingGrant,grant_digest:digest(fundingGrant),provider_limit_evidence:proof,provider_limit_evidence_digest:digest(proof)},hostContext=Object.freeze({});
 const fundingAuthority=createCloudBudgetAuthority({authenticateHost:c=>c===hostContext?{role:'HOST_COORDINATOR',principal_id:'qa3_synthetic_host'}:null,verifyOwnerFunding:({grant_digest,grant})=>grant_digest===funding.grant_digest&&grant.evidence_mode==='EXPLICIT_SYNTHETIC',verifyProviderLimit:({evidence_digest,evidence})=>evidence_digest===funding.provider_limit_evidence_digest&&evidence.evidence_mode==='EXPLICIT_SYNTHETIC'});
 const opened=[];
 async function open(index=0,role='coordinator'){
  const source=sources[index],descriptor=JSON.parse(fs.readFileSync('.private/e1-resource.json','utf8')),db=await createPsqlSession(descriptor,{role});
  const policy={budget_cap_micros:20000,quota_cap:10,max_parallel:2,resource_limits:{qa3_model:2},capabilities:{'e1.code.review':{resource_keys:['qa3_model'],max_claims:1,model_routes:[quote.route_id],cloud_policy:{schema:'awe.e1.cloud-task-policy/1',budget_group_id:'router.cheap.shared/1',key_binding_id:key,funding_grant_digest:funding.grant_digest,owner_grant_digest:digest(source.grant),routes:[{route_id:quote.route_id,snapshot:quote.route_snapshot,snapshot_digest:quote.route_snapshot_digest}]}}}};
  const admission=createAdmissionBridge({authenticate:context=>authorityPorts(source.authority).verify(context),resolvePublication:()=>({spec:source.spec,grant:source.grant,plan:source.plan,publication:source.publication,validation:source.validation,capabilities:source.registry.descriptors,domainManifest:source.domain}),verifyGrant:({grant,spec})=>digest(grant)===digest(source.grant)&&digest(spec)===digest(source.spec),policy});
  const coordinator=createCoordinator({db,admission,project_id:source.project,cloudBudgetAuthority:fundingAuthority}),rt={source,db,coordinator,admit:()=>coordinator.admit({mission_id:source.spec.mission_id},source.contexts.e1_coordinator)};opened.push(rt);return rt;
 }
 const claim=rt=>rt.coordinator.claim({mission_id:rt.source.spec.mission_id,worker_id:'e1_worker',capabilities:['e1.code.review'],lease_ms:30000});
 const scope=claim=>({mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence,logical_request_id:unique('qa3_logical'),attempt_id:unique('qa3_attempt')});
 const reservation=scope=>({...scope,route_id:quote.route_id,capability_id:'e1.code.review',capability_version:'1.0.0',reserve_micros:Number(quote.reserve_micros),quota_units:1,request_hash:digest({synthetic:'qa3-native-request',scope}),cloud:{route_snapshot_digest:quote.route_snapshot_digest,quote_digest:quote.quote_digest,input_tokens_bound:100,cached_input_tokens_bound:100,output_tokens_bound:100,worst_case_micros:quote.reserve_micros,request_charge_cap_micros:quote.reserve_micros}});
 const settlement=scope=>{const id=unique('qa3_provider');return {...scope,actual_cost_micros:4,provider_ref:id,usage:{input_tokens:3,cached_input_tokens:1,output_tokens:2,wire_attempts:1},cloud:{route_snapshot_digest:quote.route_snapshot_digest,quote_digest:quote.quote_digest,provider_request_id:id,source_id:'qa3-source-a',actual_charged_micros:'4',base_cost_micros:'3',source_coefficient:{numerator:'3',denominator:'2'},source_factor_ref:'qa3-source-a',source_factor_digest:cat.routes[0].sources[0].price_evidence_digest,charge_evidence_digest:digest({synthetic:'qa3-fake-charge',id}),charge_evidence_label:'EXPLICIT_SYNTHETIC_FAKE_PROVIDER_CHARGED_COST'}};};
 const brokerPolicy=source=>({schema:'awe.e1.router-cheap.host-policy/1',budget_group_id:'router.cheap.shared/1',key_binding_id:key,project_id:source.project,mission_id:source.spec.mission_id,spec_digest:digest(source.spec),mission_grant_digest:digest(source.grant),catalog_digest:digest(cat),allowed_route_ids:[quote.route_id],issued_at:now,expires_at:until,total_cap_micros:String(total),per_attempt_cap_micros:String(per),max_attempts:Math.min(attempts,15),hard_cap:{kind:'OFFLINE_TEST_DOUBLE',evidence_digest:funding.provider_limit_evidence_digest,observed_at:now,expires_at:until,cap_micros:String(total)}});
 return {sources,key,cat,quote,funding,hostContext,open,claim,scope,reservation,settlement,brokerPolicy,fund:rt=>rt.coordinator.provisionCloudBudget(funding,hostContext),close:()=>Promise.allSettled(opened.map(x=>x.db.close()))};
}
