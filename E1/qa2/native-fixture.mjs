import fs from 'node:fs';
import {randomUUID} from 'node:crypto';
import {digest,capabilityManifestDigest} from '../contracts/index.mjs';
import {createOfflineAuthority,createMissionIngress} from '../mission/ingress.mjs';
import {authorityPorts} from '../mission/authority.mjs';
import {createMaintenanceMission} from '../broker/index.mjs';
import {createAdmissionBridge,createCoordinator,createPsqlSession} from '../coordinator/index.mjs';

export const resource=JSON.parse(fs.readFileSync('.private/e1-resource.json','utf8'));
export const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
export function makeFixture({scenario='base',suffix=randomUUID().replaceAll('-','').slice(0,12),projectId,sharedRegistry,retryClaims=1,businessKey,effectLlm=false,budget=0,taskReserve=0,projectBudget=budget,quota=10,maxParallel=4}={}){
 const now=new Date().toISOString(),base=createMaintenanceMission({now,suffix:'qa2_'+suffix,...(sharedRegistry?{registry:sharedRegistry}:{})});
 const project=projectId??'prj_qa2_'+suffix;if(!/^prj_qa2_[a-f0-9]+$/.test(project))throw new Error('QA2 project namespace required');
 const capabilities=structuredClone(base.registry.descriptors);
 for(const cap of capabilities){if(cap.ref.capability_id==='e1.code.parse'){cap.max_attempts=retryClaims;if(scenario==='effect'){cap.effect_class='LOCAL_WRITE';cap.permissions.push('effect.local');if(effectLlm)cap.executor_kind='llm';}cap.ref.manifest_digest=capabilityManifestDigest(cap);}}
 const registry={...base.registry,descriptors:capabilities};
 const spec=structuredClone(base.spec),grant=structuredClone(base.grant),domainManifest=structuredClone(base.domainManifest),plan=structuredClone(base.bootstrapPlan);
 domainManifest.project_id=project;domainManifest.capabilities=capabilities.map(x=>x.ref);
 if(scenario==='reads')domainManifest.qa_rubric={rubric_id:'e1.qa2.concurrent_reads',digest:digest({version:1,checks:['schema','source_exact','scope','independent_qa','trace_interval']}),checks:['schema','source_exact','scope','independent_qa','trace_interval']};
 spec.project_id=project;spec.domain_manifest.digest=digest(domainManifest);spec.requested_capabilities=capabilities.map(x=>x.ref);
 for(const fact of spec.facts_refs)fact.project_id=project;
 spec.budget={currency:budget?'USD':'NONE',amount_micros:String(budget)};
 grant.project_id=project;grant.budget_cap=structuredClone(spec.budget);grant.allowed_capabilities=capabilities.map(x=>x.ref);
 if(scenario==='effect'){spec.max_actions=1;grant.max_actions=1;grant.permissions.push('effect.local');grant.allowed_effect_classes.push('LOCAL_WRITE');grant.destinations=['fake-provider:qa2-maintenance'];}
 const principals=base.principals.map(x=>({...x,projects:[project]}));
 for(const id of ['e1_worker_a','e1_worker_b'])principals.push({principal_id:id,subject_id:id,role:'EXECUTOR',projects:[project]});
 grant.allowed_principals=principals.map(x=>x.principal_id);grant.spec_digest=digest(spec);
 const sourceTask=structuredClone(plan.tasks.find(x=>x.task_id==='parse_source'));
 const headTask=structuredClone(plan.tasks.find(x=>x.task_id==='head_control'));
 function task(seed,id,deps=[]){
  const x=structuredClone(seed);x.capability=capabilities.find(c=>c.ref.capability_id===x.capability.capability_id).ref;x.retry.max_attempts=x.capability.capability_id==='e1.code.parse'?retryClaims:1;x.task_id=id;x.title='Independent QA2 '+id;x.criterion_ids=spec.criteria.map(x=>x.criterion_id);x.depends_on=deps;x.dependency_bindings=deps.map(task_id=>({task_id,output_schema:sourceTask.capability.output_schema}));x.budget={currency:spec.budget.currency,amount_micros:String(taskReserve)};x.effect={...x.effect,effect_id:'intent_'+id,project_id:project,task_id:id};x.qa={...x.qa,rubric_id:domainManifest.qa_rubric.rubric_id,rubric_digest:domainManifest.qa_rubric.digest,required_checks:domainManifest.qa_rubric.checks};return x;
 }
 if(scenario==='reads')plan.tasks=[task(sourceTask,'read_a'),task(sourceTask,'read_b'),task(sourceTask,'join',['read_a','read_b'])];
 else if(scenario==='models')plan.tasks=[task(headTask,'model_a'),task(headTask,'model_b')];
 else if(scenario==='effect')plan.tasks=[task(sourceTask,'canonical_effect')];
 else plan.tasks=[task(sourceTask,'parse_source'),task(headTask,'head_control')];
 for(const t of plan.tasks){t.effect.project_id=project;t.effect.payload_digest=digest(t.input);if(scenario==='effect')Object.assign(t.effect,{effect_class:'LOCAL_WRITE',permission:'effect.local',destination:'fake-provider:qa2-maintenance',business_key:businessKey??'qa2_business_'+suffix,max_actions:1});}
 plan.project_id=project;plan.spec_digest=digest(spec);plan.grant_digest=digest(grant);plan.budget={currency:spec.budget.currency,amount_micros:String(plan.tasks.reduce((n,t)=>n+taskReserve*t.retry.max_attempts,0))};
 const authority=createOfflineAuthority(principals);
 const contexts=Object.fromEntries(principals.map(p=>[p.principal_id,authority.issueContext(p.principal_id,project)]));
 const ingress=createMissionIngress({authority,capabilities,domainManifests:[domainManifest],projectId:project});
 ingress.mission.create({spec,grant},contexts.e1_owner);ingress.plan.propose({plan},contexts.e1_head);
 const validation=ingress.plan.validate({mission_id:spec.mission_id,plan_digest:digest(plan)},contexts.e1_coordinator);
 const publication=ingress.plan.publish({mission_id:spec.mission_id,plan_digest:digest(plan),validation_digest:validation.validation.digest},contexts.e1_coordinator);
 const policy={budget_cap_micros:projectBudget,quota_cap:quota,max_parallel:maxParallel,resource_limits:{qa_read:4,qa_model:2},capabilities:{'e1.code.parse':{resource_keys:['qa_read'],max_claims:retryClaims},'e1.head.plan':{resource_keys:['qa_model'],max_claims:1}}};
 const admission=createAdmissionBridge({authenticate:c=>authorityPorts(authority).verify(c),resolvePublication:()=>({spec,grant,plan,publication,validation:validation.validation,capabilities,domainManifest}),verifyGrant:({spec:s,grant:g})=>digest(s)===digest(spec)&&digest(g)===digest(grant),policy});
 return {project,spec,grant,domainManifest,plan,registry,originalRegistry:base.registry,source:base.source,rubric:base.rubric,principals,contexts,admission,authority,ingress,policy};
}
export async function connect(role='coordinator'){return createPsqlSession(resource,{role});}
export function coordinator(db,f){return createCoordinator({db,admission:f.admission,project_id:f.project});}
export const completedResult=(task,output={text:'Synthetic QA2 result'})=>{const result={output_schema_digest:task.capability.output_schema.digest,output};return{result,result_hash:digest(result)};};
export const completion=(claim,output)=>({mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence,...completedResult(claim.task,output)});
export function modelAttempt(f,claim,id){return{mission_id:f.spec.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence,logical_request_id:'logical_'+id,attempt_id:'attempt_'+id,route_id:'ollama.local.qwen3-4b-instruct',capability_id:claim.task.capability.capability_id,capability_version:claim.task.capability.version,reserve_micros:0,quota_units:1,request_hash:digest({synthetic_accounting_attempt:id})};}
