import fs from 'node:fs';
import {randomBytes} from 'node:crypto';
import {fork} from 'node:child_process';
import {createMissionFixture} from '../../examples/fixtures.mjs';
import {createMissionIngress,createOfflineAuthority} from '../../mission/ingress.mjs';
import {digest,capabilityManifestDigest} from '../../contracts/index.mjs';
import {createAdmissionBridge,createCoordinator,createPsqlSession} from '../../coordinator/index.mjs';

export const id=suffix=>'a2_'+suffix+'_'+randomBytes(4).toString('hex');
export function publicationFixture({project_id=id('project'),mission_id=id('mission'),task_count=3,task_cost='0',llm=false,effect=false,business_key='synthetic-maintenance',lifetime_ms=600000}={}) {
  const base=createMissionFixture('A'),now=new Date().toISOString(),future=new Date(Date.now()+lifetime_ms).toISOString();
  const capabilities=structuredClone(base.capabilities);
  for(const cap of capabilities){cap.health_until=new Date(Math.ceil(Date.now()/60000)*60000+86400000).toISOString();cap.timeout_ms=10000;if(cap.ref.capability_id==='common.research'){cap.executor_kind=llm?'llm':'script';if(effect){cap.effect_class='LOCAL_WRITE';cap.permissions.push('effect.local');}}cap.ref.manifest_digest=capabilityManifestDigest(cap);}
  const domainManifest={...structuredClone(base.domain_manifest),project_id,capabilities:capabilities.map(c=>c.ref)};
  const spec=structuredClone(base.spec);Object.assign(spec,{mission_id,project_id,deadline:future,goal:'Synthetic code maintenance coordinator canary.',requested_capabilities:capabilities.map(c=>c.ref),domain_manifest:{manifest_id:domainManifest.manifest_id,version:domainManifest.version,digest:digest(domainManifest)},budget:{currency:task_cost==='0'?'NONE':'USD',amount_micros:String(BigInt(task_cost)*BigInt(task_count)*2n)},max_actions:effect?1:0});
  spec.facts_refs=spec.facts_refs.map(f=>({...f,project_id,mission_id,created_at:now}));
  const principals=base.principals.map(p=>({...p,projects:[project_id]}));
  principals.push(...['e1_worker','e1_worker1','e1_worker2'].map(principal_id=>({principal_id,subject_id:principal_id,role:'EXECUTOR',projects:[project_id]})));
  const grant=structuredClone(base.grant);Object.assign(grant,{grant_id:id('grant'),mission_id,project_id,spec_digest:digest(spec),issued_at:now,expires_at:future,allowed_capabilities:capabilities.map(c=>c.ref),allowed_principals:principals.map(p=>p.principal_id),max_actions:effect?1:0,budget_cap:spec.budget});
  if(effect){grant.permissions.push('effect.local');grant.allowed_effect_classes.push('LOCAL_WRITE');grant.destinations=['fake-provider:maintenance'];}
  const plan=structuredClone(base.plan);Object.assign(plan,{plan_id:id('plan'),mission_id,project_id,spec_digest:digest(spec),grant_digest:digest(grant),created_at:now,deadline:future,budget:{currency:spec.budget.currency,amount_micros:String(BigInt(task_cost)*BigInt(task_count)*2n)}});
  plan.tasks=plan.tasks.slice(0,task_count).map((task,index)=>{
    const capability=capabilities.find(c=>c.ref.capability_id===task.capability.capability_id).ref,input={instruction:'Inspect synthetic module '+index};
    const dependencies=task.depends_on.filter(dep=>plan.tasks.slice(0,task_count).some(t=>t.task_id===dep));
    return {...task,capability,input,deadline:future,timeout_ms:Math.min(5000,Math.floor(lifetime_ms/4)),budget:{currency:spec.budget.currency,amount_micros:task_cost},criterion_ids:index===task_count-1?['primary','review']:['primary'],depends_on:dependencies,dependency_bindings:dependencies.map(task_id=>({task_id,output_schema:capabilities[0].ref.output_schema})),retry:{max_attempts:effect?1:2,retry_on:[],on_unknown:'HOLD'},effect:{...task.effect,mission_id,project_id,payload_digest:digest(input),...(effect?{effect_class:'LOCAL_WRITE',permission:'effect.local',destination:'fake-provider:maintenance',business_key,max_actions:1}:{} )}};
  });
  // Only a one-task fixture may represent the synthetic canonical effect.
  if(effect&&task_count!==1)throw new Error('A2_EFFECT_FIXTURE_ONE_TASK');
  const authority=createOfflineAuthority(principals),context=role=>authority.issueContext(principals.find(p=>p.role===role).principal_id,project_id);
  const contexts={owner:context('OWNER'),head:context('HEAD'),coordinator:context('COORDINATOR')};
  const ingress=createMissionIngress({clock:()=>new Date().toISOString(),authority,capabilities,projectId:project_id,domainManifests:[domainManifest]});
  ingress.mission.create({spec,grant},contexts.owner);
  const proposed=ingress.plan.propose({plan},contexts.head),validated=ingress.plan.validate({mission_id,plan_digest:proposed.plan.digest},contexts.coordinator);
  const publication=ingress.plan.publish({mission_id,plan_digest:proposed.plan.digest,validation_digest:validated.validation.digest},contexts.coordinator);
  return {spec,grant,plan,publication,validation:validated.validation,capabilities,domainManifest,ingress,contexts};
}
export function publishRevision(source,mutate=()=>{}) {
  const plan=structuredClone(source.plan);plan.revision++;plan.previous_digest=digest(source.plan);plan.reason='Bounded synthetic maintenance replan after independent result.';plan.created_at=new Date().toISOString();mutate(plan);
  const proposed=source.ingress.plan.propose({plan},source.contexts.head),validated=source.ingress.plan.validate({mission_id:source.spec.mission_id,plan_digest:proposed.plan.digest},source.contexts.coordinator),publication=source.ingress.plan.publish({mission_id:source.spec.mission_id,plan_digest:proposed.plan.digest,validation_digest:validated.validation.digest},source.contexts.coordinator);
  Object.assign(source,{plan,publication,validation:validated.validation});return source;
}
export function makeBridge(sources,policy) {
  const context=Object.freeze({}),byMission=new Map(sources.map(source=>[source.spec.mission_id,source]));
  const bridge=createAdmissionBridge({authenticate:actual=>{if(actual!==context)throw new Error('UNTRUSTED');const source=sources[0];return {principal_id:'id_e1_coordinator',project_id:source.spec.project_id,role:'COORDINATOR'};},resolvePublication:request=>byMission.get(request.mission_id),verifyGrant:({grant})=>byMission.get(grant.mission_id)?.grant.revoked_at===null,policy});
  return {bridge,context};
}
export function descriptor() {return JSON.parse(fs.readFileSync(new URL('../../../.private/e1-resource.json',import.meta.url),'utf8'));}
export async function runtime(sources,{policy,role='coordinator'}={}) {
  const db=await createPsqlSession(descriptor(),{role}),{bridge,context}=makeBridge(sources,policy??{budget_cap_micros:sources[0].spec.budget.amount_micros,quota_cap:16,max_parallel:2,resource_limits:{cpu:2},capabilities:Object.fromEntries(sources[0].capabilities.map(c=>[c.ref.capability_id,{resource_keys:['cpu'],max_claims:c.effect_class==='NONE'?2:1}]))});
  const coordinator=createCoordinator({db,admission:bridge,project_id:sources[0].spec.project_id});
  return {db,coordinator,context,async admitAll(){for(const source of sources)await coordinator.admit({mission_id:source.spec.mission_id},context);}};
}
export function startLeaf(authority,credential,config={}) {
  const child=fork(new URL('../../coordinator/leaf-worker.mjs',import.meta.url),[],{stdio:['ignore','ignore','pipe','ipc'],windowsHide:true,env:{SystemRoot:process.env.SystemRoot,WINDIR:process.env.WINDIR,PATH:process.env.PATH,TEMP:process.env.TEMP,TMP:process.env.TMP}});
  const messages=[];let stderr='';child.stderr.on('data',b=>stderr+=b.toString());child.on('message',message=>messages.push(message));
  const exit=new Promise(resolve=>child.once('exit',(code,signal)=>resolve({code,signal,messages,stderr})));
  child.send({url:authority.url,token:credential.token,capabilities:['common.research','common.transform','common.build','common.qa'],...config});
  return {child,messages,exit,async waitFor(type){const until=Date.now()+10000;while(Date.now()<until){const message=messages.find(m=>m.type===type);if(message)return message;const error=messages.find(m=>m.type==='ERROR');if(error)throw new Error(JSON.stringify(error));await new Promise(resolve=>setTimeout(resolve,10));}throw new Error('A2_LEAF_WAIT_TIMEOUT');}};
}
export function resultFor(claim,text='Synthetic maintenance result') {const output={text};return {output_schema_digest:claim.task.capability.output_schema.digest,output,artifact_digest:digest(output)};}
export async function independentAccept(qa,task) {return qa.qaEvaluate({mission_id:task.mission_id,plan_digest:task.plan_digest,task_id:task.task_id,result_hash:task.result_hash,evaluator_id:'id_e1_qa',verdict:'PASS',checks:task.document.qa.required_checks.map(check_id=>({check_id,passed:true}))});}
