import {digest,capabilityManifestDigest,validatePlanRevision} from '../../contracts/index.mjs';
import {createMissionIngress} from '../../mission/ingress.mjs';
import {createRecruitMission} from '../mission.mjs';

export const SCORE_SCHEMA={type:'object',properties:{filename:{type:'string',minLength:1,maxLength:40,enum:['score_helper.py']},language:{type:'string',minLength:1,maxLength:20,enum:['python']},code:{type:'string',minLength:1,maxLength:4096}},required:['filename','language','code'],additionalProperties:false};
export const CODE_INSTRUCTION='Author one pure Python function score(skills). Return the registered JSON object with filename score_helper.py, language python, and code. No Markdown. score accepts a list of strings, strips whitespace, casefolds, counts each distinct normalized skill ONCE: javascript 5, sql 3, testing 2; unknowns ignored. Empty input returns 0. Never modify input. Only one function, no imports, no I/O, no dependencies, no annotations or decorators. Use plain dict, set comprehension and sum. This is a fictional recruiting skill scorer, no employer contact. Code at most 20 lines.';
export function createScoreMission({run_id,now,oracle_digest,facts}){
 const base=createRecruitMission({run_id,now,oracle_digest,facts,sourceConfigs:[{},{}]}),v=x=>({contract_version:base.spec.contract_version,release:base.spec.release,...x}),cap=structuredClone(base.registry.descriptors.find(c=>c.ref.capability_id==='e1.code.review'));
 cap.ref.capability_id='e1.recruit.score-author';cap.ref.output_schema={schema_id:'e1.recruit.score.source',version:'1.0.0',digest:digest(SCORE_SCHEMA)};cap.output_schema=SCORE_SCHEMA;cap.ref.manifest_digest=capabilityManifestDigest(cap);
 const entry={...base.registry.entries.find(e=>e.descriptor.ref.capability_id==='e1.code.review'),descriptor:cap};
 const registry={...base.registry,entries:[entry],descriptors:[cap],digest:digest([entry])};
 const domainManifest={...base.domainManifest,manifest_id:'domain.recruit_score_author',capabilities:[cap.ref],description:'One genuine local model-authored pure Python score function, executed only in bounded bwrap sandbox.'};
 const spec={...base.spec,goal:'SANDBOX-RECRUIT-01: author and independently test one pure Python skill scorer in an isolated synthetic code worktree. No external effects.',criteria:[{criterion_id:'code',text:'AWE local model authors score helper, exact source and native usage are persisted, independent sandbox QA checks unseen cases.'}],requested_capabilities:[cap.ref],domain_manifest:{manifest_id:domainManifest.manifest_id,version:domainManifest.version,digest:digest(domainManifest)}};
 const grant={...base.grant,spec_digest:digest(spec),allowed_capabilities:[cap.ref],max_tasks:1};
 const input={instruction:CODE_INSTRUCTION},template=base.plan.tasks.find(t=>t.task_id==='review'),task={...template,task_id:'score_author',title:'Author a pure skill scorer',capability:cap.ref,input,depends_on:[],dependency_bindings:[],criterion_ids:['code'],effect:{...template.effect,effect_id:'intent_score_author',task_id:'score_author',payload_digest:digest(input)}};
 const plan={...base.plan,reason:'One bounded model-authored code task under the synthetic test mandate.',spec_digest:digest(spec),grant_digest:digest(grant),tasks:[task]};
 validatePlanRevision(plan,{spec,grant,capabilities:[cap],domainManifest,now});
 const ingress=createMissionIngress({authority:base.authority,capabilities:[cap],domainManifests:[domainManifest],projectId:spec.project_id});ingress.mission.create({spec,grant},base.contexts.owner);const proposed=ingress.plan.propose({plan},base.contexts.head),validated=ingress.plan.validate({mission_id:spec.mission_id,plan_digest:proposed.plan.digest},base.contexts.coordinator);ingress.plan.publish({mission_id:spec.mission_id,plan_digest:proposed.plan.digest,validation_digest:validated.validation.digest},base.contexts.coordinator);
 return {...base,spec,grant,plan,domainManifest,capabilities:[cap],registry,ingress};
}
