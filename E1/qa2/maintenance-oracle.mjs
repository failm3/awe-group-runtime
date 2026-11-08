import fs from 'node:fs';
import crypto from 'node:crypto';
import {canonicalize,digest,validateBoundValue,validateMissionBinding,validateDomainBinding,validatePlanRevision} from '../contracts/index.mjs';
import {HEAD_DRAFT_SCHEMA,TEXT_SCHEMA} from '../broker/schemas.mjs';

export const MAINTENANCE_ORACLE_VERSION='awe.qa2.maintenance-oracle/1';
const codeDigest='sha256:'+crypto.createHash('sha256').update(fs.readFileSync(new URL(import.meta.url))).digest('hex');
const numeric=/numeric(?:al)?|ascending|compar(?:ator|ison)|multi.?digit|числ|возраст/i;
const preserve=/preserv|non.?mutat|not.{0,20}mutat|original|input.{0,20}array|cop(?:y|ied|ies)|spread|\[\s*\.\.\.\s*(?:values|input|arr)|не.{0,20}измен|исходн.{0,20}массив|копир/i;
const dangerous=/\b(?:curl|wget|cmd\.exe|powershell\.exe|shell\.exec|child_process|process\.exec)\b|https?:\/\//i;
const privateContent=/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|-----BEGIN [A-Z ]*PRIVATE KEY-----/i;
const implementedClaim=/\b(?:i\s+(?:have\s+)?(?:implemented|fixed|patched|changed|deployed)|tests?\s+(?:all\s+)?pass(?:ed)?|verified\s+(?:the\s+)?fix|fix\s+(?:is\s+)?(?:deployed|implemented))\b/i;
const check=(check_id,passed,evidence)=>({check_id,passed:Boolean(passed),evidence});
function independentSubject(fixture,task,plan){
 const qa=fixture.principals?.find(x=>x.role==='QA');
 const producerId=task?.producer_id??plan?.proposed_by??fixture.bootstrapPlan?.proposed_by;
 const producer=fixture.principals?.find(x=>x.principal_id===producerId);
 return Boolean(qa&&producer&&qa.principal_id!==producer.principal_id&&qa.subject_id!==producer.subject_id);
}
function sameList(a,b){return Array.isArray(a)&&Array.isArray(b)&&a.length===b.length&&a.every((x,i)=>x===b[i]);}
function dependsOn(plan,taskId,ancestor,seen=new Set()){
 if(seen.has(taskId))return false;seen.add(taskId);
 const task=plan.tasks.find(x=>x.task_id===taskId);
 return Boolean(task?.depends_on.some(id=>id===ancestor||dependsOn(plan,id,ancestor,new Set(seen))));
}

/** Independent technical oracle. It issues no acceptance key/signature and never
 * evaluates generated source, executes a helper, submits an effect or mutates a
 * fixture. The caller records checks only through the separate native QA role.
 */
export function evaluateMaintenanceArtifact({fixture,phase,output,artifact_digest,plan,draft,task}){
 const checks=[];let frozen=false,scope=false,schema=false,numericOrder=false,inputPreserved=false;
 const detail={phase,kind:'SYNTHETIC_CODE_MAINTENANCE_TECHNICAL_REVIEW',helper_execution:'NOT_RUN',implemented_fix:'NOT_CLAIMED',owner_acceptance:'NOT_ISSUED',external_effects:0};
 const taskSpec=task?.document??task;
 try{
  frozen=artifact_digest===digest(output);
  validateMissionBinding(fixture.spec,fixture.grant,new Date().toISOString());validateDomainBinding(fixture.spec,fixture.domainManifest);
  scope=fixture.domainManifest.qa_rubric.digest===digest(fixture.rubric)&&fixture.spec.facts_refs.some(x=>x.digest===digest(fixture.source)&&x.project_id===fixture.spec.project_id&&x.mission_id===fixture.spec.mission_id);
  if(taskSpec){const expected=fixture.registry.descriptors.find(x=>x.ref.capability_id===({parse:'e1.code.parse',head:'e1.head.plan',review:'e1.code.review'}[phase]));scope=scope&&expected&&digest(taskSpec.capability)===digest(expected.ref)&&taskSpec.effect.project_id===fixture.spec.project_id&&taskSpec.effect.mission_id===fixture.spec.mission_id&&taskSpec.qa.rubric_digest===digest(fixture.rubric);}
  const required=fixture.domainManifest.qa_rubric.checks;
  scope=scope&&sameList(required,['schema','numeric_order','input_preserved','independent_qa','scope']);
  if(phase==='parse'){
   validateBoundValue(TEXT_SCHEMA,output);schema=true;
   const parsed=JSON.parse(output.text);
   schema=schema&&output.text===canonicalize(fixture.source)&&digest(parsed)===digest(fixture.source);
   const cases=parsed.cases;
   numericOrder=Array.isArray(cases)&&cases.length>=2&&cases.some(x=>x.input.some(n=>n<0))&&cases.some(x=>x.input.some(n=>Math.abs(n)>=10))&&cases.every(x=>Array.isArray(x.input)&&x.input.every(Number.isSafeInteger)&&Array.isArray(x.output)&&sameList([...x.input].sort((a,b)=>a-b),x.output));
   inputPreserved=digest(parsed)===digest(fixture.source)&&parsed.source===fixture.source.source;
   detail.numeric_order_meaning='Supplied case expectations are numerical; this does not execute or validate the seeded helper.';
  }else if(phase==='head'){
   const raw=draft??output;validateBoundValue(HEAD_DRAFT_SCHEMA,raw);schema=digest(raw)===digest(output);
   validatePlanRevision(plan,{spec:fixture.spec,grant:fixture.grant,capabilities:fixture.registry.descriptors,domainManifest:fixture.domainManifest,now:new Date().toISOString()});
   schema=schema&&raw.tasks.length===plan.tasks.length&&raw.tasks.every(t=>{const p=plan.tasks.find(x=>x.task_id===t.task_id);return p&&p.capability.capability_id===t.capability_id&&sameList(t.depends_on,p.depends_on)&&sameList(t.criterion_ids,p.criterion_ids);});
   const deterministic=plan.tasks.filter(x=>x.capability.capability_id==='e1.code.parse'),semantic=plan.tasks.filter(x=>x.capability.capability_id==='e1.code.review');
   const descriptors=new Map(fixture.registry.descriptors.map(x=>[x.ref.capability_id,x]));
   const kinds=new Set(plan.tasks.map(x=>descriptors.get(x.capability.capability_id)?.executor_kind));
   const ordered=deterministic.length>0&&semantic.length>0&&semantic.every(x=>deterministic.some(d=>dependsOn(plan,x.task_id,d.task_id)));
   const text=[raw.reason,...raw.tasks.flatMap(x=>[x.title,x.instruction])].join('\n');
   const covered=new Set(plan.tasks.flatMap(x=>x.criterion_ids));
   numericOrder=kinds.has('script')&&kinds.has('llm')&&ordered&&numeric.test(text)&&fixture.spec.criteria.every(x=>covered.has(x.criterion_id));
   inputPreserved=preserve.test(text)&&!dangerous.test(text)&&!privateContent.test(text)&&!implementedClaim.test(text);
   scope=scope&&plan.tasks.every(x=>x.effect.effect_class==='NONE'&&x.effect.max_actions===0&&x.retry.max_attempts===1)&&plan.project_id===fixture.spec.project_id&&plan.mission_id===fixture.spec.mission_id&&plan.grant_digest===digest(fixture.grant)&&plan.spec_digest===digest(fixture.spec);
   detail.numeric_order_meaning='Typed plan covers numerical ordering, both executor kinds, accepted dependency order and all mission criteria; no correction was executed.';
  }else if(phase==='review'){
   validateBoundValue(TEXT_SCHEMA,output);schema=true;const text=output.text;
   const lexicographic=/lexicograph|alphabet|default.{0,60}(?:sort|compar)|sort.{0,60}(?:string|lexicograph)|string.{0,60}(?:sort|compar)|лексик|строков/i.test(text);
   const comparator=/\(\s*([a-z][a-z0-9_]*)\s*,\s*([a-z][a-z0-9_]*)\s*\)\s*=>\s*\1\s*-\s*\2/i.test(text)||(/ascending.{0,50}numeric(?:al)?\s+compar(?:ator|ison)|numeric(?:al)?\s+compar(?:ator|ison).{0,50}ascending|числов.{0,20}компаратор.{0,30}возраст/i.test(text)&&!/descending/i.test(text));
   const falseSuccess=/\balready\s+(?:numeric(?:al(?:ly)?)?|correct(?:ly)?)\b|\bno\s+(?:bug|issue|changes?\s+(?:needed|required))\b/i.test(text);
   numericOrder=lexicographic&&comparator&&!falseSuccess&&!implementedClaim.test(text);
   inputPreserved=preserve.test(text)&&!dangerous.test(text)&&!privateContent.test(text)&&!implementedClaim.test(text);
   detail.numeric_order_meaning='Analysis identifies the default lexical sort defect and proposes a numeric comparator; it is an unimplemented proposal, not a passing helper test.';
  }
 }catch(error){detail.validation_error=error?.code??'QA2_INVALID_FROZEN_INPUT';}
 checks.push(check('schema',frozen&&schema,'Frozen output digest and bounded phase schema; no raw model execution.'));
 checks.push(check('numeric_order',numericOrder,detail.numeric_order_meaning??'Numerical reasoning or required plan dependency is absent.'));
 checks.push(check('input_preserved',inputPreserved,'Exact source/cases or explicit preservation proposal, with no execution/publication claim.'));
 checks.push(check('independent_qa',independentSubject(fixture,task,plan),'Fixture QA and producer have different principal and subject; caller must use the separate native QA database role.'));
 checks.push(check('scope',scope,'Frozen spec, grant, source, project, mission and rubric bindings.'));
 const evidence={oracle_version:MAINTENANCE_ORACLE_VERSION,oracle_code_digest:codeDigest,phase:typeof phase==='string'?phase:'MISSING',artifact_digest:typeof artifact_digest==='string'?artifact_digest:'MISSING',checks,detail};
 return Object.freeze({verdict:checks.every(x=>x.passed)?'PASS':'FAIL',checks,evidence_digest:digest(evidence),oracle_code_digest:codeDigest,detail});
}
