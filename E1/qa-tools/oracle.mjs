import {createHash,createPublicKey,verify} from 'node:crypto';
import {canonicalize,digest,immutable,need,validateBoundValue} from '../contracts/index.mjs';
import {TEXT_INPUT_SCHEMA,TEXT_OUTPUT_SCHEMA,TOOL_QUALITY_SUITE,TOOL_QUALITY_SUITE_DIGEST,toolProfile} from '../tooling/profiles.mjs';
import {CATALOG_PIN} from '../tooling/catalog.mjs';

export const TOOL_CANARY_INPUTS=immutable([
  {task_id:'search_rg',semantic_need:'text.literal-search',profile_id:'ripgrep-stdin',input:{pattern:'alpha',text:'alpha\nALPHA\nalpha beta\nAlpha\n'}},
  {task_id:'search_rga',semantic_need:'e1.tool.rga-stdin',profile_id:'ripgrep-all-stdin',input:{pattern:'--pre=literal',text:'synthetic\n--pre=literal\n--PRE=literal\n--pre=literal tail\n'}},
]);
export const TOOL_CANARY_ORACLE_DIGEST=digest({schema:'awe.e1.tool-canary-oracle/1',semantics:'CASE_SENSITIVE_LITERAL_LINE_SEARCH_FIRST_64_CRLF_NORMALIZED',inputs:TOOL_CANARY_INPUTS});
export const TOOL_CANARY_RUBRIC=immutable({checks:['schema','sources','scope','product'],oracle_digest:TOOL_CANARY_ORACLE_DIGEST,quality_suite_digest:TOOL_QUALITY_SUITE_DIGEST,scope:'TWO_FIXED_STDIN_UTILITIES_NOT_AUTONOMY'});
export const TOOL_CANARY_RUBRIC_DIGEST=digest(TOOL_CANARY_RUBRIC);
export function toolCanaryCase(task_id){const fixed=TOOL_CANARY_INPUTS.find(item=>item.task_id===task_id);need(fixed,'QA_TOOLS_FROZEN_TASK_ID');return fixed;}
/** Only public review metadata may come from IPC. Native snapshot, binding,
 * expected input and acceptance state cannot be replaced by context fields. */
export function toolQaReviewContext(value,task_id){
  const fixed=toolCanaryCase(task_id);need(value?.profile_id===fixed.profile_id,'QA_TOOLS_FROZEN_PROFILE');
  return {review:value.review,publicKey:value.publicKey,expectedFingerprint:value.expectedFingerprint,descriptor:value.descriptor,profile_id:fixed.profile_id,choice:value.choice};
}

/** Independent JS comparator; it never invokes the selected utility. */
export function literalSearchOracle(input) {
  validateBoundValue(TEXT_INPUT_SCHEMA,input);
  need(typeof input.pattern==='string'&&input.pattern.length>0,'QA_TOOLS_PATTERN');
  const matches=input.text.replaceAll('\r\n','\n').split('\n').filter(line=>line.includes(input.pattern)).slice(0,64);
  return immutable({matches,count:matches.length});
}
function fingerprint(key){return 'sha256:'+createHash('sha256').update(key.export({type:'spki',format:'der'})).digest('hex');}

export function verifyPublicToolReview({review,publicKey,expectedFingerprint,profile_id,descriptor,now=new Date().toISOString()}) {
  const key=createPublicKey(publicKey),p=toolProfile(profile_id),payload=review?.payload;
  need(fingerprint(key)===expectedFingerprint&&payload?.key_id===expectedFingerprint&&payload.profile_id===profile_id&&verify(null,Buffer.from(canonicalize(payload)),key,Buffer.from(review.signature,'base64')),'QA_TOOLS_REVIEW_SIGNATURE');
  const zoned=value=>typeof value==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value);
  need([payload.issued_at,payload.expires_at,now].every(zoned),'QA_TOOLS_REVIEW_CURRENT');
  const issued=Date.parse(payload.issued_at),expires=Date.parse(payload.expires_at),observed=Date.parse(now);
  need(payload.schema==='awe.e1.tool-review/1'&&payload.version===p.version&&payload.platform===p.platform&&payload.platform===process.platform&&[issued,expires,observed].every(Number.isFinite)&&issued<=observed&&observed<expires,'QA_TOOLS_REVIEW_CURRENT');
  need(payload.source.catalog_id===p.catalog_id&&payload.source.source_url===p.source_url&&payload.source.catalog_digest==='sha256:'+CATALOG_PIN.sha256,'QA_TOOLS_REVIEW_SOURCE');
  need(payload.input_schema_digest===digest(TEXT_INPUT_SCHEMA)&&payload.output_schema_digest===digest(TEXT_OUTPUT_SCHEMA)&&descriptor.ref.input_schema.digest===payload.input_schema_digest&&descriptor.ref.output_schema.digest===payload.output_schema_digest&&descriptor.ref.capability_id===p.capability_id&&descriptor.executor_kind===p.executor_type,'QA_TOOLS_REVIEW_SCHEMA');
  need(payload.effect_class==='NONE'&&digest(payload.permissions)===digest(descriptor.permissions)&&payload.cost.basis==='ACTUAL_API_DEBIT_MICROS'&&payload.cost.effective_actual_micros===0&&payload.cost.verified===true,'QA_TOOLS_REVIEW_AUTHORITY');
  need(payload.quality.suite_digest===TOOL_QUALITY_SUITE_DIGEST&&payload.quality.tests===TOOL_QUALITY_SUITE.cases.length&&payload.quality.passed===payload.quality.tests&&payload.quality.score===1000,'QA_TOOLS_REVIEW_QUALITY');
  return immutable({review_digest:digest(review),profile_id,version:p.version,binary_pins:payload.binary_pins});
}

/** Reads are supplied by actual native QA snapshot, never producer bytes. */
export function inspectNativeToolTask({snapshot,binding,review,publicKey,expectedFingerprint,descriptor,profile_id,expectedInput,choice,expectedState='WAIT_QA',now}) {
  const fixed=toolCanaryCase(binding.task_id);need(profile_id===fixed.profile_id,'QA_TOOLS_FROZEN_PROFILE');
  const task=snapshot.tasks.find(t=>t.mission_id===binding.mission_id&&t.task_id===binding.task_id&&t.is_current),mission=snapshot.missions.find(m=>m.mission_id===binding.mission_id);
  need(task&&task.state===expectedState&&task.plan_digest===binding.plan_digest&&task.result_hash===binding.result_hash&&task.producer_id!==binding.evaluator_id,'QA_TOOLS_NATIVE_BINDING');
  need(snapshot.project.project_id===task.project_id&&mission?.project_id===task.project_id&&mission.plan_digest===task.plan_digest&&['ACTIVE','COMPLETE'].includes(mission.state),'QA_TOOLS_NATIVE_PROJECT');
  need(digest(task.document.input)===digest(fixed.input),'QA_TOOLS_FROZEN_INPUT');
  if(expectedInput!==undefined)need(digest(expectedInput)===digest(fixed.input),'QA_TOOLS_CALLER_INPUT_SUBSTITUTION');
  need(task.document.qa?.rubric_id==='e1.tools.canary.rubric'&&task.document.qa.rubric_digest===TOOL_CANARY_RUBRIC_DIGEST&&digest(task.document.qa.required_checks)===digest(TOOL_CANARY_RUBRIC.checks)&&task.document.qa.reviewer_role==='QA','QA_TOOLS_FROZEN_RUBRIC');
  need(digest(task.document.capability)===digest(descriptor.ref)&&task.executor_kind===descriptor.executor_kind&&task.document.effect.effect_class==='NONE','QA_TOOLS_NATIVE_CAPABILITY');
  const verified=verifyPublicToolReview({review,publicKey,expectedFingerprint,profile_id,descriptor,...(now?{now}:{})}),result=task.result,execution=result?.evidence?.execution;
  need(result&&digest(result)===task.result_hash&&result.output_schema_digest===descriptor.ref.output_schema.digest&&result.artifact_digest===digest(result.output),'QA_TOOLS_RESULT_DIGEST');
  validateBoundValue(TEXT_OUTPUT_SCHEMA,result.output);
  need(execution?.schema==='awe.e1.fixed-tool-execution/1'&&execution.status==='EXECUTED'&&execution.profile_id===profile_id&&execution.external_mutations===0&&execution.input_digest===digest(task.document.input)&&execution.output_digest===digest(result.output)&&digest(execution.output)===digest(result.output)&&digest(execution.binary_pins)===digest(verified.binary_pins),'QA_TOOLS_EXECUTION_RECEIPT');
  need(result.evidence.tool_review_digest===verified.review_digest&&result.evidence.choice_digest===digest(choice)&&choice.decision==='SELECTED'&&choice.selected.ref_digest===digest(descriptor.ref)&&choice.selected.executor_type===descriptor.executor_kind,'QA_TOOLS_CHOICE_RECEIPT');
  const scope=result.evidence.native_scope;
  need(scope.mission_id===task.mission_id&&scope.task_id===task.task_id&&scope.worker_id===task.producer_id&&String(scope.fence)===String(task.fence)&&scope.plan_digest===task.plan_digest,'QA_TOOLS_NATIVE_SCOPE');
  need(digest(literalSearchOracle(task.document.input))===digest(result.output),'QA_TOOLS_LITERAL_ORACLE');
  need(execution.exit_code===(result.output.count?0:1),'QA_TOOLS_EXIT_CODE');
  need(['attempts','intents','cloud_attempts'].every(key=>Array.isArray(snapshot[key])&&snapshot[key].length===0)&&Number(snapshot.project.spent)===0&&Number(snapshot.project.reserved)===0&&Number(snapshot.project.quota_used)===0,'QA_TOOLS_NO_MODEL_EFFECT_OR_SPEND');
  const checks=['schema','sources','scope','product'].map(check_id=>({check_id,passed:true,...(check_id==='product'?{oracle_digest:TOOL_CANARY_ORACLE_DIGEST}: {})}));
  return immutable({schema:'awe.e1.native-tool-qa/1',verdict:'PASS',checks,task_id:task.task_id,project_id:task.project_id,mission_id:task.mission_id,result_hash:task.result_hash,artifact_digest:result.artifact_digest,output:result.output,input_digest:digest(task.document.input),execution_digest:digest(execution),tool_review_digest:verified.review_digest,choice_digest:digest(choice),producer_id:task.producer_id,fence:task.fence,executor_kind:task.executor_kind,oracle_digest:TOOL_CANARY_ORACLE_DIGEST,accepted:false,proof_scope:'BOUNDED_NATIVE_UTILITY_DISPATCH_NOT_AUTONOMY'});
}
