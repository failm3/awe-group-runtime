import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {generateKeyPairSync,sign} from 'node:crypto';
import {canonicalize,digest} from '../../contracts/index.mjs';
import {validateToolCanaryConfig,createNativeToolMission,toolingCanarySourcePins} from '../../tooling/native-canary.mjs';
import {toolCapability,toolProfile,TOOL_QUALITY_SUITE,TOOL_QUALITY_SUITE_DIGEST,TEXT_INPUT_SCHEMA,TEXT_OUTPUT_SCHEMA} from '../../tooling/profiles.mjs';
import {CATALOG_PIN} from '../../tooling/catalog.mjs';
import {keyFingerprint} from '../../tooling/review.mjs';
import {TOOL_CANARY_INPUTS,TOOL_CANARY_RUBRIC,TOOL_CANARY_RUBRIC_DIGEST,literalSearchOracle,inspectNativeToolTask,toolQaReviewContext} from '../../qa-tools/oracle.mjs';
import {TOOL_TIMESTAMP_CORRECTION,validateToolSourceLineage,reconstructHistoricalToolGrant} from '../../qa-tools/verify-persisted.mjs';

const hash=label=>digest({label});
function entries(){const health_until=new Date(Date.now()+1800000).toISOString();return ['ripgrep-stdin','ripgrep-all-stdin'].map(profile_id=>({evidence:'OFFLINE_CONTRACT_TEST_DOUBLE_NOT_ACTIVATED',descriptor:toolCapability(profile_id,health_until),profile_id,executor_type:toolProfile(profile_id).executor_type,provides:['text.literal-search'],installed:true,available:true,health_until,quality:{suite_digest:TOOL_QUALITY_SUITE_DIGEST,tests:TOOL_QUALITY_SUITE.cases.length,passed:TOOL_QUALITY_SUITE.cases.length,score:1000},cost:{basis:'ACTUAL_API_DEBIT_MICROS',effective_actual_micros:0,currency:'USD',verified:true}}));}

test('canary config requires explicit absolute host paths and bounded fresh run ID',()=>{
  const value={run_id:'tool_fixture',resourcePath:path.resolve('fixture/e1-resource.json'),catalogPath:path.resolve('fixture/catalog.json')};assert.equal(validateToolCanaryConfig(value).run_id,'tool_fixture');
  for(const change of [v=>v.resourcePath='relative.json',v=>v.run_id='../outside',v=>v.command='arbitrary',v=>v.catalogPath=null]){const v=structuredClone(value);change(v);assert.throws(()=>validateToolCanaryConfig(v));}
});
test('ordinary A1 tool mission is CPU-only script/program with real policy output, no model task',()=>{
  const f=createNativeToolMission({run_id:'contract_fixture',entries:entries()});
  assert.equal(f.spec.max_replans,0);assert.equal(f.spec.max_actions,0);assert.equal(f.grant.budget_cap.amount_micros,'0');
  assert.deepEqual(f.plan.tasks.map(t=>t.task_id),['search_rg','search_rga']);assert.deepEqual(f.capabilities.map(c=>c.executor_kind),['script','program']);
  assert.equal(f.choices[0].selected.executor_type,'script');assert.equal(f.choices[0].candidates.filter(c=>c.eligible).length,2);assert.equal(f.choices[1].selected.executor_type,'program');assert.equal(f.choices[1].candidates.filter(c=>c.eligible).length,1);
  assert.ok(f.plan.tasks.every(t=>t.effect.effect_class==='NONE'&&t.retry.max_attempts===1));assert.equal(f.ingress.snapshot(f.contexts.e1_tools_owner).missions[0].plans.at(-1).status,'PUBLISHED_PREFLIGHT_ONLY');
  assert.equal(digest(f.rubric),TOOL_CANARY_RUBRIC_DIGEST);assert.ok(f.plan.tasks.every(t=>t.qa.rubric_digest===TOOL_CANARY_RUBRIC_DIGEST));
});
test('independent oracle distinguishes case and treats apparent CLI flags as literal data',()=>{
  assert.deepEqual(literalSearchOracle(TOOL_CANARY_INPUTS[0].input),{matches:['alpha','alpha beta'],count:2});
  assert.deepEqual(literalSearchOracle(TOOL_CANARY_INPUTS[1].input),{matches:['--pre=literal','--pre=literal tail'],count:2});
  assert.deepEqual(literalSearchOracle({pattern:'x',text:'x\r\nX\r\nx'}),{matches:['x','x'],count:2});assert.deepEqual(literalSearchOracle({pattern:'none',text:''}),{matches:[],count:0});
});
test('source pins cover actual dispatcher, legacy discovery, native coordinator and independent QA',()=>{
  const pins=toolingCanarySourcePins();assert.ok(pins.length>=20);for(const name of ['E1/tooling/dispatch.mjs','awe/tool_registry/discovery.mjs','E1/coordinator/coordinator.mjs','E1/qa-tools/cold-readback.mjs'])assert.ok(pins.some(p=>p.path===name));assert.ok(pins.every(p=>/^[a-f0-9]{64}$/.test(p.sha256)&&!p.path.includes('.private')));
});

function qaFixture(){
  // All snapshot/model-free evidence in this helper is a labelled unit double.
  const now=new Date().toISOString(),expires_at=new Date(Date.now()+1800000).toISOString(),profile_id='ripgrep-stdin',p=toolProfile(profile_id),descriptor=toolCapability(profile_id,expires_at),key=generateKeyPairSync('ed25519'),publicKey=key.publicKey.export({type:'spki',format:'pem'}),expectedFingerprint=keyFingerprint(key.publicKey);
  const pins=[{role:'tool',digest:hash('unit binary placeholder'),bytes:1,version:p.version}],payload={schema:'awe.e1.tool-review/1',profile_id,version:p.version,platform:p.platform,issued_at:now,expires_at,key_id:expectedFingerprint,source:{catalog_id:p.catalog_id,source_url:p.source_url,catalog_digest:'sha256:'+CATALOG_PIN.sha256,raw_digest:hash('unit raw placeholder')},input_schema_digest:digest(TEXT_INPUT_SCHEMA),output_schema_digest:digest(TEXT_OUTPUT_SCHEMA),permissions:descriptor.permissions,effect_class:'NONE',quality:{suite_digest:TOOL_QUALITY_SUITE_DIGEST,tests:TOOL_QUALITY_SUITE.cases.length,passed:TOOL_QUALITY_SUITE.cases.length,score:1000},cost:{basis:'ACTUAL_API_DEBIT_MICROS',effective_actual_micros:0,currency:'USD',verified:true},evidence:'OFFLINE_SIGNED_REVIEW_FIXTURE_NOT_HOST_PROBE'};
  payload.binary_pins=pins;
  const review={payload,signature:sign(null,Buffer.from(canonicalize(payload)),key.privateKey).toString('base64')},input=TOOL_CANARY_INPUTS[0].input,output=literalSearchOracle(input),scope={mission_id:'fixture_mission',task_id:'search_rg',worker_id:'fixture_worker',fence:1,plan_digest:hash('fixture plan')},choice={decision:'SELECTED',selected:{ref_digest:digest(descriptor.ref),executor_type:'script'}};
  const execution={schema:'awe.e1.fixed-tool-execution/1',status:'EXECUTED',profile_id,input_digest:digest(input),output,output_digest:digest(output),exit_code:0,binary_pins:pins,external_mutations:0,evidence:'OFFLINE_EXECUTION_FIXTURE_NOT_PROCESS'};
  const result={output_schema_digest:descriptor.ref.output_schema.digest,output,artifact_digest:digest(output),evidence:{tool_review_digest:digest(review),choice_digest:digest(choice),execution,native_scope:scope}};
  const task={...scope,project_id:'fixture_project',state:'WAIT_QA',is_current:true,producer_id:scope.worker_id,executor_kind:'script',document:{capability:descriptor.ref,input,effect:{effect_class:'NONE'},qa:{rubric_id:'e1.tools.canary.rubric',rubric_digest:TOOL_CANARY_RUBRIC_DIGEST,required_checks:[...TOOL_CANARY_RUBRIC.checks],reviewer_role:'QA'}},result,result_hash:digest(result)};
  const binding={mission_id:scope.mission_id,task_id:scope.task_id,plan_digest:scope.plan_digest,result_hash:task.result_hash,evaluator_id:'fixture_independent_qa'};
  const args={snapshot:{project:{project_id:'fixture_project',spent:0,reserved:0,quota_used:0},tasks:[task],missions:[{project_id:'fixture_project',mission_id:scope.mission_id,state:'ACTIVE',plan_digest:scope.plan_digest}],attempts:[],intents:[],cloud_attempts:[]},binding,review,publicKey,expectedFingerprint,descriptor,profile_id,expectedInput:input,choice,now};
  const refresh=()=>{task.result_hash=digest(task.result);binding.result_hash=task.result_hash;};return {args,task,refresh};
}
test('QA contract accepts consistent labelled fixtures without claiming runtime execution',()=>{
  const f=qaFixture(),r=inspectNativeToolTask(f.args);assert.equal(r.verdict,'PASS');assert.equal(r.accepted,false);assert.equal(r.proof_scope,'BOUNDED_NATIVE_UTILITY_DISPATCH_NOT_AUTONOMY');
});
test('QA catches self-consistent wrong-case output that earlier utility smoke missed',()=>{
  const f=qaFixture(),wrong={matches:['alpha','ALPHA','alpha beta','Alpha'],count:4};f.task.result.output=wrong;f.task.result.artifact_digest=digest(wrong);f.task.result.evidence.execution.output=wrong;f.task.result.evidence.execution.output_digest=digest(wrong);f.refresh();assert.throws(()=>inspectNativeToolTask(f.args),/QA_TOOLS_LITERAL_ORACLE/);
});
test('QA rejects swapped signature, stale input/fence and accidental model accounting',()=>{
  for(const change of [f=>{f.args.review.signature='A'.repeat(88);},f=>{f.task.document.input={pattern:'other',text:'other'};},f=>{f.task.result.evidence.native_scope.fence=2;f.refresh();},f=>{f.args.snapshot.attempts=[{project_id:'fixture_project'}];}]){const f=qaFixture();change(f);assert.throws(()=>inspectNativeToolTask(f.args));}
});
test('QA cannot accept a self-consistent replacement task input supplied as expectedInput',()=>{
  const f=qaFixture(),replacement={pattern:'injected',text:'injected\n'};f.args.expectedInput=replacement;f.task.document.input=replacement;const output=literalSearchOracle(replacement);f.task.result.output=output;f.task.result.artifact_digest=digest(output);Object.assign(f.task.result.evidence.execution,{input_digest:digest(replacement),output,output_digest:digest(output)});f.refresh();assert.throws(()=>inspectNativeToolTask(f.args),/QA_TOOLS_FROZEN_INPUT/);
});
test('QA binds immutable task ID and profile instead of caller profile metadata',()=>{
  const f=qaFixture();f.args.profile_id='ripgrep-all-stdin';assert.throws(()=>inspectNativeToolTask(f.args),/QA_TOOLS_FROZEN_PROFILE/);
  const other=qaFixture();other.args.binding.task_id='arbitrary_task';other.task.task_id='arbitrary_task';assert.throws(()=>inspectNativeToolTask(other.args),/QA_TOOLS_FROZEN_TASK_ID/);
});
test('QA rejects native rubric/check-list substitutions',()=>{
  for(const change of [f=>f.task.document.qa.rubric_digest=hash('substituted rubric'),f=>f.task.document.qa.required_checks=['schema'],f=>f.task.document.qa.reviewer_role='EXECUTOR']){const f=qaFixture();change(f);assert.throws(()=>inspectNativeToolTask(f.args),/QA_TOOLS_FROZEN_RUBRIC/);}
});
test('QA rejects native external intents, cloud attempts and missing ledger evidence',()=>{
  for(const key of ['intents','cloud_attempts']){const f=qaFixture();f.args.snapshot[key]=[{origin:'OFFLINE_NEGATIVE_FIXTURE'}];assert.throws(()=>inspectNativeToolTask(f.args),/QA_TOOLS_NO_MODEL_EFFECT_OR_SPEND/);}
  const missing=qaFixture();delete missing.args.snapshot.cloud_attempts;assert.throws(()=>inspectNativeToolTask(missing.args),/QA_TOOLS_NO_MODEL_EFFECT_OR_SPEND/);
});
test('QA IPC metadata cannot override actual native snapshot/binding/expected input',()=>{
  const f=qaFixture(),selected=toolQaReviewContext({...f.args,snapshot:{forged:true},binding:{task_id:'other'},expectedInput:{pattern:'injected',text:'injected'}},'search_rg');
  assert.deepEqual(Object.keys(selected).sort(),['choice','descriptor','expectedFingerprint','profile_id','publicKey','review'].sort());assert.equal(selected.profile_id,'ripgrep-stdin');assert.equal(inspectNativeToolTask({...selected,snapshot:f.args.snapshot,binding:f.args.binding,now:f.args.now}).verdict,'PASS');
});
test('historical QA timestamp with PostgreSQL +03 offset equals UTC review time',()=>{
  const f=qaFixture();f.args.now=new Date(Date.parse(f.args.now)+10800000).toISOString().replace(/Z$/,'+03:00');assert.equal(inspectNativeToolTask(f.args).verdict,'PASS');
});
test('expired or invalid historical timestamps reject after epoch conversion',()=>{
  for(const value of ['invalid',null]){const f=qaFixture();f.args.now=value??'not-a-date';assert.throws(()=>inspectNativeToolTask(f.args),/QA_TOOLS_REVIEW_CURRENT/);}
  const expired=qaFixture();expired.args.now=new Date(Date.parse(expired.args.review.payload.expires_at)+10800000).toISOString().replace(/Z$/,'+03:00');assert.throws(()=>inspectNativeToolTask(expired.args),/QA_TOOLS_REVIEW_CURRENT/);
});
test('historical review time requires an explicit valid UTC zone',()=>{
  for(const transform of [value=>value.replace(/Z$/,''),value=>value.replace(/Z$/,'+99:99'),value=>value.replace('T',' ')]){const f=qaFixture();f.args.now=transform(f.args.now);assert.throws(()=>inspectNativeToolTask(f.args),/QA_TOOLS_REVIEW_CURRENT/);}
});
test('read-only recovery permits only the exact timestamp correction and rejects dispatcher changes',()=>{
  const current=toolingCanarySourcePins(),original=current.map(pin=>pin.path===TOOL_TIMESTAMP_CORRECTION.path?{...pin,sha256:TOOL_TIMESTAMP_CORRECTION.from_sha256}:pin),verified=validateToolSourceLineage(original,current);
  assert.equal(verified.explicit_corrections.length,1);assert.equal(verified.unchanged,current.length-1);
  const changed=current.map(pin=>pin.path==='E1/tooling/dispatch.mjs'?{...pin,sha256:'0'.repeat(64)}:pin);assert.throws(()=>validateToolSourceLineage(original,changed),/QA_TOOLS_EXECUTION_SOURCE_CHANGED/);
});
test('historical grant reconstruction must hash-match the actual admitted grant',()=>{
  const f=createNativeToolMission({run_id:'grant_reconstruct',entries:entries()}),checkpoint={run_id:'grant_reconstruct',project_id:f.spec.project_id,mission_id:f.spec.mission_id,grant_digest:digest(f.grant),signed_reviews:[{payload:{issued_at:f.grant.issued_at}},{payload:{issued_at:f.grant.issued_at}}]},mission={spec:f.spec,grant_digest:digest(f.grant)};
  assert.deepEqual(reconstructHistoricalToolGrant({checkpoint,mission,descriptors:f.capabilities}),f.grant);
  assert.throws(()=>reconstructHistoricalToolGrant({checkpoint,mission:{...mission,grant_digest:hash('wrong grant')},descriptors:f.capabilities}),/QA_TOOLS_HISTORICAL_GRANT_HASH/);
});
