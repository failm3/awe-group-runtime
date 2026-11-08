import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {fork} from 'node:child_process';
import {digest,immutable,need,exact} from '../contracts/index.mjs';
import {validateResourceDescriptor} from '../coordinator/resource.mjs';
import {createPsqlSession} from '../coordinator/psql-session.mjs';
import {createCoordinator} from '../coordinator/coordinator.mjs';
import {toolCapability,toolProfile,TOOL_QUALITY_SUITE_DIGEST} from '../tooling/profiles.mjs';
import {chooseExecutor} from '../tooling/policy.mjs';
import {CATALOG_PIN} from '../tooling/catalog.mjs';
import {TOOL_CANARY_INPUTS,TOOL_CANARY_ORACLE_DIGEST,TOOL_CANARY_RUBRIC_DIGEST,inspectNativeToolTask,verifyPublicToolReview} from './oracle.mjs';

const repo=fileURLToPath(new URL('../../',import.meta.url));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export const TOOL_TIMESTAMP_CORRECTION=immutable({path:'E1/qa-tools/oracle.mjs',from_sha256:'068f1eee720d915772a1defab58a29e60a0906767307d146249c8dfdc1fd5802',to_sha256:'8b57e5d9e5205d5f425be3e0164d3f67a9a56ba463d47e6778b116002cea2ee8',reason:'Historical native QA timestamps include a +03 offset; require an explicit zone and compare finite UTC epochs instead of lexical timestamp strings.'});
function load(filename,maxBytes=262144){const st=fs.lstatSync(filename);need(st.isFile()&&!st.isSymbolicLink()&&st.nlink===1&&st.size<=maxBytes,'QA_TOOLS_FINALIZE_FILE');return JSON.parse(fs.readFileSync(filename,'utf8'));}
function safeSource(relative){need(typeof relative==='string'&&!path.isAbsolute(relative)&&!relative.includes('\\')&&!relative.split('/').some(part=>!part||part==='.'||part==='..')&&!relative.startsWith('.private/'),'QA_TOOLS_FINALIZE_SOURCE_PATH');return path.join(repo,relative);}

/** A narrow explicit correction, never an allow-all override of old sources. */
export function validateToolSourceLineage(original,current){
  need(Array.isArray(original)&&original.length>20&&Array.isArray(current)&&current.length===original.length&&new Set(original.map(p=>p.path)).size===original.length,'QA_TOOLS_FINALIZE_SOURCE_SET');
  const changes=[];
  for(const old of original){const now=current.find(pin=>pin.path===old.path);need(now&&/^[a-f0-9]{64}$/.test(old.sha256)&&/^[a-f0-9]{64}$/.test(now.sha256),'QA_TOOLS_FINALIZE_SOURCE_SET');
    if(old.sha256!==now.sha256){need(old.path===TOOL_TIMESTAMP_CORRECTION.path&&old.sha256===TOOL_TIMESTAMP_CORRECTION.from_sha256&&now.sha256===TOOL_TIMESTAMP_CORRECTION.to_sha256,'QA_TOOLS_EXECUTION_SOURCE_CHANGED');changes.push(TOOL_TIMESTAMP_CORRECTION);}}
  need(changes.length===1,'QA_TOOLS_EXPECTED_TIMESTAMP_CORRECTION');
  return immutable({original_pin_count:original.length,unchanged:original.length-1,explicit_corrections:changes,original_source_pin_digest:digest(original),verification_source_pin_digest:digest(current)});
}

/** Reconstruct data, never republish A1. The returned grant is usable only when
 * its hash equals BOTH the persisted native grant digest and the checkpoint. */
export function reconstructHistoricalToolGrant({checkpoint,mission,descriptors}){
  const spec=mission.spec;
  need(spec.project_id===checkpoint.project_id&&spec.mission_id===checkpoint.mission_id&&spec.owner_id==='e1_tools_owner','QA_TOOLS_FINALIZE_MISSION');
  const issued=checkpoint.signed_reviews[0].payload.issued_at;
  need(checkpoint.signed_reviews.every(r=>r.payload.issued_at===issued),'QA_TOOLS_FINALIZE_REVIEW_TIMES');
  const grant={contract_version:spec.contract_version,release:spec.release,grant_id:'grant_tools_'+checkpoint.run_id,grant_version:1,mission_id:spec.mission_id,project_id:spec.project_id,owner_id:spec.owner_id,issued_by:'e1_tools_owner',spec_digest:digest(spec),issued_at:issued,expires_at:spec.deadline,revoked_at:null,revocation_reason:null,allowed_principals:['e1_tools_owner','e1_tools_head','e1_tools_coordinator','e1_tools_rg','e1_tools_rga','e1_tools_qa'],permissions:['mission.create','mission.revise','mission.revoke','plan.propose','plan.validate','plan.publish','artifact.read','artifact.write','qa.evaluate'],allowed_capabilities:descriptors.map(c=>c.ref),allowed_data_classes:['PUBLIC'],allowed_origins:['OWNER'],allowed_effect_classes:['NONE'],destinations:[],max_tasks:2,max_actions:0,max_replans:0,budget_cap:{currency:'NONE',amount_micros:'0'}};
  need(digest(grant)===mission.grant_digest&&mission.grant_digest===checkpoint.grant_digest,'QA_TOOLS_HISTORICAL_GRANT_HASH');return immutable(grant);
}

function coldChild(message){return new Promise((resolve,reject)=>{
  const env=Object.fromEntries(['SystemRoot','WINDIR','PATH','TEMP','TMP'].filter(k=>process.env[k]).map(k=>[k,process.env[k]])),peer=fork(new URL('./cold-readback.mjs',import.meta.url),[],{cwd:repo,env,stdio:['ignore','ignore','pipe','ipc'],windowsHide:true});let result;
  const timer=setTimeout(()=>{peer.kill();reject(Error('QA_TOOLS_FINALIZE_TIMEOUT'));},30000);
  peer.stderr.on('data',()=>{});peer.on('message',m=>{if(m.type==='QA_READY')return;result=m;peer.disconnect();});
  peer.once('error',()=>{clearTimeout(timer);reject(Error('QA_TOOLS_FINALIZE_SPAWN'));});
  peer.once('exit',code=>{clearTimeout(timer);if(code!==0||result?.type!=='COLD_VERIFIED')reject(Object.assign(Error(result?.code??'QA_TOOLS_FINALIZE_COLD_FAILED'),{code:result?.code??'QA_TOOLS_FINALIZE_COLD_FAILED'}));else resolve(result);});peer.send(message);
});}

/** Read-only completion of the ALREADY EXECUTED two-task canary. No utility,
 * version probe, model, A1 publication, native completion or QA mutation runs. */
export async function verifyPersistedTools(config){
  exact(config,['run_id','checkpointPath','resourcePath']);need(/^[a-z][a-z0-9_]{0,39}$/.test(config.run_id)&&path.isAbsolute(config.checkpointPath)&&path.isAbsolute(config.resourcePath),'QA_TOOLS_FINALIZE_CONFIG');
  const originalCheckpointBytes=fs.readFileSync(config.checkpointPath),cp=load(config.checkpointPath),checkpoint_sha256=sha(originalCheckpointBytes);
  need(cp.run_id===config.run_id&&cp.completed_tasks===2&&cp.reason==='QA_TOOLS_REVIEW_CURRENT'&&cp.model_calls===0&&cp.paid_calls===0&&cp.signed_reviews?.length===2&&cp.actual_tool_probes?.length===2&&cp.launches?.length===2,'QA_TOOLS_FINALIZE_CHECKPOINT');
  const currentPins=cp.source_pins.map(pin=>({path:pin.path,sha256:sha(fs.readFileSync(safeSource(pin.path)))})),lineage=validateToolSourceLineage(cp.source_pins,currentPins),resource=validateResourceDescriptor(load(config.resourcePath));
  let snapshot,events;const db=await createPsqlSession(resource,{role:'qa'});
  try{const coordinator=createCoordinator({db,project_id:cp.project_id});snapshot=await coordinator.snapshot();events=await coordinator.events();}finally{await db.close();}
  const mission=snapshot.missions.find(m=>m.mission_id===cp.mission_id),nativeTasks=snapshot.tasks.filter(t=>t.mission_id===cp.mission_id&&t.is_current),nativePlan=snapshot.plans.find(p=>p.mission_id===cp.mission_id&&p.digest===cp.plan_digest);
  need(mission?.state==='COMPLETE'&&mission.plan_digest===cp.plan_digest&&nativeTasks.length===2&&nativeTasks.every(t=>t.state==='ACCEPTED')&&nativePlan&&digest(nativePlan.document)===cp.plan_digest,'QA_TOOLS_FINALIZE_NATIVE_COMPLETE');
  const signed=TOOL_CANARY_INPUTS.map(item=>{const matches=cp.signed_reviews.filter(review=>review.payload.profile_id===item.profile_id);need(matches.length===1,'QA_TOOLS_FINALIZE_PROFILE_SET');return matches[0];});
  const descriptors=signed.map(review=>toolCapability(review.payload.profile_id,review.payload.expires_at)),grant=reconstructHistoricalToolGrant({checkpoint:cp,mission,descriptors});
  const entries=signed.map((review,index)=>({descriptor:descriptors[index],executor_type:toolProfile(review.payload.profile_id).executor_type,provides:['text.literal-search'],installed:true,available:true,health_until:review.payload.expires_at,quality:review.payload.quality,cost:review.payload.cost}));
  const expected=[],operations=[];
  for(let index=0;index<TOOL_CANARY_INPUTS.length;index++){
    const fixed=TOOL_CANARY_INPUTS[index],task=nativeTasks.find(t=>t.task_id===fixed.task_id),review=signed[index],descriptor=descriptors[index];need(task,'QA_TOOLS_FINALIZE_TASK_SET');
    const passed=events.filter(e=>e.mission_id===cp.mission_id&&e.task_id===task.task_id&&e.kind==='QA_PASS'&&e.body.result_hash===task.result_hash&&e.body.evaluator_id==='e1_tools_qa');need(passed.length===1,'QA_TOOLS_FINALIZE_QA_EVENT');
    verifyPublicToolReview({review,publicKey:cp.review_public_key,expectedFingerprint:cp.review_key_fingerprint,profile_id:fixed.profile_id,descriptor,now:passed[0].at});
    const choice=chooseExecutor({request:{capability_id:fixed.semantic_need,quality_suite_digest:TOOL_QUALITY_SUITE_DIGEST,min_quality_score:1000,max_cost_micros:0,data_class:'PUBLIC',origin:'OWNER'},candidates:entries,grant,now:review.payload.issued_at});
    need(digest(choice)===task.result.evidence.choice_digest,'QA_TOOLS_HISTORICAL_CHOICE_HASH');
    const binding={mission_id:cp.mission_id,task_id:task.task_id,plan_digest:cp.plan_digest,result_hash:task.result_hash,evaluator_id:'e1_tools_qa'},reviewContext={review,publicKey:cp.review_public_key,expectedFingerprint:cp.review_key_fingerprint,descriptor,profile_id:fixed.profile_id,choice};
    const inspected=inspectNativeToolTask({snapshot,binding,...reviewContext,expectedState:'ACCEPTED',now:passed[0].at});
    const launches=cp.launches.filter(l=>l.profile_id===fixed.profile_id&&l.native_scope.mission_id===cp.mission_id&&l.native_scope.task_id===task.task_id&&String(l.native_scope.fence)===String(task.fence)&&l.native_scope.worker_id===task.producer_id&&l.native_scope.plan_digest===task.plan_digest&&l.pid>0);need(launches.length===1,'QA_TOOLS_FINALIZE_ORIGINAL_PROCESS');
    operations.push({task_id:task.task_id,worker_id:task.producer_id,fence:task.fence,executor_kind:task.executor_kind,choice,choice_provenance:'DETERMINISTIC_RECONSTRUCTION_HASH_MATCHES_ORIGINAL_NATIVE_CHOICE_DIGEST',result_hash:task.result_hash,output:task.result.output,execution_digest:inspected.execution_digest,launch:launches[0],qa_native_event:passed[0],qa_process_pid:'NOT_CHECKPOINTED',evaluation:inspected});expected.push({binding,reviewContext});
  }
  const cold=await coldChild({resource,project_id:cp.project_id,mission_id:cp.mission_id,expected});need(cold.status==='PASS'&&cold.pid!==process.pid&&cold.outputs.length===2,'QA_TOOLS_FINALIZE_COLD');
  const afterPins=cp.source_pins.map(pin=>({path:pin.path,sha256:sha(fs.readFileSync(safeSource(pin.path)))}));need(digest(afterPins)===digest(currentPins)&&sha(fs.readFileSync(config.checkpointPath))===checkpoint_sha256,'QA_TOOLS_FINALIZE_SOURCE_OR_CHECKPOINT_CHANGED');
  const report={schema:'awe.e1.native-tool-canary/1',status:'PASS_NATIVE_TOOL_DISPATCH',run_id:cp.run_id,started_at:cp.started_at,verified_at:new Date().toISOString(),project_id:cp.project_id,mission_id:cp.mission_id,source_pins:cp.source_pins,source_pin_digest:digest(cp.source_pins),verification_source_pins:currentPins,source_lineage:lineage,verifier:{path:'E1/qa-tools/verify-persisted.mjs',sha256:sha(fs.readFileSync(fileURLToPath(import.meta.url)))},original_checkpoint_sha256:checkpoint_sha256,original_checkpoint_status:cp.status,original_cold_failure:cp.reason,finalization_mode:'READ_ONLY_EXISTING_COMPLETED_MISSION_NO_REEXECUTION',catalog:{...CATALOG_PIN,full_catalog_exported:false,lifecycle:'CANDIDATES_ONLY'},actual_tool_probes:cp.actual_tool_probes,signed_reviews:signed,review_public_key:cp.review_public_key,review_key_fingerprint:cp.review_key_fingerprint,fixture:{spec:mission.spec,grant,native_plan:nativePlan.document,oracle_digest:TOOL_CANARY_ORACLE_DIGEST,rubric_digest:TOOL_CANARY_RUBRIC_DIGEST},operations,cold,native_tool_dispatches:2,reexecuted_utilities:0,new_model_calls:0,model_calls:0,paid_calls:0,api_actual_cost_micros:0,native_mutations_during_finalization:0,new_native_read_sessions:2,native_ledger:{spent:Number(snapshot.project.spent),reserved:Number(snapshot.project.reserved),quota_used:Number(snapshot.project.quota_used),model_attempts:0,cloud_attempts:0,effect_intents:0},installation_performed:false,external_effects:0,full_catalog_exported:false,proof_scope:'BOUNDED_NATIVE_UTILITY_DISPATCH',coding_autonomy:'NOT_CLAIMED',dynamic_agents:'NOT_TESTED',four_way_live_model_comparison:'NOT_RUN',limitations:['Original full choice JSON was not checkpointed; reconstruction is accepted only because its digest matches each original native result.','Original QA process PIDs and catalog-search result digests were not checkpointed. Native independent QA_PASS events and the original execution source pins are preserved.','The UTC comparison correction affects historical cold verification only; the original tool dispatcher and fixed utility profiles are unchanged.'],accepted:false};
  need(!JSON.stringify(report).includes(os.homedir()),'QA_TOOLS_FINALIZE_PRIVATE_PATH');
  const relative='E1/tooling/evidence/NATIVE-'+cp.run_id+'.json',output=path.join(repo,relative);fs.mkdirSync(path.dirname(output),{recursive:true});fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n',{flag:'wx'});return report;
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  need(process.argv[2]==='--read-only-finalize'&&process.argv.length===4,'QA_TOOLS_FINALIZE_EXPLICIT_COMMAND');
  verifyPersistedTools(load(process.argv[3])).then(report=>console.log(JSON.stringify({status:report.status,run_id:report.run_id,project_id:report.project_id,original_native_dispatches:2,reexecuted_utilities:0,new_model_calls:0,native_mutations:0,evidence:'E1/tooling/evidence/NATIVE-'+report.run_id+'.json'}))).catch(error=>{console.error(JSON.stringify({status:'BLOCKED_READ_ONLY_FINALIZATION',reason:error.code??'QA_TOOLS_FINALIZE_FAILED',reexecuted_utilities:0,new_model_calls:0}));process.exitCode=1;});
}
