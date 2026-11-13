import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {fork,spawnSync} from 'node:child_process';
import {createNativeE1Host} from './staging.mjs';
import {createAuthorityClient} from '../coordinator/index.mjs';
import {createMaintenanceMission,createBrokerRegistry,createLocalModelBroker,selectExecutor} from '../broker/index.mjs';
import {digest,need} from '../contracts/index.mjs';
import {verifyPersistedTaskArtifact,modelRequestIds} from './artifact-binding.mjs';

const repo=fileURLToPath(new URL('../../',import.meta.url));
function load(filename){const st=fs.lstatSync(filename);need(st.isFile()&&!st.isSymbolicLink()&&st.size<=65536,'E1_RESOURCE_FILE');return JSON.parse(fs.readFileSync(filename,'utf8'));}
function plainFixture(f){return {source:f.source,spec:f.spec,grant:f.grant,domainManifest:f.domainManifest,rubric:f.rubric,principals:f.principals,bootstrapPlan:f.bootstrapPlan,registry:{descriptors:f.registry.descriptors}};}
function child(module,config,timeout=20000){
 const env={};for(const k of ['SystemRoot','WINDIR','PATH','TEMP','TMP'])if(process.env[k])env[k]=process.env[k];
 return new Promise((resolve,reject)=>{
  const peer=fork(new URL(module,import.meta.url),[],{cwd:repo,env,stdio:['ignore','ignore','pipe','ipc'],windowsHide:true});let result,err='';
  const timer=setTimeout(()=>{peer.kill();reject(Error('E1_FIXED_CHILD_TIMEOUT'));},timeout);
  peer.stderr.on('data',b=>err=(err+b.toString()).slice(-4096));
  peer.on('message',m=>{if(m.type==='ERROR')result={error:m.code};else result=m;});
  peer.once('error',e=>{clearTimeout(timer);reject(e);});
  peer.once('exit',code=>{clearTimeout(timer);if(code!==0||result?.error||!result)reject(Object.assign(Error(result?.error??'E1_FIXED_CHILD_FAILED'),{details:err}));else resolve(result);});
  peer.send(config);
 });
}
function publish(f,plan){
 const proposed=f.ingress.plan.propose({plan},f.contexts.head),validated=f.ingress.plan.validate({mission_id:f.spec.mission_id,plan_digest:proposed.plan.digest},f.contexts.coordinator);
 return f.ingress.plan.publish({mission_id:f.spec.mission_id,plan_digest:proposed.plan.digest,validation_digest:validated.validation.digest},f.contexts.coordinator);
}
export async function runMaintenanceCanary({resourcePath=path.join(repo,'.private/e1-resource.json'),suffix='live_'+Date.now().toString(36),timeoutMs=120000,maxOutputTokens=512,concise=true,registryTime,previousUnknownMission=null}={}){
 const started_at=new Date().toISOString(),resource=load(resourcePath);
 const registry=registryTime?createBrokerRegistry({now:registryTime}):createBrokerRegistry();
 const f=createMaintenanceMission({suffix,registry,concise});
 f.ingress.mission.create({spec:f.spec,grant:f.grant},f.contexts.owner);publish(f,f.bootstrapPlan);
 const policy={budget_cap_micros:'0',quota_cap:6,max_parallel:2,resource_limits:{cpu:2,local_model:1},capabilities:Object.fromEntries(f.registry.descriptors.map(cap=>[cap.ref.capability_id,{resource_keys:[cap.executor_kind==='llm'?'local_model':'cpu'],max_claims:1,priority:0}]))};
 const host=await createNativeE1Host({resource,authority:f.authority,ingress:f.ingress,capabilities:f.registry.descriptors,domainManifests:[f.domainManifest],ownerGrants:[f.grant],policy});
 const worker=host.authority.issueCredential({role:'WORKER',principal_id:'e1_worker',project_id:f.spec.project_id,capabilities:['e1.code.parse']});
 const brokerCredential=host.authority.issueCredential({role:'BROKER',principal_id:'e1_worker',project_id:f.spec.project_id,capabilities:['e1.head.plan','e1.code.review']});
 const qaCredential=host.authority.issueCredential({role:'QA',principal_id:'e1_qa',project_id:f.spec.project_id});
 const client=createAuthorityClient({url:host.authority.url,token:brokerCredential.token});
 const broker=createLocalModelBroker({accounting:client,registry:f.registry,timeoutMs,contextTokens:4096,maxOutputTokens});
 const operations=[],measured=[],privateDir=path.join(repo,'.private/canary-'+suffix),publicFile=path.join(repo,'E1/evidence2/LOCAL-CONTOUR.json');fs.mkdirSync(privateDir,{recursive:true});fs.mkdirSync(path.dirname(publicFile),{recursive:true});
 fs.writeFileSync(path.join(privateDir,'fixture.json'),JSON.stringify(plainFixture(f),null,2)+'\n');
 const runPolicy={registry_created_at:f.registry.created_at,registry_digest:f.registry.digest,broker_source_pin:f.registry.source.build_digest,capabilities:f.registry.descriptors.map(c=>({ref:c.ref,health_until:c.health_until})),concise,context_tokens:4096,max_output_tokens:maxOutputTokens,timeout_ms:timeoutMs,previous_unknown_mission:previousUnknownMission,previous_unknown_policy:'RETAIN_HOLD_UNKNOWN_AND_CHARGED_QUOTA; NO_RETRY',new_mission_spec_digest:digest(f.spec),new_mission_grant_digest:digest(f.grant)};
 const selectors={script:selectExecutor({registry:f.registry,spec:f.spec,grant:f.grant,task:{kind:'deterministic',data_label:'SYNTHETIC'}}),semantic:selectExecutor({registry:f.registry,spec:f.spec,grant:f.grant,task:{kind:'head',data_label:'SYNTHETIC'}})};
 let finalSnapshot,modelPlan,headResponse;
 async function qa(task_id,phase,extra={}){
  const state=await host.coordinator.snapshot(),task=state.tasks.find(t=>t.mission_id===f.spec.mission_id&&t.task_id===task_id&&t.is_current);
  need(task?.state==='WAIT_QA','E1_QA_PENDING_REQUIRED');
  const artifact_digest=verifyPersistedTaskArtifact(task);
  const evaluation={fixture:plainFixture(f),phase,output:task.result.output,artifact_digest,task,...extra};
  const result=await child('./qa-leaf.mjs',{url:host.authority.url,token:qaCredential.token,evaluation,binding:{mission_id:task.mission_id,task_id:task.task_id,plan_digest:task.plan_digest,result_hash:task.result_hash}});
  operations.push({kind:'INDEPENDENT_QA',task_id,phase,pid:result.pid,verdict:result.evaluation.verdict,evidence_digest:result.evaluation.evidence_digest,result_hash:task.result_hash});
  need(result.evaluation.verdict==='PASS'&&result.value.status==='ACCEPTED','E1_INDEPENDENT_QA_REJECTED');
 }
 async function parseTask(task_id){
  const result=await child('./script-leaf.mjs',{url:host.authority.url,token:worker.token,mission_id:f.spec.mission_id,task_id});
  need(result.type==='COMPLETED','E1_SCRIPT_NOT_COMPLETED');
  operations.push({kind:'SCRIPT_WORKER',task_id,pid:result.pid,result_hash:result.result_hash,executor_kind:'script'});await qa(task_id,'parse');
 }
 async function modelTask(task_id,capability_id,{head=false}={}){
  const claim=await client.claim({mission_id:f.spec.mission_id,task_id,capabilities:[capability_id],lease_ms:150000});
  need(claim.status==='CLAIMED'&&claim.task_id===task_id,'E1_MODEL_CLAIM_REQUIRED');
  const scope={mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence,...modelRequestIds(claim.mission_id,claim.task_id)};
  const response=head?await broker.generateHeadProposal({scope,spec:f.spec,grant:f.grant,source:f.source,domainManifest:f.domainManifest,authority:f.authority,headContext:f.contexts.head,plan_id:f.bootstrapPlan.plan_id,revision:2,previous_digest:digest(f.bootstrapPlan)}):await broker.invoke({scope,spec:f.spec,grant:f.grant,capability_id,input:claim.task.input,data_label:'SYNTHETIC'});
  fs.writeFileSync(path.join(privateDir,task_id+'.model.json'),JSON.stringify(response,null,2)+'\n');
  measured.push({task_id,capability_id,decision:response.decision,reason:response.reason,usage:response.usage??null,model:response.model??null,wire_attempts:response.wire_attempts??0,accounting_status:response.accounting_status??null,response_digest:response.response_digest??null});
  need(response.decision==='PROPOSED','E1_MODEL_PROPOSAL_REQUIRED:'+response.reason);
  const result={output_schema_digest:claim.task.capability.output_schema.digest,output:response.output,artifact_digest:digest(response.output),evidence:{request_hash:response.request_hash,response_digest:response.response_digest,usage:response.usage}};
  await client.complete({...scope,result,result_hash:digest(result)});
  operations.push({kind:'MODEL_TASK',task_id,executor_kind:'llm',fence:claim.fence,result_hash:digest(result)});
  await qa(task_id,head?'head':'review',head?{draft:response.draft,plan:response.plan}:{});
  return response;
 }
 try{
  await host.admitPublished(f.spec.mission_id,f.contexts.coordinator);
  await parseTask('parse_source');
  headResponse=await modelTask('head_control','e1.head.plan',{head:true});modelPlan=headResponse.plan;
  publish(f,modelPlan);await host.admitPublished(f.spec.mission_id,f.contexts.coordinator);
  const accepted=new Set();
  while(accepted.size<modelPlan.tasks.length){
   const ready=modelPlan.tasks.filter(t=>!accepted.has(t.task_id)&&t.depends_on.every(d=>accepted.has(d)));
   need(ready.length>0,'E1_GENERATED_DAG_STALLED');
   for(const task of ready){
    if(task.capability.capability_id==='e1.code.parse')await parseTask(task.task_id);
    else if(task.capability.capability_id==='e1.code.review')await modelTask(task.task_id,'e1.code.review');
    else throw Error('E1_UNBOUND_EXECUTOR');
    accepted.add(task.task_id);
   }
  }
  finalSnapshot=await host.coordinator.snapshot();
  const mission=finalSnapshot.missions.find(m=>m.mission_id===f.spec.mission_id);
  need(mission?.state==='COMPLETE','E1_CONTOUR_NOT_COMPLETE');
  const events=await host.coordinator.events(),last=events.at(-1).sequence,consumer_id='monitor_'+suffix;
  const current=await host.coordinator.getCursor(consumer_id);await host.coordinator.ackCursor({consumer_id,sequence:last,expected_sequence:current.sequence??0});
  fs.writeFileSync(path.join(privateDir,'snapshot.json'),JSON.stringify(finalSnapshot,null,2)+'\n');
  const report={schema:'awe.e1.local-contour/1',status:'PASS_REAL_LOCAL_CONTOUR',started_at,finished_at:new Date().toISOString(),run_policy:runPolicy,authority_pid:process.pid,project_id:f.spec.project_id,mission_id:f.spec.mission_id,resource_id:resource.resource_id,model_plan_digest:digest(modelPlan),bootstrap_plan_digest:digest(f.bootstrapPlan),plan_revisions:finalSnapshot.plans.filter(p=>p.mission_id===f.spec.mission_id).length,selectors,model_attempts:measured,operations,current_tasks:finalSnapshot.tasks.filter(t=>t.mission_id===f.spec.mission_id&&t.is_current).map(t=>({task_id:t.task_id,state:t.state,plan_digest:t.plan_digest,result_hash:t.result_hash})),ledger:{reserved:finalSnapshot.project.reserved,spent:finalSnapshot.project.spent,quota_used:finalSnapshot.project.quota_used,attempts:finalSnapshot.attempts.filter(a=>a.mission_id===f.spec.mission_id).map(a=>({attempt_id:a.attempt_id,state:a.state,usage:a.usage,request_hash:a.request_hash}))},cursor:{consumer_id,sequence:last},accepted:false,owner_acceptance:'NOT_REQUESTED',external_effects:0,code_changes_applied:0,github_tasks_executed:0,scope:'Synthetic code-maintenance planning and analysis; original helper intentionally not modified; not E1 Pilot acceptance'};
  fs.writeFileSync(publicFile,JSON.stringify(report,null,2)+'\n');
  await host.close();
  const cold=spawnSync(process.execPath,[fileURLToPath(new URL('./cold-readback.mjs',import.meta.url)),resourcePath,f.spec.project_id,f.spec.mission_id,consumer_id],{cwd:repo,encoding:'utf8',timeout:30000,windowsHide:true,env:Object.fromEntries(['SystemRoot','WINDIR','PATH','TEMP','TMP'].filter(k=>process.env[k]).map(k=>[k,process.env[k]]))});
  need(cold.status===0,'E1_COLD_READBACK_FAILED');const readback=JSON.parse(cold.stdout.trim());
  need(readback.pid!==process.pid&&readback.mission_state==='COMPLETE'&&readback.cursor.sequence===last&&readback.attempts.length===measured.length,'E1_COLD_STATE_DRIFT');
  fs.writeFileSync(path.join(repo,'E1/evidence2/COLD-READBACK.json'),JSON.stringify(readback,null,2)+'\n');
  console.log(JSON.stringify({status:report.status,mission_id:f.spec.mission_id,model_calls:measured.length,current_tasks:report.current_tasks.length,authority_pid:process.pid,cold_process_pid:readback.pid,evidence:'E1/evidence2/LOCAL-CONTOUR.json'}));
  return report;
 }catch(error){
  const failed={schema:'awe.e1.local-contour/1',status:'FAILED_OR_HOLD',started_at,finished_at:new Date().toISOString(),mission_id:f.spec.mission_id,project_id:f.spec.project_id,run_policy:runPolicy,reason:error.code??error.message,model_attempts:measured,operations,external_effects:0,accepted:false};
  fs.writeFileSync(path.join(privateDir,'failure.json'),JSON.stringify(failed,null,2)+'\n');fs.writeFileSync(path.join(path.dirname(publicFile),'FAILED-'+suffix+'.json'),JSON.stringify(failed,null,2)+'\n');console.error(JSON.stringify(failed));
  await host.close().catch(()=>{});throw error;
 }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 need(process.argv[2]==='--authorized-local-canary'&&process.argv.length===4,'E1_EXPLICIT_CANARY_COMMAND');
 const options=load(process.argv[3]);
 need(Object.keys(options).every(k=>['resourcePath','suffix','timeoutMs','maxOutputTokens','concise','registryTime','previousUnknownMission'].includes(k)),'E1_CANARY_CONFIG_FIELDS');
 runMaintenanceCanary(options).catch(()=>{process.exitCode=1;});
}
