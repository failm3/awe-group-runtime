import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {fork} from 'node:child_process';
import {RELEASE,CONTRACT_VERSION,digest,immutable,need,exact,validatePlanRevision} from '../contracts/index.mjs';
import {createOfflineAuthority,authorityPorts} from '../mission/authority.mjs';
import {createMissionIngress} from '../mission/ingress.mjs';
import {createNativeE1Host} from '../host/staging.mjs';
import {createAuthorityClient} from '../coordinator/authority-server.mjs';
import {validateResourceDescriptor} from '../coordinator/resource.mjs';
import {loadPinnedCatalogRepository} from './catalog.mjs';
import {probeInstalledTool,signToolReview,activateToolReview,keyFingerprint} from './review.mjs';
import {TOOL_QUALITY_SUITE_DIGEST,TEXT_INPUT_SCHEMA} from './profiles.mjs';
import {chooseExecutor} from './policy.mjs';
import {createToolDispatcher} from './dispatch.mjs';
import {TOOL_CANARY_INPUTS,TOOL_CANARY_ORACLE_DIGEST} from '../qa-tools/oracle.mjs';

const repo=fileURLToPath(new URL('../../',import.meta.url));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const zero={currency:'NONE',amount_micros:'0'};
const versioned=value=>({contract_version:CONTRACT_VERSION,release:RELEASE,...value});
const safeEnv=()=>Object.fromEntries(['SystemRoot','WINDIR','PATH','TEMP','TMP'].filter(k=>process.env[k]).map(k=>[k,process.env[k]]));
function load(filename){const st=fs.lstatSync(filename);need(st.isFile()&&!st.isSymbolicLink()&&st.nlink===1&&st.size<=65536,'TOOL_CANARY_PRIVATE_CONFIG');return JSON.parse(fs.readFileSync(filename,'utf8'));}
function save(filename,value){fs.mkdirSync(path.dirname(filename),{recursive:true});const temporary=filename+'.tmp';fs.writeFileSync(temporary,JSON.stringify(value,null,2)+'\n',{mode:0o600});fs.renameSync(temporary,filename);}
export function validateToolCanaryConfig(value){exact(value,['run_id','resourcePath','catalogPath']);need(/^[a-z][a-z0-9_]{0,39}$/.test(value.run_id)&&typeof value.resourcePath==='string'&&path.isAbsolute(value.resourcePath)&&typeof value.catalogPath==='string'&&path.isAbsolute(value.catalogPath),'TOOL_CANARY_CONFIG');return immutable(value);}

export function toolingCanarySourcePins(){
  const paths=['contracts/canonical.mjs','awe/project_factory/factory.mjs','awe/state/errors.mjs','awe/tool_registry/common.mjs','awe/tool_registry/discovery.mjs','awe/tool_registry/taxonomy.mjs','E1/contracts/index.mjs','E1/contracts/schemas.mjs','E1/mission/authority.mjs','E1/mission/ingress.mjs','E1/host/staging.mjs','E1/coordinator/errors.mjs','E1/coordinator/admission.mjs','E1/coordinator/authority-server.mjs','E1/coordinator/coordinator.mjs','E1/coordinator/psql-session.mjs','E1/coordinator/resource.mjs',...['catalog.mjs','dispatch.mjs','local-execution.mjs','policy.mjs','profiles.mjs','review.mjs','native-canary.mjs'].map(p=>'E1/tooling/'+p),...['oracle.mjs','leaf.mjs','cold-readback.mjs'].map(p=>'E1/qa-tools/'+p)];
  return immutable(paths.sort().map(p=>({path:p,sha256:sha(fs.readFileSync(path.join(repo,p)))})));
}

export function createNativeToolMission({run_id,entries,now=new Date().toISOString(),deadline=new Date(Date.parse(now)+600000).toISOString()}){
  need(/^[a-z][a-z0-9_]{0,39}$/.test(run_id)&&Array.isArray(entries)&&entries.length===2,'TOOL_CANARY_MISSION');
  const project_id='prj_tools_'+run_id,mission_id='mission_tools_'+run_id,capabilities=entries.map(e=>e.descriptor);
  need(entries.every(e=>e.health_until>deadline),'TOOL_CANARY_REVIEW_DEADLINE');
  const principals=[['e1_tools_owner','e1_tools_owner','OWNER'],['e1_tools_head','e1_tools_head','HEAD'],['e1_tools_coordinator','e1_tools_coordinator','COORDINATOR'],['e1_tools_rg','e1_tools_rg','EXECUTOR'],['e1_tools_rga','e1_tools_rga','EXECUTOR'],['e1_tools_qa','e1_tools_qa_independent','QA']].map(([principal_id,subject_id,role])=>({principal_id,subject_id,role,projects:[project_id]}));
  const authority=createOfflineAuthority(principals),contexts=Object.fromEntries(principals.map(p=>[p.principal_id,authority.issueContext(p.principal_id,project_id)]));
  const rubric={checks:['schema','sources','scope','product'],oracle_digest:TOOL_CANARY_ORACLE_DIGEST,quality_suite_digest:TOOL_QUALITY_SUITE_DIGEST,scope:'TWO_FIXED_STDIN_UTILITIES_NOT_AUTONOMY'};
  const domainManifest=versioned({manifest_id:'domain.tools_canary',version:'1.0.0',project_id,domain:'software',description:'Two reviewed installed utility profiles, exact synthetic stdin, native A1/A2 dispatch and independent QA.',capabilities:capabilities.map(c=>c.ref),qa_rubric:{rubric_id:'e1.tools.canary.rubric',digest:digest(rubric),checks:rubric.checks}});
  const fact=versioned({artifact_id:'inputs_'+run_id,project_id,mission_id,uri:'artifact:tools/'+run_id+'/inputs',digest:digest(TOOL_CANARY_INPUTS),media_type:'application/json',schema:{schema_id:'e1.tools.synthetic-inputs',version:'1.0.0',digest:digest(TEXT_INPUT_SCHEMA)},data_class:'PUBLIC',origin:'OWNER',producer_id:'e1_tools_owner',created_at:now});
  const spec=versioned({mission_id,project_id,owner_id:'e1_tools_owner',revision:1,goal:'TOOL-NATIVE-01: use the approved existing literal-search utilities on fixed synthetic stdin through ordinary E1 capabilities, produce exact persisted outputs and independent QA. Zero model calls, installations and external effects; this does not demonstrate coding autonomy or dynamic agents.',criteria:[{criterion_id:'tools',text:'Both declared utility tasks complete through actual native claims, fixed process invocation and independent literal-search QA.'}],facts_refs:[fact],domain_manifest:{manifest_id:domainManifest.manifest_id,version:domainManifest.version,digest:digest(domainManifest)},requested_capabilities:capabilities.map(c=>c.ref),budget:zero,deadline,data_classes:['PUBLIC'],allowed_origins:['OWNER'],max_replans:0,max_actions:0});
  const grant=versioned({grant_id:'grant_tools_'+run_id,grant_version:1,mission_id,project_id,owner_id:spec.owner_id,issued_by:'e1_tools_owner',spec_digest:digest(spec),issued_at:now,expires_at:deadline,revoked_at:null,revocation_reason:null,allowed_principals:principals.map(p=>p.principal_id),permissions:['mission.create','mission.revise','mission.revoke','plan.propose','plan.validate','plan.publish','artifact.read','artifact.write','qa.evaluate'],allowed_capabilities:capabilities.map(c=>c.ref),allowed_data_classes:['PUBLIC'],allowed_origins:['OWNER'],allowed_effect_classes:['NONE'],destinations:[],max_tasks:2,max_actions:0,max_replans:0,budget_cap:zero});
  const choices=TOOL_CANARY_INPUTS.map(item=>chooseExecutor({request:{capability_id:item.semantic_need,quality_suite_digest:TOOL_QUALITY_SUITE_DIGEST,min_quality_score:1000,max_cost_micros:0,data_class:'PUBLIC',origin:'OWNER'},candidates:entries,grant,now}));
  need(choices[0].decision==='SELECTED'&&choices[0].selected.executor_type==='script'&&choices[1].decision==='SELECTED'&&choices[1].selected.executor_type==='program','TOOL_CANARY_REAL_SELECTION');
  const tasks=TOOL_CANARY_INPUTS.map((item,index)=>{
    const capability=capabilities.find(c=>digest(c.ref)===choices[index].selected.ref_digest);need(capability,'TOOL_CANARY_SELECTED_REF');
    return versioned({task_id:item.task_id,title:'Use '+item.profile_id+' with fixed synthetic stdin',capability:capability.ref,input:item.input,depends_on:[],dependency_bindings:[],criterion_ids:['tools'],budget:zero,deadline,timeout_ms:capability.timeout_ms,data_classes:['PUBLIC'],origin:{kind:'OWNER',source_digests:[fact.digest]},effect:versioned({effect_id:'intent_'+item.task_id,mission_id,project_id,task_id:item.task_id,effect_class:'NONE',permission:null,destination:null,business_key:null,payload_digest:digest(item.input),max_actions:0,reconcile_capability:null,unknown_policy:'HOLD',outcome:'NOT_STARTED'}),retry:{max_attempts:1,retry_on:[],on_unknown:'HOLD'},qa:{rubric_id:domainManifest.qa_rubric.rubric_id,rubric_digest:domainManifest.qa_rubric.digest,required_checks:rubric.checks,reviewer_role:'QA'}});
  });
  const plan=versioned({plan_id:'plan_tools_'+run_id,mission_id,project_id,revision:1,spec_digest:digest(spec),grant_digest:digest(grant),grant_version:1,previous_digest:null,proposed_by:'e1_tools_head',reason:'Host-declared bounded tool tasks; existing AWE selector chooses shared semantic implementation and explicit second-profile coverage.',created_at:now,budget:zero,deadline,tasks});
  validatePlanRevision(plan,{spec,grant,capabilities,domainManifest,now});
  const ingress=createMissionIngress({authority,projectId:project_id,capabilities,domainManifests:[domainManifest]});
  ingress.mission.create({spec,grant},contexts.e1_tools_owner);
  const proposed=ingress.plan.propose({plan},contexts.e1_tools_head),checked=ingress.plan.validate({mission_id,plan_digest:proposed.plan.digest},contexts.e1_tools_coordinator);
  ingress.plan.publish({mission_id,plan_digest:proposed.plan.digest,validation_digest:checked.validation.digest},contexts.e1_tools_coordinator);
  return {spec,grant,plan,choices,capabilities,domainManifest,rubric,principals,authority,contexts,ingress};
}

function isolatedReader(module,message,timeout=30000){return new Promise((resolve,reject)=>{
  const child=fork(new URL(module,import.meta.url),[],{cwd:repo,env:safeEnv(),stdio:['ignore','ignore','pipe','ipc'],windowsHide:true});let outcome;
  const timer=setTimeout(()=>{child.kill();reject(Error('TOOL_CANARY_READER_TIMEOUT'));},timeout);
  child.stderr.on('data',()=>{});child.on('message',m=>{if(m.type==='QA_READY')return;outcome=m;child.disconnect();});
  child.once('error',()=>{clearTimeout(timer);reject(Error('TOOL_CANARY_READER_SPAWN'));});
  child.once('exit',code=>{clearTimeout(timer);if(code!==0||!outcome||outcome.type==='ERROR')reject(Object.assign(Error(outcome?.code??'TOOL_CANARY_READER_FAILED'),{code:outcome?.code??'TOOL_CANARY_READER_FAILED'}));else resolve(outcome);});
  child.send(message);
});}

/** Explicit trusted-host canary. There is no install, shell command generation,
 * model invocation, separate scheduler or funding path. */
export async function runNativeToolCanary(config){
  const {run_id,resourcePath,catalogPath}=validateToolCanaryConfig(config),privateRoot=path.join(repo,'.private','tools-'+run_id);
  need(!fs.existsSync(privateRoot),'TOOL_CANARY_RUN_EXISTS');fs.mkdirSync(privateRoot,{recursive:true,mode:0o700});
  const checkpoint=path.join(privateRoot,'CHECKPOINT.json'),started_at=new Date().toISOString(),source_pins=toolingCanarySourcePins();
  const record=value=>save(checkpoint,{...(fs.existsSync(checkpoint)?load(checkpoint):{}),...value,run_id,updated_at:new Date().toISOString()});
  record({status:'PREFLIGHT',started_at,source_pins,model_calls:0,paid_calls:0});
  let host;
  try{
    const resource=validateResourceDescriptor(load(resourcePath)),catalog=loadPinnedCatalogRepository({filename:catalogPath,principal:{tenant_id:'e1_tool_canary',actor_id:'host_reviewer'},projectIds:['e1_tool_canary']});
    const key=generateKeyPairSync('ed25519'),publicKey=key.publicKey.export({type:'spki',format:'pem'}),expectedFingerprint=keyFingerprint(key.publicKey),now=new Date().toISOString(),expires_at=new Date(Date.now()+1800000).toISOString(),home=os.homedir();
    const definitions=[['ripgrep-stdin','Радар-0673','ripgrep','rg.exe','LICENSE-MIT'],['ripgrep-all-stdin','Радар-0046','rga','rga.exe','LICENSE.md']],entries=[],probes=[],reviews=[],binarySets=new Map();
    const catalogDecisions=[];
    for(const [profile_id,catalog_id,app,exe,license]of definitions){
      const query={project_id:'e1_tool_canary',need:'code search',capabilities:['code.develop'],text_filter:app==='ripgrep'?'BurntSushi/ripgrep':'phiresky/ripgrep-all',mode:'CANDIDATES',limit:5};
      const discovered=await catalog.search(query),catalog_record=await catalog.getCatalogRecord('e1_tool_canary',catalog_id);
      need(discovered.physical_decision==='DENY'&&discovered.results.every(row=>row.permitted===false)&&discovered.results.some(row=>row.tool_id===catalog_record?.tool_id),'TOOL_CANARY_CATALOG_NOT_AUTHORITY');
      catalogDecisions.push({profile_id,query_digest:digest(query),catalog_result_digest:digest(discovered),selected_catalog_id:catalog_id,physical_decision:'DENY',authority:'NONE'});
      const root=path.join(home,'scoop/apps',app,'current'),binaries={tool:path.join(root,exe)};if(profile_id==='ripgrep-all-stdin')binaries.rg=path.join(home,'scoop/apps/ripgrep/current/rg.exe');
      const probe=probeInstalledTool({profile_id,catalog_record,binaries,distributionManifest:path.join(root,'scoop-manifest.json'),licenseFile:path.join(root,license),now});
      const review=signToolReview({probe,privateKey:key.privateKey,issued_at:now,expires_at}),entry=activateToolReview({review,trustedPublicKey:key.publicKey,expectedKeyFingerprint:expectedFingerprint,catalog_record,binaries,now});
      probes.push(probe);reviews.push(review);entries.push(entry);binarySets.set(profile_id,Object.freeze(binaries));
    }
    record({status:'HOST_REVIEW_COMPLETE',actual_tool_probes:probes,signed_reviews:reviews,review_public_key:publicKey,review_key_fingerprint:expectedFingerprint});
    const f=createNativeToolMission({run_id,entries,now}),policy={budget_cap_micros:'0',quota_cap:1,max_parallel:1,resource_limits:{cpu:1},capabilities:Object.fromEntries(f.capabilities.map(c=>[c.ref.capability_id,{resource_keys:['cpu'],max_claims:1,priority:0}]))};
    host=await createNativeE1Host({resource,authority:f.authority,ingress:f.ingress,capabilities:f.capabilities,domainManifests:[f.domainManifest],ownerGrants:[f.grant],policy});
    await host.admitPublished(f.spec.mission_id,f.contexts.e1_tools_coordinator);
    const qa=host.authority.issueCredential({role:'QA',principal_id:'e1_tools_qa',project_id:f.spec.project_id}),auth=authorityPorts(f.authority),lookup=new Map(entries.map(entry=>[digest(entry.descriptor.ref),entry]));
    const operations=[],expected=[],launches=[];
    record({status:'NATIVE_ADMITTED',project_id:f.spec.project_id,mission_id:f.spec.mission_id,grant_digest:digest(f.grant),plan_digest:digest(f.plan),review_key_fingerprint:expectedFingerprint});
    for(let index=0;index<TOOL_CANARY_INPUTS.length;index++){
      const item=TOOL_CANARY_INPUTS[index],entry=entries[index],worker_id=index===0?'e1_tools_rg':'e1_tools_rga',context=f.contexts[worker_id];
      const credential=host.authority.issueCredential({role:'WORKER',principal_id:worker_id,project_id:f.spec.project_id,capabilities:[entry.descriptor.ref.capability_id]}),client=createAuthorityClient({url:host.authority.url,token:credential.token});
      const claim=await client.claim({mission_id:f.spec.mission_id,task_id:item.task_id,capabilities:[entry.descriptor.ref.capability_id],lease_ms:30000});
      need(claim.status==='CLAIMED','TOOL_CANARY_CLAIM');
      const scope={mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence,plan_digest:claim.plan_digest};
      const dispatcher=createToolDispatcher({lookup:ref=>lookup.get(ref),authenticate:actor=>auth.verify(actor),resolveGrant:request=>{auth.verify(f.contexts.e1_tools_owner);need(request.mission_id===f.spec.mission_id,'TOOL_CANARY_GRANT_SCOPE');return f.grant;},binaryResolver:profile=>{need(binarySets.has(profile),'TOOL_CANARY_BINARY_PROFILE');return binarySets.get(profile);},launchObserver:value=>{launches.push(immutable(value));},coordinator:{project_id:f.spec.project_id,snapshot:()=>host.coordinator.snapshot(),heartbeat:request=>client.heartbeat(request)}});
      const dispatched=await dispatcher.dispatch({context,scope,choice:f.choices[index],input:item.input});
      need(dispatched.decision==='EXECUTED_PENDING_COMPLETE_AND_QA'&&dispatched.native_claim_checked===true,'TOOL_CANARY_DISPATCH');
      const complete=await client.complete({...scope,result:dispatched.result,result_hash:dispatched.result_hash});need(complete.status==='WAIT_QA','TOOL_CANARY_WAIT_QA');
      record({status:'TOOL_EXECUTED_WAIT_QA',task_id:item.task_id,result_hash:dispatched.result_hash,output:dispatched.result.output,execution_digest:digest(dispatched.result.evidence.execution),launches});
      const binding={mission_id:f.spec.mission_id,task_id:item.task_id,plan_digest:digest(f.plan),result_hash:dispatched.result_hash,evaluator_id:'e1_tools_qa'};
      const reviewContext={review:reviews[index],publicKey,expectedFingerprint,descriptor:entry.descriptor,profile_id:item.profile_id,expectedInput:item.input,choice:f.choices[index]};
      const checked=await isolatedReader('../qa-tools/leaf.mjs',{url:host.authority.url,token:qa.token,binding,reviewContext});
      need(checked.verdict==='PASS'&&checked.value.status==='ACCEPTED','TOOL_CANARY_INDEPENDENT_QA');
      const observed=launches.filter(value=>value.native_scope.task_id===item.task_id);need(observed.length===1&&observed[0].pid>0,'TOOL_CANARY_ACTUAL_PROCESS');
      operations.push({task_id:item.task_id,worker_id,fence:claim.fence,executor_kind:entry.descriptor.executor_kind,choice:f.choices[index],result_hash:dispatched.result_hash,output:dispatched.result.output,execution_digest:digest(dispatched.result.evidence.execution),launch:observed[0],qa:checked});expected.push({binding,reviewContext});
      record({status:'TASK_ACCEPTED',task_id:item.task_id,result_hash:dispatched.result_hash,completed_tasks:operations.length});
    }
    const snapshot=await host.coordinator.snapshot();need(snapshot.missions.find(m=>m.mission_id===f.spec.mission_id)?.state==='COMPLETE'&&snapshot.attempts.length===0&&Number(snapshot.project.spent)===0&&Number(snapshot.project.reserved)===0&&Number(snapshot.project.quota_used)===0,'TOOL_CANARY_NATIVE_FINAL');
    await host.close();host=null;
    const cold=await isolatedReader('../qa-tools/cold-readback.mjs',{resource,project_id:f.spec.project_id,mission_id:f.spec.mission_id,expected});
    need(cold.status==='PASS'&&cold.pid!==process.pid&&cold.outputs.length===2,'TOOL_CANARY_COLD');
    need(digest(toolingCanarySourcePins())===digest(source_pins),'TOOL_CANARY_SOURCE_CHANGED');
    const report={schema:'awe.e1.native-tool-canary/1',status:'PASS_NATIVE_TOOL_DISPATCH',run_id,started_at,finished_at:new Date().toISOString(),project_id:f.spec.project_id,mission_id:f.spec.mission_id,source_pins,source_pin_digest:digest(source_pins),catalog:catalog.source,catalog_decisions:catalogDecisions,host_review_status:'TESTED_HOST_ONLY_NOT_NATIVE_AUTHORITY',actual_tool_probes:probes,signed_reviews:reviews,review_public_key:publicKey,review_key_fingerprint:expectedFingerprint,fixture:{spec:f.spec,grant:f.grant,plan:f.plan,domainManifest:f.domainManifest,rubric:f.rubric},operations,cold,native_tool_dispatches:2,model_calls:0,paid_calls:0,api_actual_cost_micros:0,native_ledger:{spent:Number(snapshot.project.spent),reserved:Number(snapshot.project.reserved),quota_used:Number(snapshot.project.quota_used),model_attempts:0},installation_performed:false,external_effects:0,full_catalog_exported:false,authority_profile:'HOST_LOCAL_A1_BOOTSTRAP_BOUND_TO_NATIVE_E1_NOT_PRODUCTION_AUTHN',awe_actions:['deterministic executor policy selection','native claim and fixed utility dispatch','persisted outputs and independent QA'],sol_actions:['defined bounded synthetic mission and second-profile coverage','wired trusted ports and supplied scoped host grants','reviewed installed tools and started this canary'],proof_scope:'BOUNDED_NATIVE_UTILITY_DISPATCH_NOT_CODING_AUTONOMY',dynamic_agents:'NOT_TESTED',four_way_live_model_comparison:'NOT_RUN',accepted:false};
    need(!JSON.stringify(report).includes(home),'TOOL_CANARY_PRIVATE_PATH_EXPORT');
    const relative='E1/tooling/evidence/NATIVE-'+run_id+'.json';save(path.join(repo,relative),report);record({status:report.status,evidence:relative,report_sha256:sha(Buffer.from(JSON.stringify(report,null,2)+'\n'))});
    return report;
  }catch(error){record({status:'BLOCKED_NATIVE_TOOL_CANARY',reason:error.code??'TOOL_CANARY_FAILED'});throw error;}
  finally{if(host)await host.close().catch(()=>{});}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  need(process.argv[2]==='--authorized-native-tools'&&process.argv.length===4,'TOOL_CANARY_EXPLICIT_COMMAND');
  runNativeToolCanary(load(process.argv[3])).then(report=>console.log(JSON.stringify({status:report.status,project_id:report.project_id,mission_id:report.mission_id,native_tool_dispatches:report.native_tool_dispatches,model_calls:0,paid_calls:0,api_actual_cost_micros:0,evidence:'E1/tooling/evidence/NATIVE-'+report.run_id+'.json'}))).catch(error=>{console.error(JSON.stringify({status:'BLOCKED_NATIVE_TOOL_CANARY',reason:error.code??'TOOL_CANARY_FAILED',model_calls:0,paid_calls:0}));process.exitCode=1;});
}
