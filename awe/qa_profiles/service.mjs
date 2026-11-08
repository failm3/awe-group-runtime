import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {bytesHash,copy,digest,fields,frozen,need,validateProfile,verdict,VERSION,MAP} from './contracts.mjs';
import {runProfile,runnerHash} from './runner.mjs';
import {buildFeedback} from './auto02.mjs';

// A candidate evidence producer, not a QA/state authority. It has NO state write,
// acceptance, scheduler, ledger, dispatch, issuer, or caller-verdict import API.
export function createProfileQa({statePort,artifacts,postSaveArtifacts,issuer,requirements,reference,sourceReader=()=>[],runtime={},clock=()=>new Date().toISOString()}){
 const profile=validateProfile(requirements),ref=frozen(copy(reference)),config=frozen(copy(runtime));
 const handles=new WeakMap(),serviceId=randomUUID();
 fields(ref,['project_id','task_id','version','artifact','file_hash','bytes','path','provenance_hash']);
 need(ref.project_id===profile.scope.project_id&&ref.task_id===profile.scope.task_id,'ARTIFACT_SCOPE');
 const testHash=runnerHash();
 function context(reader=artifacts){
  const state=statePort.read();statePort.live(state.pin);
  need(digest(state.pin.scope)===digest(profile.scope)&&digest(state.pin.spec)===digest(profile.spec),'PROFILE_STATE_BINDING');
  const bytes=reader.read(copy(ref));
  need(Buffer.isBuffer(bytes)&&bytes.length<=32768&&bytesHash(bytes)===ref.file_hash&&bytes.length===ref.bytes,'ARTIFACT_CHANGED');
  const sources=sourceReader();need(Array.isArray(sources)&&!sources.then,'SYNC_SOURCES_REQUIRED');
  need(Buffer.byteLength(JSON.stringify(sources))<=131072,'SOURCE_SIZE');
  need(new Set(sources.map(s=>s.id)).size===sources.length,'SOURCE_DUPLICATE');
  need(digest(statePort.read().pin)===digest(state.pin),'STATE_CHANGED');
  return {pin:copy(state.pin),bytes:Buffer.from(bytes),sources:copy(sources),hash:digest({pin:state.pin,reference:ref,profile,sources})};
 }
 function binding(){
  const c=context();return {scope:copy(profile.scope),spec:copy(profile.spec),epochs:copy(c.pin.epochs),
   config_revision:c.pin.config_revision,fence:c.pin.fence,lease_epoch:c.pin.lease_epoch,
   requirements_hash:digest(profile),artifact:copy(ref),policy_version:'QA02_PROFILE_CANDIDATE_V1'};
 }
 function identity(session,grant,role){const b=binding(),actor=issuer.check(session,grant,'VERIFY',b);need(actor.role===role,'QA02_ROLE_DENIED');return {session,grant,actor};}
 function report(handle,role){const r=handles.get(handle);need(r&&r.role===role,'QA02_REPORT_UNTRUSTED');return r;}
 function current(r){
  const c=context();need(r.binding_hash===c.hash&&r.test_code_hash===runnerHash(),'QA02_REPORT_STALE');
  if(profile.profile==='research')for(const criterion of profile.criteria){const s=c.sources.find(s=>s.id===criterion.check.source_id);if(s){const age=Date.parse(clock())-Date.parse(s.fetched_at);need(Number.isFinite(age)&&age>=0&&age<=criterion.check.max_age_ms,'SOURCE_EXPIRED');}}
  if(r.auth)identity(r.auth.session,r.auth.grant,r.auth.actor.role);
 }
 function expose(role,result,c,auth=null,extra={}){
  const evidence={version:VERSION,service_id:serviceId,run_id:'run_'+randomUUID().replaceAll('-',''),role,
   profile:profile.profile,profile_hash:digest(profile),test_code_hash:testHash,scope:copy(profile.scope),
   spec:copy(profile.spec),artifact:copy(ref),binding_hash:c?.hash??null,executed_at:clock(),
   ...copy(result),...copy(extra)};
  const h=Object.freeze({});handles.set(h,{...evidence,auth});return h;
 }
 async function execute(role,auth,mode='evaluate'){
  let c;
  try{
   c=context();
   need(runnerHash()===testHash,'RUNNER_CHANGED');
   if(['web','code'].includes(profile.profile))need(config.approved_artifact_hashes?.includes(ref.file_hash),'EXECUTION_NOT_APPROVED');
   if(profile.profile==='web'){
    need(config.playwright_module&&config.chromium_executable,'BROWSER_UNAVAILABLE');
    need(bytesHash(readFileSync(config.playwright_module))===config.playwright_sha256&&bytesHash(readFileSync(config.chromium_executable))===config.chromium_sha256,'BROWSER_PIN_MISMATCH');
   }
   const input={profile,bytes_base64:c.bytes.toString('base64'),sources:c.sources,role,mode,now:clock(),runtime:{playwright_module:config.playwright_module??null,chromium_executable:config.chromium_executable??null}};
   const result=await runProfile(input,config.timeout_ms??15000);
   need(context().hash===c.hash,'VERIFICATION_CHANGED');
   if(auth)identity(auth.session,auth.grant,auth.actor.role);
   return {result,c};
  }catch(error){return {c,result:{execution_status:'ERROR',verdict:'BLOCKED',rows:[],mutations:[],error:error.message}};}
 }
 function inspect(handle){const r=handles.get(handle);need(r,'QA02_REPORT_UNTRUSTED');const {auth,...value}=r;return frozen(copy(value));}
 async function local(){const {result,c}=await execute('local',null);return expose('local',result,c);}
 async function examine(session,grant){const auth=identity(session,grant,'EXAMINER'),{result,c}=await execute('independent',auth);return expose('independent',result,c,auth);}
 async function audit(session,grant,request){
  fields(request,['local','examiner']);const l=report(request.local,'local'),e=report(request.examiner,'independent');
  const auth=identity(session,grant,'AUDITOR');need(auth.actor.id!==e.auth.actor.id&&auth.actor.subject!==e.auth.actor.subject,'INDEPENDENT_AUDITOR_REQUIRED');
  // Local report is first revealed HERE, after the independent report is sealed.
  const {result,c}=await execute('auditor',auth,'audit'),findings=[];
  try{current(l);current(e);}catch{findings.push({code:'STALE_OR_REVOKED_REPORT',status:'BLOCKED'});}
  for(const r of [l,e]){
   if(r.execution_status!=='EXECUTED')findings.push({code:'EVIDENCE_NOT_EXECUTED',status:'BLOCKED'});
   const ids=r.rows.map(row=>row.criterion_id);
   if(profile.criteria.some(c=>ids.filter(id=>id===c.id).length!==1))findings.push({code:'CRITERIA_COVERAGE',status:'UNCLEAR'});
   if(r.rows.some(row=>row.artifact_sha256!==ref.file_hash||!Object.hasOwn(row,'actual')||!Object.hasOwn(row,'expected')))findings.push({code:'EVIDENCE_BINDING',status:'FAIL'});
  }
  if(l.verdict!==e.verdict)findings.push({code:'LOCAL_EXAMINER_DISAGREEMENT',status:'UNCLEAR'});
  if(result.verdict!==e.verdict)findings.push({code:'EXAMINER_NOT_REPRODUCED',status:result.verdict==='BLOCKED'?'BLOCKED':'UNCLEAR'});
  if(!result.mutations.length||result.mutations.some(m=>!m.detected))findings.push({code:'MUTATION_NOT_DETECTED',status:'UNCLEAR'});
  const status=verdict([{status:result.verdict},...findings]);
  return expose('auditor',{...result,verdict:status,findings},c,auth,{local_hash:digest(inspect(request.local)),examiner_hash:digest(inspect(request.examiner))});
 }
 function gate(request){
  fields(request,['local','examiner','auditor']);
  let status='BLOCKED',reason='REPORTS_UNAVAILABLE',evidence=[];
  try{
   const l=report(request.local,'local'),e=report(request.examiner,'independent'),a=report(request.auditor,'auditor');
   [l,e,a].forEach(current);
   need(a.local_hash===digest(inspect(request.local))&&a.examiner_hash===digest(inspect(request.examiner)),'AUDIT_REPORT_MISMATCH');
   const c=context();need(postSaveArtifacts,'POST_SAVE_READER_REQUIRED');need(postSaveArtifacts!==artifacts,'INDEPENDENT_POST_SAVE_READER_REQUIRED');
   need(context(postSaveArtifacts).hash===c.hash,'POST_SAVE_CHANGED');
   status=verdict([l,e,a].map(r=>({status:r.verdict})));reason=status==='PASS'?'ALL_REQUIRED_EVIDENCE':'PROFILE_REJECTED';
   evidence=[request.local,request.examiner,request.auditor].map(h=>inspect(h));
  }catch(error){reason=error.message;}
  return frozen({version:VERSION,verdict:status,d08_candidate_verdict:MAP[status],reason,scope:copy(profile.scope),spec:copy(profile.spec),
   artifact:copy(ref),profile_hash:digest(profile),evidence_hash:digest(evidence),evidence,
   authority:'CANDIDATE_ONLY',authoritative_qa:'NOT_SUBMITTED',authoritative_complete:false,accepted:false,published:false,physical_decision:'DENY'});
 }
 function feedback(request,context){return buildFeedback(gate(request),context);}
 return Object.freeze({binding,local,examine,audit,gate,inspect,feedback});
}
