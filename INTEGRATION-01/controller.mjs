import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {createCase} from './adapters/fixture.mjs';
import {restoreCheckpoint} from '../awe/integration_v4/checkpoint.mjs';
import {evaluationPins} from '../awe/execution_security/evaluation.mjs';
import {canonicalize,digest} from '../contracts/canonical.mjs';
const root=path.resolve(import.meta.dirname,'..'),scope={project_id:'prj_alpha',task_id:'task_one',operation_id:'op_control_one'};
export class ApiError extends Error{constructor(code,message,status=409){super(message);this.code=code;this.status=status;}}
const need=(v,code,message=code,status=409)=>{if(!v)throw new ApiError(code,message,status);};
const copy=structuredClone;
// Legacy digest UI only. MASTER01 uses master-controller.mjs and never createCase.
export const EXECUTION_PROFILE='LEGACY_INT04_DIGEST_DEMO_NOT_MASTER01';
const nativeTask=(storage)=>storage.read(db=>db.projects?.prj_alpha?.tasks?.task_one??null);
// This is an inbox/projection/HTTP driver for the EXISTING INT04 coordinator.
// It never writes task lifecycle, grants, attempts, reserves or QA verdicts.
export async function createController({dataDir,autoRun=true,pauseAfterStart=false}={}){
 fs.mkdirSync(dataDir,{recursive:true});const file=path.join(dataDir,'ui-inbox.json'),caseDir=path.join(dataDir,'case');
 const lockFile=path.join(dataDir,'controller.lock'),lock=fs.openSync(lockFile,'wx');
 let f=null,restored=null,hold=false,closed=false,pending=null,startedResolve,continueResolve;
 const started=new Promise(r=>{startedResolve=r;}),continueWork=new Promise(r=>{continueResolve=r;});
 let meta={version:'INTEGRATION01_UI_INBOX_V1',revision:1,taskText:null,scenario:null,receipts:[],messages:[],events:[],externalQa:null,lastError:null,cancelRequested:false};
 const emit=(type,text)=>{meta.revision++;meta.events.push({id:'event_'+meta.revision,revision:meta.revision,cursor:'i01:'+meta.revision,taskId:meta.taskText?'task_one':null,type,text,createdAt:new Date().toISOString()});persist();};
 const persist=()=>{const tmp=file+'.tmp';fs.writeFileSync(tmp,JSON.stringify(meta)+'\n');fs.renameSync(tmp,file);};
 if(fs.existsSync(file)||fs.existsSync(caseDir)){
  hold=true;try{meta=JSON.parse(fs.readFileSync(file,'utf8'));need(meta.version==='INTEGRATION01_UI_INBOX_V1','INBOX_FORMAT');if(meta.taskText)restored=restoreCheckpoint(caseDir);}catch(e){meta.lastError={code:'HOLD_CHECKPOINT_UNAVAILABLE',message:'Снимок отсутствует или повреждён. Новый запуск закрыт; нужна независимая сверка.'};}
  meta.externalQa=meta.externalQa?{...meta.externalQa,historical:true}:null;emit('STARTUP_HOLD','Восстановлено только представление. Resume, новые attempts и effective acceptance закрыты.');
 }
 const state=()=>f?f.h.service.getTask(f.h.state,scope):restored?nativeTask(restored.storage):null;
 const ledger=()=>f?.b.ledger??restored?.ledger??null;
 const internal=()=>f?f.host.read():restored?.storage.read(db=>db.int04??{})??{};
 const bundle=()=>f?.host.bundle??restored?.checkpoint.bundle??null;
 function receipt(key){return meta.receipts.find(r=>r.key===key)?.result??null;}
 function artifactContent(){const b=bundle();if(!b)return null;
  if(f){const r=f.m.artifacts.read(f.m.session('act_worker'),JSON.stringify({artifact_id:'art_int04_output',version:b.reference.version,path:'site/index.txt'}));need(r.ok,'D07_READBACK_DENIED','D07 отказал в чтении результата',403);const bytes=Buffer.from(r.value.bytes_base64,'base64');need(digest(JSON.parse(bytes))===b.reference.file_hash,'D07_READBACK_CHANGED');return bytes.toString('utf8');}
  // A restored checkpoint is historical evidence only; it does not recreate D07.
  return Buffer.from(b.bytes_base64,'base64').toString('utf8');
 }
 function snapshot(){
  const t=state(),x=internal(),b=bundle(),l=ledger()?.inspect(),budget=l?.totals?.task;
  let processes=null;try{processes=f?.host.runtime.integrationProcesses();}catch{}
  const finished=x.phase==='WORK_COMPLETED',qaPass=x.qa?.qa==='QA_PASS'&&!hold&&!x.uncertain&&!meta.cancelRequested;
  const secondPass=meta.externalQa?.result?.verdict==='QA_PASS'&&!hold;
  const canAccept=Boolean(qaPass&&secondPass&&x.qa?.accepted===false&&!x.qa?.rejected&&t?.state==='QA_PENDING');
  const error=meta.lastError??(x.uncertain?{code:'OUTCOME_UNKNOWN',message:'Нужна сверка существующей попытки. Повтор закрыт.'}:null);
  const task=t?{id:'task_one',projectId:'prj_alpha',parentId:null,title:meta.taskText.slice(0,90),status:t.state,revision:t.revision,specRevision:t.spec.revision,authorAgentId:'child',progress:null,updatedAt:meta.events.at(-1)?.createdAt??new Date().toISOString(),error:error?{...error,retryable:false}:null,nativeState:t.state,phase:hold?'HOLD':x.phase,workCompleted:finished&&!hold,authoritativeComplete:false,canCancel:!hold&&x.phase==='RUNNING'&&!meta.cancelRequested,completedStages:[true,finished,finished,qaPass&&secondPass],executionLimits:{elapsedSeconds:null,maxDurationSeconds:5,toolCallsUsed:Object.keys(x.attempts??{}).length,maxToolCalls:1,activeChildren:processes?.active??0,maxChildren:2}}:null;
  const qa=[];if(b){
   if(x.qa)qa.push({id:'qa-sec-d08',artifactId:'a-task_one',taskId:'task_one',artifactVersion:b.reference.version,specRevision:b.pin.spec.revision,contentDigest:b.reference.file_hash,role:'EVALUATOR',reviewerId:'sec-evaluator',verdict:hold?'INCONCLUSIVE':x.qa.qa==='QA_PASS'?'PASS':x.qa.qa==='QA_FAIL'?'FAIL':'INCONCLUSIVE',summary:hold?'Исторический отчёт; effective QA закрыта до reconciliation.':`SEC → fixed D08: ${x.qa.qa}. Signed proof committed: ${Boolean(x.qa.proof)}.`,createdAt:task.updatedAt});
   if(meta.externalQa)qa.push({id:'qa-separate-process',artifactId:'a-task_one',taskId:'task_one',artifactVersion:b.reference.version,specRevision:b.pin.spec.revision,contentDigest:b.reference.file_hash,role:'VERIFIER',reviewerId:'fixed-d08-separate-process',verdict:hold?'INCONCLUSIVE':meta.externalQa.result.verdict==='QA_PASS'?'PASS':meta.externalQa.result.verdict==='QA_FAIL'?'FAIL':'INCONCLUSIVE',summary:hold?'Исторический отдельный процесс; текущая приёмка закрыта.':`Повтор fixed D08 в отдельном guarded Node-процессе: ${meta.externalQa.result.verdict}. Это E0, не production trust isolation.`,createdAt:task.updatedAt});
  }
  const artifacts=b?[{id:'a-task_one',taskId:'task_one',projectId:'prj_alpha',name:'INTEGRATION01-result.json',version:b.reference.version,specRevision:b.pin.spec.revision,content:artifactContent(),contentDigest:b.reference.file_hash,persisted:true,readBackVerified:!hold,acceptance:!hold&&x.qa?.accepted?'ACCEPTED':!hold&&x.qa?.rejected?'REJECTED':'PENDING',published:false,canAccept,historical:hold,qaState:hold?'HOLD':x.qa?.qa??'QA_NOT_RUN'}]:[];
  const agent=(id,name,role,parentId,status,description)=>({id,name,role,parentId,projectId:'prj_alpha',status,description});
  const runtimeStatus=id=>{try{return f.host.runtime.inspect(id).status;}catch{return 'NOT_STARTED';}};
  const agents=t?[agent('main','Координатор INT-04','MAIN',null,task.phase,'D03 — единственный владелец задачи'),agent('worker','RT parent · отдельный fixed процесс','SUBAGENT','main',hold?'HOLD':runtimeStatus('run_int04_parent'),'Только контекст задачи; без переписки и host API'),agent('child','RT child · отдельный fixed процесс','EXECUTOR','worker',hold?'HOLD':runtimeStatus('run_int04_child'),'Результат: SHA-256, UTF8 bytes и scoped artifact ref'),agent('verifier','Fixed D08 · отдельный процесс','VERIFIER',null,secondPass?'QA_PASS':hold?'HOLD':'QA_PENDING','Независимый повтор вычисления'),agent('evaluator','SEC evaluator → D08','EVALUATOR',null,qaPass?'QA_PASS':x.qa?.qa??'QA_PENDING','Логическая identity отличается от автора')]:[];
  return {executionProfile:EXECUTION_PROFILE,contractVersion:'integration01.ui/1',mock:false,offline:true,revision:meta.revision,cursor:'i01:'+meta.revision,updatedAt:meta.events.at(-1)?.createdAt??new Date().toISOString(),connection:'CONNECTED',hold,storageWarning:hold?'STARTUP HOLD: отображение восстановлено, выполнение и приёмка закрыты.':null,projects:[{id:'prj_alpha',name:'Legacy INT04 digest demo',description:'Исторический ограниченный demo-профиль; не MASTER01.'}],tasks:task?[task]:[],agents,messages:copy(meta.messages),permissions:[],artifacts,qa,budgets:task?[{taskId:'task_one',currency:'RUB',unit:'MICRO_RUB',confirmedMicros:budget?.spentMicros??null,reservedMicros:budget?.reservedMicros??null,unreconciledMicros:hold?null:budget?.uncertainMicros??null,limitMicros:budget?.capMicros??null,attempts:budget?.attempts??0,reservedAttempts:budget?.reservedAttempts??0,owner:'D06_MemoryLedger'}]:[],events:copy(meta.events),runtime:processes??{active:0,spawn_count:0,runs:[]},owners:{task:'D03_StateService',reservation:'D06_MemoryLedger',attempt:'D06_RouteBroker',runtime:'RT01_PROCESS',qa:'D08_FIXED'},physicalDecision:'DENY',realHermes:'NOT_RUN',liveLlm:'NOT_RUN'};
 }
 async function separateQa(){
  const input=JSON.stringify({bundle:f.host.bundle,source_pins:evaluationPins()});need(Buffer.byteLength(input)<=65536,'QA_INPUT_TOO_LARGE');
  const env={TZ:'UTC'};for(const k of ['SystemRoot','WINDIR','TEMP','TMP'])if(process.env[k])env[k]=process.env[k];
  const result=spawnSync(process.execPath,['--require',path.join(root,'baseline/offline-guard.cjs'),path.join(root,'tests/integration_v4/qa-worker.mjs')],{cwd:root,env,encoding:'utf8',input,timeout:3000,maxBuffer:65536,windowsHide:true});
  fs.writeFileSync(path.join(caseDir,'independent-d08.stdout.json'),result.stdout??'');fs.writeFileSync(path.join(caseDir,'independent-d08.stderr.txt'),result.stderr??'');
  need(result.status===0,'INDEPENDENT_QA_PROCESS_FAILED');meta.externalQa=JSON.parse(result.stdout);persist();emit('D08_SEPARATE_PROCESS',`Отдельный fixed D08 вычислил ${meta.externalQa.result.verdict}.`);
 }
 async function run(){
  try{
   emit('COORDINATOR_START','D03 задача создана. Существующий INT04 запускает TR/SEC/LLM01/D06/RT01.');const start=await f.host.start();emit('COORDINATOR_STARTED',`INT04 start: ${start.status??start.decision}.`);startedResolve(start);
   if(start.status==='RUNNING'&&f.host.model?.outputReleased){meta.messages.push({id:'message-model',taskId:'task_one',role:'agent',text:'LLM01 sealed mock ответил: '+f.host.model.output.text,createdAt:new Date().toISOString()});persist();}
   if(start.status!=='RUNNING'){meta.lastError={code:start.code??start.reason??start.status,message:'Контур не получил подтверждения запуска. Другая попытка не создаётся.'};persist();return;}
   if(pauseAfterStart)await continueWork;
   if(meta.cancelRequested||closed)return;
   const work=await f.host.finish();emit('COORDINATOR_FINISHED',`INT04 work: ${work.status??work.decision}.`);
   if(work.status!=='WORK_COMPLETED'){meta.lastError={code:work.reason??work.code??work.status,message:'Исполнение не подтверждено; COMPLETE и QA PASS не выдаются.'};persist();return;}
   if(meta.cancelRequested)return;
   meta.messages.push({id:'message-result',taskId:'task_one',role:'agent',text:'Ограниченная операция выполнена. D07 сохранил и прочитал exact JSON. Результат доступен в Студии; authoritative D03 COMPLETE не выдан.',createdAt:new Date().toISOString()});
   emit('D07_READBACK','RT результаты и итог сохранены/прочитаны через D07. D03 остаётся QA_PENDING.');
   const q=await f.host.verify();emit('D08_MAIN',`SEC → fixed D08: ${q.qa??q.code??q.decision}.`);
   if(q.qa)await separateQa();else{meta.lastError={code:q.code??'QA_DENIED',message:'Независимая проверка не получила допустимых доказательств.'};persist();}
   if(q.qa&&q.qa!=='QA_PASS')meta.lastError={code:q.qa,message:'D08 отклонил или не подтвердил точную версию результата.'};
   persist();
  }catch(e){meta.lastError={code:e.code??'COORDINATOR_ERROR',message:'Контур остановлен: '+e.message};emit('COORDINATOR_ERROR',meta.lastError.code);startedResolve({status:'ERROR'});}
  finally{if(!pauseAfterStart||meta.cancelRequested||internal().phase!=='RUNNING')await f?.host.close();persist();}
 }
 let inboxTail=Promise.resolve();
 async function execute(c){
  need(!closed,'CLOSED');need(c&&typeof c==='object'&&!Array.isArray(c),'INVALID_COMMAND','Нужен command object',400);need(Object.keys(c).every(k=>['type','projectId','taskId','expectedRevision','idempotencyKey','payload'].includes(k)),'COMMAND_FIELDS_DENIED','Неизвестные поля команды запрещены',400);
  need(typeof c.idempotencyKey==='string'&&/^[a-zA-Z0-9_-]{8,128}$/.test(c.idempotencyKey),'INVALID_KEY','Нужен стабильный ключ команды',400);
  const fingerprint=digest(c),previous=meta.receipts.find(r=>r.key===c.idempotencyKey);
  if(previous){need(previous.fingerprint===fingerprint,'IDEMPOTENCY_CONFLICT');return copy(previous.result);}
  need(c.projectId==='prj_alpha','SCOPE_DENIED','Project scope запрещён',403);need(!hold,'STARTUP_HOLD','Контур в HOLD. Новый запуск и приёмка закрыты.');
  if(c.type==='CREATE_TASK'){
   need(!meta.taskText,'ONE_TASK_PER_CONTOUR','В этом профиле уже есть задача. Новый профиль создаётся отдельным локальным запуском.');
   need(c.payload&&Object.keys(c.payload).every(k=>['text','scenario'].includes(k)),'PAYLOAD_FIELDS_DENIED','Scope/actor/grants не принимаются из формы',400);const text=c.payload?.text;need(typeof text==='string'&&text.trim()&&text.length<=1024,'INVALID_INPUT','Лимит существующего INT04: 1…1024 символа',400);
   const scenario=c.payload.scenario??'normal';need(['normal','child-failure','lost-ack','provider-timeout','qa-failure'].includes(scenario),'SCENARIO_DENIED','Неизвестный test scenario',400);
   meta.taskText=text;meta.scenario=scenario;persist();
   f=await createCase({directory:caseDir,text,scenario});meta.messages.push({id:'message-1',taskId:'task_one',role:'owner',text,createdAt:new Date().toISOString()});emit('D03_CREATED','StateService: задача task_one находится в RUNNING. Это bounded digest-сценарий.');
  }else{
   need(f&&c.taskId==='task_one','TASK_SCOPE_DENIED','Task scope запрещён',403);need(c.expectedRevision===state().revision,'REVISION_CONFLICT','Ревизия D03 изменилась; обновите представление.');
   if(c.type==='POST_MESSAGE'){need(c.payload&&Object.keys(c.payload).every(k=>k==='text'),'PAYLOAD_FIELDS_DENIED','Недопустимые поля сообщения',400);
    need(typeof c.payload?.text==='string'&&c.payload.text.trim()&&c.payload.text.length<=1024,'INVALID_INPUT','Сообщение: 1…1024 символа',400);
    await f.host.deliverEvent(c.idempotencyKey,{type:'UI_MESSAGE',taskId:'task_one',text:c.payload.text});meta.messages.push({id:c.idempotencyKey,taskId:'task_one',role:'owner',text:c.payload.text,createdAt:new Date().toISOString()});emit('MESSAGE_RECORDED','Уточнение записано в INT04 inbox; неизменяемый task context не расширен.');
   }else if(c.type==='CANCEL_TASK'){need(c.payload&&Object.keys(c.payload).length===0,'PAYLOAD_FIELDS_DENIED','Отмена не принимает override-поля',400);
    need(internal().phase==='RUNNING','CANCEL_NOT_READY','Отмена доступна после подтверждённого RT start.');meta.cancelRequested=true;
    const result=await f.host.cancel();emit('CANCEL_REQUESTED',`D03 ${state().state}; RT ${result.runtime?.status}. Финальный D03 CANCELLED не заявляется без reconciliation.`);continueResolve();await f.host.close();
   }else if(c.type==='ACCEPT_ARTIFACT'||c.type==='REJECT_ARTIFACT'){
    need(c.payload&&Object.keys(c.payload).sort().join()===['artifactId','artifactVersion','contentDigest'].sort().join(),'PAYLOAD_FIELDS_DENIED','Приёмка принимает только exact artifact binding',400);const b=bundle();need(b&&c.payload?.artifactId==='a-task_one'&&c.payload.artifactVersion===b.reference.version&&c.payload.contentDigest===b.reference.file_hash,'ARTIFACT_VERSION_CONFLICT');
    if(c.type==='ACCEPT_ARTIFACT'){need(snapshot().artifacts[0].canAccept,'QA_REQUIRED','Нужны реальные два fixed D08 отчёта и текущий proof.');const result=await f.host.accept(internal().qa.proof);need(result.accepted===true,'ACCEPTANCE_DENIED');emit('TEST_OWNER_ACCEPTED','Тестовый OWNER принял exact версию. Authoritative D03 COMPLETE и публикации нет.');}
    else{await f.host.reject();emit('TEST_OWNER_REJECTED','Тестовый OWNER отклонил exact версию.');}
   }else throw new ApiError('UNSUPPORTED_COMMAND','В этом slice команда не реализована. Новый attempt не создан.',400);
  }
  const result={status:'RECORDED',offline:true,commandId:'cmd_'+randomUUID(),entityId:'task_one'};meta.receipts.push({key:c.idempotencyKey,fingerprint,result});persist();
  if(c.type==='CREATE_TASK'&&autoRun)pending=run();return copy(result);
 }
 return {
  getSnapshot:snapshot,artifactContent,lookup:receipt,
  command(c){const next=inboxTail.then(()=>execute(c));inboxTail=next.catch(()=>{});return next;},
  waitStarted:()=>started,continue:()=>continueResolve(),waitIdle:()=>pending??Promise.resolve(),
  testCase:()=>f,
  async close(){closed=true;continueResolve();await pending;await f?.host.close();fs.closeSync(lock);fs.unlinkSync(lockFile);}
 };
}
