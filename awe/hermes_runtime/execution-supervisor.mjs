import {spawn} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {mkdirSync,mkdtempSync,lstatSync,realpathSync} from 'node:fs';
import {join} from 'node:path';
import {sourceRoot} from './profile.mjs';
import {boundedFrames} from './bounded-frames.mjs';
import {launchRequest,need,digest,copy,freeze,exact} from './protocol.mjs';
import {canonicalize} from '../../contracts/canonical.mjs';
import {verifyExecutionPins,executionPlan,executionLock,hashBytes,EXECUTION_CONTRACT} from './execution-profile.mjs';

const defaults={max_processes:3,wall_ms:600,cpu_ms:200,memory_bytes:128*1024*1024,output_bytes:8192,startup_ms:700,exit_ms:1000};
const safe=e=>/^RT_PROCESS_[A-Z_]+$/.test(e?.message??'')?e.message:'RT_PROCESS_EXECUTION_FAILED';
export function createExecutionSupervisor(options={}){
 exact(options,['limits']);verifyExecutionPins();
 const limits={...defaults,...options.limits};need(Object.keys(limits).length===Object.keys(defaults).length,'RT_PROCESS_LIMITS');
 for(const [k,v]of Object.entries(limits))need(Number.isSafeInteger(v)&&v>0&&v<=defaults[k],'RT_PROCESS_LIMITS');
 const root=join(sourceRoot,'RT-02/sandbox');mkdirSync(root,{recursive:true});
 need(!lstatSync(root).isSymbolicLink()&&realpathSync(root)===root,'RT_PROCESS_DIRECTORY');
 const directory=mkdtempSync(join(root,'controller-'));const records=new Map(),handles=new WeakMap(),outputs=new Map();let closed=false;
 const get=h=>{need(handles.has(h),'RT_PROCESS_HANDLE');return handles.get(h);};
 function event(r,kind,payload={}){const q=r.request,g=q.grant;r.events.push(JSON.stringify({version:'rt01/1',project_id:g.scope.project_id,task_id:g.scope.task_id,actor_id:q.actor_id,run_id:g.run_id,child_id:q.child_id,seq:r.events.length+1,event_id:'evt_'+g.run_id+'_'+(r.events.length+1),kind,model:q.model,payload}));}
 function waitFor(r,type,ms){
  const have=r.frames.find(f=>f.type===type);if(have)return Promise.resolve(have);
  if(r.fault||r.exited)return Promise.reject(Error(r.fault??'RT_PROCESS_EXIT_UNPROVEN'));
  return new Promise((resolve,reject)=>{const w={type,resolve,reject};w.timer=setTimeout(()=>{r.waiters=r.waiters.filter(x=>x!==w);reject(Error('RT_PROCESS_TIMEOUT'));},ms);r.waiters.push(w);});
 }
 function fail(r,code){r.fault??=code;for(const w of r.waiters.splice(0)){clearTimeout(w.timer);w.reject(Error(r.fault));}if(!r.exited)r.child.stdin.end();}
 async function stop(r){
  if(!r.exited){r.child.stdin.end();let timer;try{await Promise.race([r.exit,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('RT_PROCESS_EXIT_UNPROVEN')),limits.exit_ms);})]);}catch{
   // Kill only this owned helper handle. Closing its Job handle kills all members.
   r.child.kill('SIGKILL');await Promise.race([r.exit,new Promise(resolve=>{const t=setTimeout(resolve,limits.exit_ms);t.unref();})]);
  }finally{clearTimeout(timer);}}
  // Kill-on-job-close handles helper crashes; only a checked EXIT frame is positive child-exit proof.
  need(r.exited&&r.frames.some(f=>f.type==='EXIT'&&f.active_processes===0),'RT_PROCESS_EXIT_UNPROVEN');
 }
 function receive(r,f){
  need(f.contract==='rt02.job/1'&&['STARTED','EXIT','FAULT'].includes(f.type)&&!r.frames.some(x=>x.type===f.type),'RT_PROCESS_JOB_FRAME');
  if(f.type==='FAULT'){exact(f,['contract','type','code']);throw Error('RT_PROCESS_JOB_HOST_FAILED');}
  if(f.type==='STARTED'){
   exact(f,['contract','type','pid','assigned_before_resume','job_process_limit']);need(Number.isSafeInteger(f.pid)&&f.pid>0&&f.assigned_before_resume===true&&f.job_process_limit===1,'RT_PROCESS_JOB_FRAME');r.pid=f.pid;
  }else{
   exact(f,['contract','type','pid','exit_code','reason','stdout','stderr','stdout_bytes','stderr_bytes','cpu_micros','peak_job_bytes','active_processes','created_processes']);
   need(f.pid===r.pid&&f.active_processes===0&&Number.isSafeInteger(f.created_processes)&&f.created_processes>=1,'RT_PROCESS_JOB_EXIT');
   for(const k of ['exit_code','stdout_bytes','stderr_bytes','cpu_micros','peak_job_bytes'])need(Number.isSafeInteger(f[k])&&f[k]>=0,'RT_PROCESS_JOB_FRAME');
   need(['EXIT','NONZERO_EXIT','CANCELLED','TIME_LIMIT','CPU_LIMIT','OUTPUT_LIMIT'].includes(f.reason),'RT_PROCESS_JOB_FRAME');
   for(const k of ['stdout','stderr'])need(typeof f[k]==='string'&&f[k].length<=Math.ceil(limits.output_bytes/3)*4&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(f[k]),'RT_PROCESS_JOB_OUTPUT');
  }
  r.frames.push(copy(f));for(const w of [...r.waiters])if(w.type===f.type){r.waiters=r.waiters.filter(x=>x!==w);clearTimeout(w.timer);w.resolve(f);}
 }
 const api=Object.freeze({mode:'RT01_SYNTHETIC_ONLY',
  async launchChild(raw,context){
   need(!closed,'RT_PROCESS_CLOSED');const q=launchRequest(JSON.stringify(raw)),run=q.grant.run_id;
   need(!records.has(run),'RT_PROCESS_REPLAY');need([...records.values()].filter(r=>!r.exited).length<limits.max_processes,'RT_PROCESS_COUNT_LIMIT');
   need(typeof context==='string'&&Buffer.byteLength(context)<=4096&&digest({text:context})===q.context.hash,'RT_PROCESS_CONTEXT');
   if(q.grant.parent_run_id){const parent=records.get(q.grant.parent_run_id);need(parent&&!parent.exited&&!parent.fault,'RT_PROCESS_PARENT_LOST');}
   verifyExecutionPins();const home=mkdtempSync(join(directory,'work-')),plan=executionPlan(context,q,home,limits);
   need(Buffer.byteLength(JSON.stringify(plan.job))<8192,'RT_PROCESS_INPUT');
   const env={SystemRoot:process.env.SystemRoot,TZ:'UTC',HOME:directory,USERPROFILE:directory,TEMP:directory,TMP:directory};
   const child=spawn(executionLock.executables.python.path,['-I','-S','-B',join(sourceRoot,'awe/hermes_runtime/executors/job-host.py')],{cwd:directory,env,stdio:['pipe','pipe','pipe'],windowsHide:true});
   const r={request:copy(q),child,plan,home,instance:randomUUID(),frames:[],events:[],waiters:[],fault:null,exited:false,wire:0,helperStderr:0,collected:false};records.set(run,r);
   r.exit=new Promise(resolve=>{r.resolveExit=resolve;});const handle=Object.freeze({});handles.set(handle,r);
   const decoder=boundedFrames({limit:26000,onFrame:f=>{try{receive(r,f);}catch(e){fail(r,safe(e));}},onError:()=>fail(r,'RT_PROCESS_JOB_FRAME')});
   child.stdout.on('data',b=>{r.wire+=b.length;if(r.wire>30000)fail(r,'RT_PROCESS_JOB_OUTPUT');else decoder.push(b);});
   child.stderr.on('data',b=>{r.helperStderr+=b.length;if(r.helperStderr>4096)fail(r,'RT_PROCESS_JOB_OUTPUT');});
   child.stdin.on('error',()=>{if(!r.exited)fail(r,'RT_PROCESS_PIPE_LOST');});child.on('error',()=>fail(r,'RT_PROCESS_SPAWN_FAILED'));
   child.on('close',(code,signal)=>{decoder.end();r.exited=true;r.helperExit=code;r.helperSignal=signal;clearTimeout(r.deadline);r.resolveExit();if(code!==0||!r.frames.some(f=>f.type==='EXIT'))fail(r,'RT_PROCESS_EXIT_UNPROVEN');});
   r.deadline=setTimeout(()=>fail(r,'RT_PROCESS_LIFETIME_LIMIT'),limits.wall_ms+limits.startup_ms+limits.exit_ms);
   try{const started=waitFor(r,'STARTED',limits.startup_ms);started.catch(()=>{});child.stdin.write(JSON.stringify(plan.job)+'\n');await started;return handle;}
   catch(e){fail(r,safe(e));try{await stop(r);}catch{}throw Error(r.fault);}
  },
  async streamEvents(h,cursor){
   const r=get(h);need(!r.fault,r.fault??'RT_PROCESS_EXECUTION_FAILED');
   if(!r.collected){r.collected=true;try{
    const exit=await waitFor(r,'EXIT',limits.wall_ms+limits.exit_ms);await stop(r);
    need(!r.fault&&r.helperExit===0,'RT_PROCESS_EXIT_UNPROVEN');
    need(exit.stdout_bytes<=limits.output_bytes&&exit.stderr_bytes<=limits.output_bytes,'RT_PROCESS_OUTPUT_LIMIT');
    if(exit.reason==='TIME_LIMIT')throw Error('RT_PROCESS_TIME_LIMIT');
    if(exit.reason==='CPU_LIMIT')throw Error('RT_PROCESS_CPU_LIMIT');
    if(exit.reason==='OUTPUT_LIMIT')throw Error('RT_PROCESS_OUTPUT_LIMIT');
    if(exit.reason==='CANCELLED')throw Error('RT_PROCESS_LATE_RESULT');
    if(exit.exit_code!==0){event(r,'ERROR',{code:'executor_nonzero_exit'});}
    else{
     const stdout=Buffer.from(exit.stdout,'base64'),stderr=Buffer.from(exit.stderr,'base64');
     need(stdout.length===exit.stdout_bytes&&stderr.length===exit.stderr_bytes,'RT_PROCESS_JOB_OUTPUT');
     let result;
     if(r.plan.manifest.executor==='cli'){need(stdout.toString('utf8')===r.plan.expected,'RT_PROCESS_RESULT_INVALID');result={schema:'rt02.cli.result/1',text:stdout.toString('utf8')};}
     else{result=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(stdout));need(r.plan.expected&&digest(result)===digest(r.plan.expected),'RT_PROCESS_RESULT_INVALID');}
     const output={contract:EXECUTION_CONTRACT,run_id:r.request.grant.run_id,scope:r.request.grant.scope,tool:r.plan.manifest,input_hash:r.request.context.hash,result,
      evidence:{instance:r.instance,pid:r.pid,exit_code:exit.exit_code,active_processes:0,created_processes:exit.created_processes,stdout_hash:hashBytes(stdout),stderr_hash:hashBytes(stderr),stdout_bytes:stdout.length,stderr_bytes:stderr.length,cpu_micros:exit.cpu_micros,peak_job_bytes:exit.peak_job_bytes,assigned_before_resume:true,limits},physical_decision:'DENY',qa:'QA_NOT_RUN',authoritative_complete:false};
     const bytes=Buffer.from(canonicalize(output)),artifact_hash=hashBytes(bytes),artifact_ref=digest({scope:r.request.grant.scope,run:r.request.grant.run_id,artifact_hash});outputs.set(artifact_ref,{request:r.request,bytes,artifact_hash});r.outputRef=artifact_ref;event(r,'RESULT',{artifact_ref,artifact_hash});
    }
   }catch(e){fail(r,safe(e));try{await stop(r);}catch{}throw Error(r.fault);}}
   return r.events.filter(e=>JSON.parse(e).seq>cursor);
  },
  async cancel(h){const r=get(h);r.cancelRequested=true;
   for(const c of records.values())if(c.request.grant.parent_run_id===r.request.grant.run_id){c.cancelRequested=true;await stop(c);}
   await stop(r);r.collected=true;r.cancelProof={exited:true,active_processes:0};r.events=[];event(r,'CANCELLED');return {accepted:true};},
  async reconcile(h){const r=get(h);return {connected:!r.fault&&(!r.exited||r.frames.some(f=>f.type==='EXIT'))};}
 });
 const snapshot=run=>{const r=records.get(run);need(r,'RT_PROCESS_RUN_UNKNOWN');const e=r.frames.find(f=>f.type==='EXIT');return freeze({contract:'rt01.process/1',execution_contract:EXECUTION_CONTRACT,run_id:run,request_hash:digest(r.request),instance:r.instance,pid:r.pid??null,helper_pid:r.child.pid??null,exited:r.exited,exit_code:e?.exit_code??null,fault:r.fault,usage:{cpu_micros:e?.cpu_micros??0,peak_job_bytes:e?.peak_job_bytes??0},stdout_bytes:e?.stdout_bytes??0,stderr_bytes:e?.stderr_bytes??0,output_ref:r.outputRef??null,cancel_proof:r.cancelProof??null,work_directory:r.home,job_exit:e??null,resumable:false});};
 return Object.freeze({api,contract:'rt01.process/1',limits:freeze(copy(limits)),snapshot,
  verify(req,c){const o=outputs.get(c.artifact_ref);return Boolean(o&&o.artifact_hash===c.artifact_hash&&hashBytes(o.bytes)===c.artifact_hash&&digest(o.request)===digest(req));},
  readOutput(ref){need(outputs.has(ref),'RT_PROCESS_OUTPUT_UNKNOWN');return freeze(JSON.parse(outputs.get(ref).bytes.toString('utf8')));},
  inspect(){return freeze({contract:'rt01.process/1',execution_contract:EXECUTION_CONTRACT,spawn_count:records.size,active:[...records.values()].filter(r=>!r.exited).length,physical_decision:'DENY',real_hermes:'REAL_HERMES_NOT_RUN',runs:[...records.keys()].map(snapshot)});},
  async terminate(run){const r=records.get(run);need(r,'RT_PROCESS_RUN_UNKNOWN');await Promise.all([r,...[...records.values()].filter(c=>c.request.grant.parent_run_id===run)].map(stop));},
  async close(){closed=true;await Promise.all([...records.values()].map(stop));}
 });
}
