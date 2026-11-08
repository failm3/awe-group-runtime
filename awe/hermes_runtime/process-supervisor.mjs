import {spawn} from 'node:child_process';
import {randomUUID,createHash} from 'node:crypto';
import {mkdirSync,mkdtempSync} from 'node:fs';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {boundedFrames} from './bounded-frames.mjs';
import {sourceRoot,cleanEnvironment} from './profile.mjs';
import {canonicalize} from '../../contracts/canonical.mjs';
import {launchRequest,digest,copy,freeze,need,exact} from './protocol.mjs';
import {createExecutionSupervisor} from './execution-supervisor.mjs';
export const PROCESS_CONTRACT='rt01.process/1';
const behaviors=new Set(['digest','hang','ignore_cancel','late_result','crash','malformed','flood','stderr_flood','memory','cpu','error','binding_spoof','history','duplicate','nonzero_exit']);
const defaults={max_processes:3,heap_mb:32,max_rss_bytes:128*1024*1024,max_cpu_micros:1000000,lifetime_ms:5000,startup_ms:700,rpc_ms:500,cancel_grace_ms:100,exit_ms:250,context_bytes:32000,stdout_bytes:65536,stderr_bytes:4096};
const sha=bytes=>'sha256:'+createHash('sha256').update(bytes).digest('hex');
const safeFailure=e=>/^RT_PROCESS_[A-Z_]+$/.test(e?.message??'')?e.message:'RT_PROCESS_FAILURE';
export function createProcessSupervisor(options={}) {
 if(options.executorProfile!==undefined){need(options.executorProfile==='rt02.executor/1'&&Object.keys(options).every(k=>['executorProfile','limits'].includes(k)),'RT_PROCESS_OPTIONS');return createExecutionSupervisor({limits:options.limits});}
 need(options&&Object.keys(options).every(k=>['limits','syntheticFaults'].includes(k)),'RT_PROCESS_OPTIONS');
 need(process.version==='v24.21.0','RT_PROCESS_NODE_PIN');
 const limits={...defaults,...options.limits};need(Object.keys(limits).length===Object.keys(defaults).length,'RT_PROCESS_LIMITS');
 for(const [k,v]of Object.entries(limits))need(Number.isSafeInteger(v)&&v>0&&v<=defaults[k],'RT_PROCESS_LIMITS');
 need(limits.heap_mb>=16,'RT_PROCESS_LIMITS');
 const faults=copy(options.syntheticFaults??{});for(const b of Object.values(faults))need(behaviors.has(b),'RT_PROCESS_BEHAVIOR');
 const records=new Map(),handles=new WeakMap(),outputs=new Map();let closed=false,spawnCount=0;
 const root=join(sourceRoot,'RT-01/process-candidate/sandbox');mkdirSync(root,{recursive:true});
 const directory=mkdtempSync(join(root,'controller-'));
 const get=h=>{need(handles.has(h),'RT_PROCESS_HANDLE');return handles.get(h);};
 function rejectWait(r,code){for(const w of r.waiters.splice(0)){clearTimeout(w.timer);w.reject(Error(code));}}
 async function stop(r){
  if(r.stopping)return r.stopping;
  r.stopping=(async()=>{
   if(!r.exited){r.intentional=true;try{r.child.kill('SIGKILL');}catch{}}
   if(!r.exited){let timer;try{await Promise.race([r.exit,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('RT_PROCESS_EXIT_UNCONFIRMED')),limits.exit_ms);})]);}finally{clearTimeout(timer);}}
   need(r.exited,'RT_PROCESS_EXIT_UNCONFIRMED');return {exited:true,exit_code:r.exitCode,signal:r.signal};
  })();return r.stopping;
 }
 function fail(r,code){
  if(!r.fault)r.fault=code;rejectWait(r,r.fault);void stop(r).catch(()=>{r.fault='RT_PROCESS_EXIT_UNCONFIRMED';});
  for(const c of records.values())if(c.request.grant.parent_run_id===r.request.grant.run_id)fail(c,'RT_PROCESS_PARENT_LOST');
 }
 function wait(r,type,ms){
  if(r.fault)return Promise.reject(Error(r.fault));
  const ready=r.messages.find(m=>m.type===type);if(ready)return Promise.resolve(ready);
  return new Promise((resolve,reject)=>{const w={type,resolve,reject,timer:null};w.timer=setTimeout(()=>{r.waiters=r.waiters.filter(x=>x!==w);reject(Error('RT_PROCESS_TIMEOUT'));},ms);r.waiters.push(w);});
 }
 function send(r,type,payload={}){
  need(!r.exited&&!r.fault,'RT_PROCESS_DISCONNECTED');const text=JSON.stringify({version:'rt01.process.ipc/1',instance:r.instance,binding:r.binding,type,payload})+'\n';
  need(Buffer.byteLength(text)<=49152,'RT_PROCESS_FRAME_LIMIT');r.child.stdin.write(text,e=>{if(e&&!r.exited)fail(r,'RT_PROCESS_PIPE_LOST');});
 }
 function event(r,kind,payload={}){const q=r.request,g=q.grant;
  r.events.push(JSON.stringify({version:'rt01/1',project_id:g.scope.project_id,task_id:g.scope.task_id,actor_id:q.actor_id,run_id:g.run_id,child_id:q.child_id,
   seq:r.events.length+1,event_id:'evt_'+g.run_id+'_'+(r.events.length+1),kind,model:q.model,payload}));
 }
 function receive(r,m){
  exact(m,['version','instance','binding','type','payload']);need(m.version==='rt01.process.ipc/1'&&m.instance===r.instance&&m.binding===r.binding,'RT_PROCESS_BINDING');
  need(['STARTED','RESULT','ERROR','CANCELLED','CHECKPOINT','USAGE'].includes(m.type),'RT_PROCESS_RESPONSE');
  if(m.type==='USAGE'){
   exact(m.payload,['rss_bytes','cpu_micros']);for(const x of Object.values(m.payload))need(Number.isSafeInteger(x)&&x>=0,'RT_PROCESS_USAGE');
   r.usage=copy(m.payload);need(m.payload.rss_bytes<=limits.max_rss_bytes&&m.payload.cpu_micros<=limits.max_cpu_micros,'RT_PROCESS_RESOURCE_LIMIT');return;
  }
  need(!r.messages.some(x=>x.type===m.type),'RT_PROCESS_DUPLICATE_FRAME');
  if(m.type==='STARTED'){exact(m.payload,['pid']);need(m.payload.pid===r.child.pid,'RT_PROCESS_PID_BINDING');}
  if(m.type==='RESULT'){
   exact(m.payload,['output']);exact(m.payload.output,['schema','input_hash','utf8_bytes']);need(m.payload.output.schema==='rt01.process.result/1','RT_PROCESS_OUTPUT');
   need(m.payload.output.input_hash===r.inputHash&&m.payload.output.utf8_bytes===r.contextBytes,'RT_PROCESS_OUTPUT');r.hasResult=true;
  }
  if(m.type==='ERROR'){exact(m.payload,['code']);need(m.payload.code==='synthetic_failure','RT_PROCESS_ERROR_CODE');r.knownError=true;}
  if(m.type==='CANCELLED'){exact(m.payload,[]);need(r.cancelRequested,'RT_PROCESS_UNSOLICITED_CANCEL');}
  if(m.type==='CHECKPOINT'){exact(m.payload,['context_hash']);need(m.payload.context_hash===r.request.context.hash,'RT_PROCESS_CHECKPOINT');}
  r.messages.push(copy(m));for(const w of [...r.waiters])if(w.type===m.type){r.waiters=r.waiters.filter(x=>x!==w);clearTimeout(w.timer);w.resolve(copy(m));}
 }
 const api=Object.freeze({mode:'RT01_SYNTHETIC_ONLY',
  async launchChild(raw,context){
   need(!closed,'RT_PROCESS_CLOSED');const q=launchRequest(JSON.stringify(raw)),run=q.grant.run_id;
   need(!records.has(run),'RT_PROCESS_REPLAY');need([...records.values()].filter(x=>!x.exited).length<limits.max_processes,'RT_PROCESS_COUNT_LIMIT');
   need(typeof context==='string'&&Buffer.byteLength(context)<=limits.context_bytes&&digest({text:context})===q.context.hash,'RT_PROCESS_CONTEXT');
   const startPayload={scope:q.grant.scope,actor_id:q.actor_id,run_id:run,child_id:q.child_id,parent_run_id:q.grant.parent_run_id,model:q.model,tools:q.tools,
    permissions:{capabilities:q.grant.capabilities,deadline:q.grant.deadline,context_hash:q.context.hash,context_readonly:true,physical_decision:'DENY'},context,behavior:faults[run]??'digest'};
   need(Buffer.byteLength(JSON.stringify({version:'rt01.process.ipc/1',instance:randomUUID(),binding:digest(q),type:'START',payload:startPayload}))+1<=49152,'RT_PROCESS_FRAME_LIMIT');
   if(q.grant.parent_run_id){const p=records.get(q.grant.parent_run_id);need(p&&!p.exited&&!p.fault&&!p.cancelRequested,'RT_PROCESS_PARENT_LOST');}
   const home=join(directory,run);mkdirSync(home);const env=cleanEnvironment(home);if(process.env.SystemRoot)env.SystemRoot=process.env.SystemRoot;
   const child=spawn(process.execPath,['--max-old-space-size='+limits.heap_mb,'--require',join(sourceRoot,'baseline/offline-guard.cjs'),fileURLToPath(new URL('./process-worker.mjs',import.meta.url))],
    {cwd:home,env,stdio:['pipe','pipe','pipe'],windowsHide:true});spawnCount++;
   const r={request:copy(q),child,instance:randomUUID(),binding:digest({request:q,context_hash:q.context.hash}),inputHash:sha(Buffer.from(context)),contextBytes:Buffer.byteLength(context),
    messages:[],waiters:[],events:[],stdoutBytes:0,stderrBytes:0,usage:{rss_bytes:0,cpu_micros:0},exited:false,intentional:false,cancelRequested:false,hasResult:false,knownError:false,collected:false,fault:null};
   r.exit=new Promise(resolve=>{r.resolveExit=resolve;});records.set(run,r);const handle=Object.freeze({});handles.set(handle,r);
   const decoder=boundedFrames({limit:8192,onFrame:m=>{try{receive(r,m);}catch(e){fail(r,safeFailure(e));}},onError:()=>fail(r,'RT_PROCESS_MALFORMED_FRAME')});
   child.stdout.on('data',b=>{r.stdoutBytes+=b.length;if(r.stdoutBytes>limits.stdout_bytes)fail(r,'RT_PROCESS_OUTPUT_LIMIT');else decoder.push(b);});
   child.stderr.on('data',b=>{r.stderrBytes+=b.length;if(r.stderrBytes>limits.stderr_bytes)fail(r,'RT_PROCESS_STDERR_LIMIT');});
   child.stdin.on('error',()=>{if(!r.exited&&!r.intentional)fail(r,'RT_PROCESS_PIPE_LOST');});
   child.on('error',()=>fail(r,'RT_PROCESS_SPAWN_FAILED'));
   child.on('close',(code,signal)=>{decoder.end();r.exited=true;r.exitCode=code;r.signal=signal;clearTimeout(r.deadline);r.resolveExit();
    if(!r.intentional&&!r.cancelRequested&&((!r.hasResult&&!r.knownError)||code!==0))fail(r,'RT_PROCESS_UNEXPECTED_EXIT');});
   r.deadline=setTimeout(()=>fail(r,'RT_PROCESS_LIFETIME_LIMIT'),limits.lifetime_ms);
   try{
    const ready=wait(r,'STARTED',limits.startup_ms);ready.catch(()=>{});send(r,'START',startPayload);
    await ready;return handle;
   }catch(e){fail(r,safeFailure(e));await stop(r);throw Error(r.fault);}
  },
  async streamEvents(handle,cursor){
   const r=get(handle);if(r.fault)throw Error(r.fault);
   if(!r.collected&&!r.cancelRequested){r.collected=true;
    try{
     const result=Promise.race([wait(r,'RESULT',limits.rpc_ms),wait(r,'ERROR',limits.rpc_ms)]);result.catch(()=>{});send(r,'COLLECT');const reply=await result;
     let timer;try{await Promise.race([r.exit,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('RT_PROCESS_EXIT_UNCONFIRMED')),limits.exit_ms);})]);}finally{clearTimeout(timer);}
     need(!r.fault&&r.exitCode===0,'RT_PROCESS_UNEXPECTED_EXIT');
     if(reply.type==='ERROR')event(r,'ERROR',{code:'synthetic_failure'});
     else{const bytes=Buffer.from(canonicalize(reply.payload.output)),artifact_hash=sha(bytes),artifact_ref=digest({scope:r.request.grant.scope,run:r.request.grant.run_id,artifact_hash});
      outputs.set(artifact_ref,{request:r.request,bytes,artifact_hash});r.outputRef=artifact_ref;event(r,'RESULT',{artifact_ref,artifact_hash});}
    }catch(e){fail(r,safeFailure(e));await stop(r);throw Error(r.fault);}
   }
   return r.events.filter(e=>JSON.parse(e).seq>cursor);
  },
  async cancel(handle){
   const r=get(handle);r.cancelRequested=true;
   for(const c of records.values())if(c.request.grant.parent_run_id===r.request.grant.run_id&&!c.exited)await stop(c);
   if(!r.exited&&!r.fault){const terminal=wait(r,'CANCELLED',limits.cancel_grace_ms);terminal.catch(()=>{});try{
    send(r,'CANCEL');await terminal;let timer;try{await Promise.race([r.exit,new Promise(resolve=>{timer=setTimeout(resolve,limits.cancel_grace_ms);})]);}finally{clearTimeout(timer);}
   }catch{}}
   const forced=!r.exited;await stop(r);r.fault=null;r.cancelProof={exited:true,forced,exit_code:r.exitCode,signal:r.signal};r.events=[];event(r,'CANCELLED');return {accepted:true};
  },
  async reconcile(handle){const r=get(handle);return {connected:!r.fault&&(!r.exited||r.hasResult)};}
 });
 return Object.freeze({api,contract:PROCESS_CONTRACT,limits:freeze(copy(limits)),
  verify(req,c){const o=outputs.get(c.artifact_ref);return Boolean(o&&o.artifact_hash===c.artifact_hash&&sha(o.bytes)===c.artifact_hash&&o.request.grant.run_id===req.grant.run_id&&o.request.grant.scope.project_id===req.grant.scope.project_id&&o.request.grant.scope.task_id===req.grant.scope.task_id);},
  readOutput(ref){need(outputs.has(ref),'RT_PROCESS_OUTPUT_UNKNOWN');return freeze(JSON.parse(outputs.get(ref).bytes.toString('utf8')));},
  snapshot(run){const r=records.get(run);need(r,'RT_PROCESS_RUN_UNKNOWN');return freeze({contract:PROCESS_CONTRACT,run_id:run,request_hash:digest(r.request),instance:r.instance,pid:r.child.pid??null,
   exited:r.exited,exit_code:r.exitCode??null,fault:r.fault,usage:r.usage,stdout_bytes:r.stdoutBytes,stderr_bytes:r.stderrBytes,output_ref:r.outputRef??null,cancel_proof:r.cancelProof??null,resumable:false});},
  inspect(){return freeze({contract:PROCESS_CONTRACT,spawn_count:spawnCount,active:[...records.values()].filter(r=>!r.exited).length,physical_decision:'DENY',real_hermes:'REAL_HERMES_NOT_RUN',runs:[...records.keys()].map(run=>this.snapshot(run))});},
 async terminate(run){const r=records.get(run);need(r,'RT_PROCESS_RUN_UNKNOWN');fail(r,'RT_PROCESS_CONTROLLER_STOP');await Promise.all([...records.values()].filter(x=>x===r||x.request.grant.parent_run_id===run).map(stop));},
  async close(){closed=true;await Promise.all([...records.values()].map(r=>stop(r)));}
 });
}
