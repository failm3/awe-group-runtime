import fs from 'node:fs';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {sourceFor} from '../executable_tools/programs.mjs';
import {expectedStats} from '../executable_tools/verification.mjs';
import {executionLock} from '../hermes_runtime/execution-profile.mjs';
import {boundedFrames} from '../hermes_runtime/bounded-frames.mjs';
import {canonicalize,digest,need,freeze,hashBytes} from './common.mjs';
import {verifyLocalPins,LOCAL_LIMITS,validateLocalOutput} from './local-reviewed.mjs';
const root=path.resolve(import.meta.dirname,'../..');let active=false;
// Host-only fixed adapter; gate supplies its synchronous current-authority barrier.
// Agent requests cannot name files, executable paths, callbacks or source text.
export async function executeReviewedStats({request:r,current}){
 need(!active,'LOCAL_PROCESS_LIMIT');verifyLocalPins();current();active=true;
 let child,timer,poller,dir,launched=false;
 try{
  const sandbox=path.join(root,'OWNER-02/sandbox');fs.mkdirSync(sandbox,{recursive:true});
  need(!fs.lstatSync(sandbox).isSymbolicLink()&&fs.realpathSync(sandbox)===sandbox,'LOCAL_DIRECTORY_DENIED');
  dir=fs.mkdtempSync(path.join(sandbox,'job-'));const file=path.join(dir,'reviewed.mjs'),guard=path.join(root,'TOOLS-02/child-guard.cjs');
  const source=sourceFor('JS');fs.writeFileSync(file,source,{flag:'wx'});need(hashBytes(fs.readFileSync(file))===r.tool_digest,'LOCAL_CODE_DRIFT');
  const limits=LOCAL_LIMITS,env={SystemRoot:process.env.SystemRoot,TZ:'UTC',HOME:dir,USERPROFILE:dir,TEMP:dir,TMP:dir};
  const job={executable:executionLock.executables.node.path,args:['--permission','--disable-proto=throw','--max-old-space-size=32','--allow-fs-read='+file,'--allow-fs-read='+guard,'--require',guard,file],cwd:dir,env,stdin:canonicalize(r.payload),wall_ms:limits.wall_ms,cpu_ms:limits.cpu_ms,memory_bytes:limits.memory_bytes,output_bytes:limits.output_bytes};
  need(Buffer.byteLength(JSON.stringify(job))<=8192,'LOCAL_JOB_TOO_LARGE');
  verifyLocalPins();current(); // no await between this barrier and fixed spawn
  child=spawn(executionLock.executables.python.path,['-I','-S','-B',path.join(root,'awe/hermes_runtime/executors/job-host.py')],{cwd:dir,env,windowsHide:true,stdio:['pipe','pipe','pipe']});launched=true;
  const frames=[];let wire=0,err=0,fault=null;
  const stop=code=>{fault??=code;child.stdin.end();};
  const decoder=boundedFrames({limit:26000,onFrame:f=>{try{need(f.contract==='rt02.job/1'&&['STARTED','EXIT'].includes(f.type)&&!frames.some(x=>x.type===f.type),'LOCAL_DUPLICATE_CALLBACK');frames.push(f);}catch(e){stop(e.code??e.message);}},onError:()=>stop('LOCAL_FRAME_INVALID')});
  child.stdout.on('data',b=>{wire+=b.length;if(wire>30000)stop('LOCAL_OUTPUT_LIMIT');else decoder.push(b);});child.stderr.on('data',b=>{err+=b.length;if(err>4096)stop('LOCAL_STDERR_LIMIT');});child.stdin.on('error',()=>{});
  const exit=new Promise(resolve=>{child.once('error',()=>stop('LOCAL_SPAWN_FAILED'));child.once('close',(code,signal)=>{decoder.end();resolve({code,signal});});});
  timer=setTimeout(()=>{stop('LOCAL_EXIT_UNKNOWN');child.kill('SIGKILL');},limits.wall_ms+2000);
  poller=setInterval(()=>{try{current();}catch{stop('LOCAL_AUTHORITY_CHANGED');}},10);
  child.stdin.write(JSON.stringify(job)+'\n');const ended=await exit;
  const start=frames.find(f=>f.type==='STARTED'),end=frames.find(f=>f.type==='EXIT');
  fs.writeFileSync(path.join(dir,'job-evidence.json'),JSON.stringify({ended,fault,frames,wire,helper_stderr_bytes:err},null,2)+'\n');
  // Job active-process limit is one. Windows can account for a failed/terminated
  // child in TotalProcesses; cumulative job members plus its helper are bounded.
  need(!fault&&ended.code===0&&start?.assigned_before_resume===true&&start.job_process_limit===1&&end?.pid===start.pid&&end.active_processes===0&&Number.isSafeInteger(end.created_processes)&&end.created_processes>=1&&end.created_processes+1<=limits.max_processes,'LOCAL_EXIT_OR_AUTHORITY_UNKNOWN');
  need(end.reason==='EXIT'&&end.exit_code===0&&end.stdout_bytes<=limits.output_bytes&&end.stderr_bytes===0&&end.cpu_micros<=limits.cpu_ms*1000&&end.peak_job_bytes<=limits.memory_bytes,'LOCAL_LIMIT_OR_EXECUTOR_FAILURE');
  const bytes=Buffer.from(end.stdout,'base64');need(bytes.length===end.stdout_bytes,'LOCAL_OUTPUT_BINDING');const output=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
  validateLocalOutput(output);
  need(digest(output)===digest(expectedStats(r.payload.text)),'LOCAL_OUTPUT_INVALID');current();
  return freeze({profile:r.local.profile,output,output_hash:digest(output),payload_hash:r.payload_hash,attempt_id:r.attempt_id,evidence:{stdout_hash:hashBytes(bytes),cpu_micros:end.cpu_micros,peak_job_bytes:end.peak_job_bytes,active_processes:0,created_processes:end.created_processes,job_active_process_limit:1,total_process_limit:limits.max_processes,assigned_before_resume:true},physical_decision:'DENY',authoritative_complete:false});
 }catch(e){if(launched)e.potentialEffect=true;throw e;}
 finally{clearTimeout(timer);clearInterval(poller);active=false;/* Keep the exact run directory as scoped evidence; never reuse it. */}
}
