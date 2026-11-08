import {readFileSync,lstatSync} from 'node:fs';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {sourceRoot} from './profile.mjs';
import {need,exact,parseIntent,freeze,digest} from './protocol.mjs';
export const EXECUTION_CONTRACT='rt02.executor/1';
export const hashBytes=b=>'sha256:'+createHash('sha256').update(b).digest('hex');
const lock=JSON.parse(readFileSync(join(sourceRoot,'RT-02/runtime-lock.json'),'utf8'));
export const executionLock=freeze(lock);
const directory=join(sourceRoot,'awe/hermes_runtime/executors');
const programs=new Set(['sum','wait','cpu','memory','crash','flood','stderr','probe']);
export function verifyExecutionPins(){
 need(process.platform==='win32'&&process.version==='v24.21.0','RT_PROCESS_PLATFORM_PIN');
 for(const [name,pin]of Object.entries(lock.executables)){
  need(!lstatSync(pin.path).isSymbolicLink()&&hashBytes(readFileSync(pin.path))===pin.hash,'RT_PROCESS_EXECUTABLE_PIN');
  if(name==='node')need(pin.path.toLowerCase()===process.execPath.toLowerCase(),'RT_PROCESS_EXECUTABLE_PIN');
 }
 for(const [name,hash]of Object.entries(lock.sources))need(hashBytes(readFileSync(join(sourceRoot,name)))===hash,'RT_PROCESS_SOURCE_PIN');
}
export function programManifest(executor,program){
 need(['javascript','python','cli'].includes(executor)&&(executor==='cli'?program==='filter':programs.has(program)),'RT_PROCESS_PROGRAM_DENIED');
 return freeze({contract:EXECUTION_CONTRACT,tool_id:'tool_rt02_'+executor+'_'+program,executor,program,
  digest:digest({contract:EXECUTION_CONTRACT,executor,program,lock}),physical_decision:'DENY',runtime_dispatch:false});
}
export function executionPlan(context,request,home,limits){
 const q=parseIntent(context);exact(q,['contract','executor','program','input']);
 need(q.contract==='rt02.program/1','RT_PROCESS_PROGRAM_VERSION');
 const manifest=programManifest(q.executor,q.program);
 need(request.tools.length===1&&request.tools[0].id===manifest.tool_id&&request.tools[0].digest===manifest.digest,'RT_PROCESS_TOOL_BINDING');
 let stdin,expected;
 if(q.executor==='cli'){
  exact(q.input,['text']);need(typeof q.input.text==='string'&&/^[A-Za-z0-9 \r\n]*$/.test(q.input.text)&&q.input.text.length<=2048&&q.input.text.includes('AWE'),'RT_PROCESS_INPUT');
  stdin=q.input.text.replace(/\r?\n/g,'\r\n');if(!stdin.endsWith('\r\n'))stdin+='\r\n';
  expected=stdin.split('\r\n').filter(s=>s.includes('AWE')).map(s=>s+'\r\n').join('');
 }else{
  exact(q.input,['values']);need(Array.isArray(q.input.values)&&q.input.values.length<=100&&q.input.values.every(v=>Number.isSafeInteger(v)&&Math.abs(v)<=1000000),'RT_PROCESS_INPUT');
  stdin=JSON.stringify({program:q.program,values:q.input.values})+'\n';
  if(q.program==='sum')expected={schema:'rt02.synthetic.result/1',value:q.input.values.reduce((a,b)=>a+b,0)};
  if(q.program==='probe')expected={schema:'rt02.synthetic.result/1',value:{environment_clean:true,filesystem_denied:true,network_denied:true,spawn_denied:true}};
 }
 const env={SystemRoot:process.env.SystemRoot,TZ:'UTC',HOME:home,USERPROFILE:home,TEMP:home,TMP:home,AWE_PHYSICAL_DECISION:'DENY',PYTHONNOUSERSITE:'1',PYTHONDONTWRITEBYTECODE:'1'};
 const executable=lock.executables[q.executor==='javascript'?'node':q.executor==='python'?'python':'cli'].path;
 const js=join(directory,'javascript.cjs'),py=join(directory,'python.py'),guard=join(sourceRoot,'baseline/offline-guard.cjs');
 const args=q.executor==='javascript'?['--permission','--allow-fs-read='+js,'--allow-fs-read='+guard,'--allow-fs-read='+home,'--allow-fs-write='+home,'--disable-proto=throw','--max-old-space-size=32','--require',guard,js]:q.executor==='python'?['-I','-S','-B',py]:['/L','/C:AWE'];
 return {manifest,expected,job:{executable,args,env,cwd:home,stdin,wall_ms:limits.wall_ms,cpu_ms:limits.cpu_ms,memory_bytes:limits.memory_bytes,output_bytes:limits.output_bytes}};
}
