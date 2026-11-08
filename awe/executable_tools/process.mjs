import {spawn} from 'node:child_process';
import path from 'node:path';
import {TextDecoder} from 'node:util';
import {ensure,exact,inputShape,canonical,bytesDigest} from './protocol.mjs';
import {ROOT,verifyPins} from './pins.mjs';
import {createScope,scopeInfo,writeScoped,closeScope} from './scope.mjs';
import {sourceFor} from './programs.mjs';
let active=0;
export function limitsShape(l={timeout_ms:5000,max_output_bytes:8192}){
 exact(l,['timeout_ms','max_output_bytes']);ensure(Number.isInteger(l.timeout_ms)&&l.timeout_ms>=1&&l.timeout_ms<=5000&&Number.isInteger(l.max_output_bytes)&&l.max_output_bytes>=1&&l.max_output_bytes<=8192,'TOOLS_LIMITS');return {...l};
}
function launch({lock,binary,args,cwd,input,limits,beforeSpawn,signal}){
 const executable=verifyPins(lock,binary);ensure(active<3,'TOOLS_PROCESS_LIMIT');ensure(!signal?.aborted,'TOOLS_CANCELLED');
 const env={TEMP:cwd,TMP:cwd,HOME:cwd,USERPROFILE:cwd,PATH:path.dirname(executable),LANG:'C',TZ:'UTC',NO_COLOR:'1'};
 if(process.env.SystemRoot)env.SystemRoot=process.env.SystemRoot;
 // This synchronous host barrier is immediately before spawn. It cannot be a Promise.
 beforeSpawn();active++;
 return new Promise((resolve,reject)=>{
  let child;try{child=spawn(executable,args,{cwd,env,shell:false,windowsHide:true,stdio:['pipe','pipe','pipe']});}catch{active--;reject(Error('TOOLS_SPAWN'));return;}
  let fault=null,size=0,stderr=0,chunks=[],done=false;
  const stop=code=>{fault??=code;child.kill('SIGKILL');};
  const timer=setTimeout(()=>stop('TOOLS_TIMEOUT'),limits.timeout_ms);
  const abort=()=>stop('TOOLS_CANCELLED');signal?.addEventListener('abort',abort,{once:true});
  child.stdout.on('data',b=>{size+=b.length;if(size>limits.max_output_bytes)stop('TOOLS_OUTPUT_LIMIT');else chunks.push(b);});
  child.stderr.on('data',b=>{stderr+=b.length;if(stderr>2048)stop('TOOLS_STDERR_LIMIT');});
  child.on('error',()=>{fault??='TOOLS_SPAWN';});child.stdin.on('error',()=>{});
  child.on('close',(code)=>{if(done)return;done=true;active--;clearTimeout(timer);signal?.removeEventListener('abort',abort);
   if(fault||code!==0||stderr>0){reject(Error(fault??'TOOLS_PROCESS_FAILED'));return;}
   try{const output=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks));resolve({stdout:output,stdout_digest:bytesDigest(Buffer.from(output)),bytes:size,exit_code:code});}catch{reject(Error('TOOLS_OUTPUT_ENCODING'));}
  });
  child.stdin.end(input);
 });
}
/** Only exact reviewed template bytes can reach an interpreter. Python isolation flags
 * are hygiene, not an OS sandbox. No hostile source is accepted by this API. */
export async function runProgram({lock,scope,language,source,template='text.stats.v1',input,limits,beforeSpawn=()=>{},signal}){
 ensure(source===sourceFor(language,template),'TOOLS_UNREVIEWED_SOURCE');inputShape('text.stats',input);limits=limitsShape(limits);
 const job=createScope(scope);
 try{
  const name=language==='JS'?'program.mjs':'program.py';writeScoped(job,name,source);const cwd=scopeInfo(job).root,file=path.join(cwd,name);
  const guard=path.join(ROOT,'TOOLS-02/child-guard.cjs');
  const args=language==='JS'?['--permission','--disable-proto=throw','--max-old-space-size=32','--allow-fs-read='+file,'--allow-fs-read='+guard,'--require',guard,file]:['-I','-S','-B',file];
  const result=await launch({lock,binary:language==='JS'?'node':'python',args,cwd,input:canonical(input),limits,beforeSpawn,signal});
  let output;try{output=JSON.parse(result.stdout);}catch{throw Error('TOOLS_OUTPUT_JSON');}
  exact(output,template==='text.stats.v1'?['utf8_bytes','code_points','lines','sha256']:['words','utf8_bytes','sha256']);return {...result,output};
 }finally{closeScope(job);}
}
export async function runCli({lock,scope,kind,limits,beforeSpawn=()=>{},signal}){
 ensure(['cli.node_version','cli.git_version'].includes(kind),'TOOLS_CLI');limits=limitsShape(limits);const job=createScope(scope);
 try{const result=await launch({lock,binary:kind==='cli.node_version'?'node':'git',args:['--version'],cwd:scopeInfo(job).root,input:'',limits,beforeSpawn,signal});
  ensure((kind==='cli.node_version'?/^v24\.21\.0\r?\n$/:/^git version [0-9.]+(?:\.windows\.\d+)?\r?\n$/).test(result.stdout),'TOOLS_CLI_OUTPUT');return {output:{version:result.stdout.trim()},...result};
 }finally{closeScope(job);}
}
export const inspectProcesses=()=>({active,max:3});
