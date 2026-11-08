import {Worker} from 'node:worker_threads';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {bytesHash} from './contracts.mjs';
export const runnerHash=()=>bytesHash(Buffer.concat(['worker.mjs','runner.mjs','contracts.mjs','node-guard.cjs','service.mjs','auto02.mjs','d08-evidence.mjs','../qa/common.mjs','../../contracts/canonical.mjs'].map(path=>readFileSync(new URL(path,import.meta.url)))));
export async function runProfile(input,timeout=15000){
 return new Promise(resolve=>{
  let settled=false;
  const worker=new Worker(new URL('./worker.mjs',import.meta.url),{workerData:input,
   execArgv:['--require',fileURLToPath(new URL('./node-guard.cjs',import.meta.url))],
   resourceLimits:{maxOldGenerationSizeMb:96,maxYoungGenerationSizeMb:16,stackSizeMb:4}});
  const done=value=>{if(settled)return;settled=true;clearTimeout(timer);worker.terminate().finally(()=>resolve(value));};
  const timer=setTimeout(()=>done({execution_status:'ERROR',verdict:'BLOCKED',rows:[],mutations:[],error:'RUNNER_TIMEOUT'}),timeout);
  worker.once('message',done);
  worker.once('error',()=>done({execution_status:'ERROR',verdict:'BLOCKED',rows:[],mutations:[],error:'RUNNER_ERROR'}));
  worker.once('exit',code=>{if(!settled)done({execution_status:'ERROR',verdict:'BLOCKED',rows:[],mutations:[],error:'RUNNER_EXIT_'+code});});
 });
}
