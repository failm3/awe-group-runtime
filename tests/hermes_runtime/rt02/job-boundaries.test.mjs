import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtempSync,mkdirSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {createInterface} from 'node:readline';
import {sourceRoot} from '../../../awe/hermes_runtime/profile.mjs';
import {executionLock} from '../../../awe/hermes_runtime/execution-profile.mjs';
const env={SystemRoot:process.env.SystemRoot,TZ:'UTC'};
async function start(t,script,limits={}){
 const base=join(sourceRoot,'RT-02/sandbox');mkdirSync(base,{recursive:true});const home=mkdtempSync(join(base,'job-test-'));
 const child=spawn(executionLock.executables.python.path,['-I','-S','-B',join(sourceRoot,'awe/hermes_runtime/executors/job-host.py')],{cwd:home,env,stdio:['pipe','pipe','pipe'],windowsHide:true});
 t.after(()=>{child.stdin.end();if(child.exitCode===null)child.kill();});
 const frames=[];let wake;
 createInterface({input:child.stdout}).on('line',line=>{frames.push(JSON.parse(line));wake?.();});
 const exit=new Promise(resolve=>child.once('close',(code,signal)=>resolve({code,signal})));
 const wait=async type=>{for(let i=0;i<100;i++){const f=frames.find(x=>x.type===type);if(f)return f;await new Promise(resolve=>{const timer=setTimeout(resolve,20);wake=()=>{clearTimeout(timer);resolve();};});}throw Error('JOB_FRAME_TIMEOUT');};
 child.stdin.write(JSON.stringify({executable:executionLock.executables.python.path,args:['-I','-S','-B','-c',script],env,cwd:home,stdin:'',wall_ms:2000,cpu_ms:500,memory_bytes:134217728,output_bytes:8192,...limits})+'\n');
 return {child,exit,wait,frames,started:await wait('STARTED')};
}
test('Windows Job denies an actual synthetic descendant before its program runs',async t=>{
 const f=await start(t,"import subprocess,sys,json\ntry:\n r=subprocess.run([sys.executable,'-I','-S','-c',\"print('DESCENDANT_EXECUTED')\"],capture_output=True,timeout=1)\n print(json.dumps({'denied':r.returncode!=0,'stdout':r.stdout.decode()}))\nexcept OSError:\n print(json.dumps({'denied':True,'stdout':''}))");
 const e=await f.wait('EXIT');await f.exit;assert.equal(e.exit_code,0);assert.equal(e.active_processes,0);const output=JSON.parse(Buffer.from(e.stdout,'base64').toString());assert.equal(output.denied,true);assert.equal(output.stdout,'');
 writeFileSync(join(sourceRoot,'RT-02/evidence/job-descendant-denial.json'),JSON.stringify({started:f.started,exit:e,output},null,2)+'\n');
});
test('Windows Job rejects an allocation beyond its committed-memory quota',async t=>{
 const f=await start(t,"try:\n x=bytearray(64*1024*1024)\n print('UNEXPECTED_ALLOCATION')\nexcept MemoryError:\n print('MEMORY_DENIED')",{memory_bytes:16*1024*1024});
 const e=await f.wait('EXIT');await f.exit;assert.equal(e.exit_code,0);assert.equal(Buffer.from(e.stdout,'base64').toString().trim(),'MEMORY_DENIED');assert.equal(e.active_processes,0);
 writeFileSync(join(sourceRoot,'RT-02/evidence/job-memory-quota.json'),JSON.stringify({configured_memory_bytes:16*1024*1024,requested_bytes:64*1024*1024,started:f.started,exit:e},null,2)+'\n');
});
for(const kind of ['pipe_eof','helper_crash'])test('Job stops its child on '+kind,async t=>{
 const f=await start(t,'import time;time.sleep(60)');
 if(kind==='pipe_eof'){f.child.stdin.end();const e=await f.wait('EXIT');assert.equal(e.reason,'CANCELLED');assert.equal(e.active_processes,0);await f.exit;}
 else{f.child.kill('SIGKILL');await f.exit;}
 // Inventory only. Never attach to or kill a PID from evidence.
 const powershell=join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe');
 const script='$p=Get-Process -Id '+f.started.pid+' -ErrorAction SilentlyContinue; if($null -eq $p){"ABSENT"}else{"PRESENT"}';
 const observed=execFileSync(powershell,['-NoProfile','-NonInteractive','-Command',script],{env,encoding:'utf8',windowsHide:true,timeout:3000}).trim();
 assert.equal(observed,'ABSENT');writeFileSync(join(sourceRoot,'RT-02/evidence/job-'+kind+'.json'),JSON.stringify({owned_helper_pid:f.child.pid,started:f.started,observed,pid_kills_used:false,probe:'READ_ONLY_GET_PROCESS'},null,2)+'\n');
});
