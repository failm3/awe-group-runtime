import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {existsSync,readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {createInterface} from 'node:readline';
import {sourceRoot} from '../../../awe/hermes_runtime/profile.mjs';
import {processFixture} from './fixture.mjs';
import {createInt04ProcessAdapter,INT04_PROCESS_CONTRACT} from '../../../awe/hermes_runtime/int04-process-adapter.mjs';
import {planHash} from '../../../awe/hermes_runtime/adapter.mjs';
import {digest} from '../../../awe/hermes_runtime/protocol.mjs';
test('controller abrupt death closes worker pipes; actual parent/child processes exit without saved-PID killing',async t=>{
 const powershell=process.platform==='win32'?join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe'):null;
 if(powershell&&!existsSync(powershell)){t.skip('read-only Windows process witness unavailable');return;}
 const env={TZ:'UTC'};if(process.env.SystemRoot)env.SystemRoot=process.env.SystemRoot;
 const child=spawn(process.execPath,[join(sourceRoot,'tests/hermes_runtime/process_candidate/controller-crash-host.mjs')],{cwd:sourceRoot,env,stdio:['ignore','pipe','pipe'],windowsHide:true});
 t.after(()=>{if(child.exitCode===null)child.kill();});let stderr='';child.stderr.on('data',b=>{stderr+=b.toString();});
 const info=await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('CRASH_HOST_START_TIMEOUT '+stderr)),3000);createInterface({input:child.stdout}).once('line',line=>{clearTimeout(timer);resolve(JSON.parse(line));});});
 assert.equal(info.pids.length,2);assert(info.pids.every(p=>Number.isSafeInteger(p)&&p>0));
 const exited=new Promise(resolve=>child.once('exit',resolve));child.kill();await exited;
 const alive=()=>{
  if(powershell){const script='$ids=@('+info.pids.join(',')+'); $live=@($ids | Where-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue }); ConvertTo-Json -InputObject $live -Compress';
   return JSON.parse(execFileSync(powershell,['-NoProfile','-NonInteractive','-Command',script],{env,encoding:'utf8',windowsHide:true,timeout:3000}));}
  return info.pids.filter(pid=>{try{return readFileSync('/proc/'+pid+'/stat','utf8').split(') ')[1][0]!=='Z';}catch{return false;}});
 };
 await new Promise(resolve=>setTimeout(resolve,150));let remaining=alive();
 for(let i=0;i<5&&remaining.length;i++){await new Promise(resolve=>setTimeout(resolve,100));remaining=alive();}
 assert.deepEqual(remaining,[]);writeFileSync(join(sourceRoot,'RT-01/process-candidate/evidence/controller-death.json'),JSON.stringify({controlled_host_pid:child.pid,worker_pids:info.pids,remaining,probe:'READ_ONLY_PROCESS_INVENTORY',pid_kills_used:false,real_hermes:'REAL_HERMES_NOT_RUN'},null,2)+'\n');
});
test('restart HOLD forbids fresh run IDs and close forbids further admissions',async t=>{
 const f=await processFixture(t);await f.launch();await f.restart();const fresh=f.request('run_fresh');
 assert.equal((await f.launch(fresh)).code,'RT_HOST_STARTUP_HOLD');assert.equal(f.counts.begin,1);assert.equal(f.adapter.inspectProcesses().active,0);
 await f.adapter.close();assert.equal((await f.launch(fresh)).code,'RT_HOST_CLOSED');assert.equal(f.counts.begin,1);
});
test('revocation before poll immediately stops the whole active process tree',async t=>{
 const f=await processFixture(t);await f.launch();await f.launch(f.child());f.control.revoked=true;
 assert.equal((await f.adapter.runtime.join('run_parent')).status,'OUTCOME_UNKNOWN');assert.equal(f.adapter.inspectProcesses().active,0);
});
test('worker join also fences revoked authority and stops its owned process',async t=>{
 const f=await processFixture(t);await f.launch();const worker=f.adapter.runtime.bindWorker('run_parent',f.session);f.control.revoked=true;
 assert.equal((await worker.join()).status,'OUTCOME_UNKNOWN');assert.equal(f.adapter.inspectProcesses().active,0);
});
test('forged worker session cannot cancel another task process',async t=>{
 const f=await processFixture(t);await f.launch();const worker=f.adapter.runtime.bindWorker('run_parent',{});
 assert.equal((await worker.cancel()).code,'RT_HOST_WORKER_DENIED');assert.equal((await worker.join()).code,'RT_HOST_WORKER_DENIED');assert.equal(f.adapter.inspectProcesses().active,1);
});
test('journal failure after actual spawn still stops process and does not expose dependency text',async t=>{
 const f=await processFixture(t);let writes=0;const journal={read:f.journal.read,append:e=>{if(++writes>1)throw Error('SECRET_JOURNAL_CANARY');return f.journal.append(e);}};
 const adapter=createInt04ProcessAdapter({...f.ports,journal},{contract:INT04_PROCESS_CONTRACT});t.after(()=>adapter.close());
 const r=await adapter.runtime.launchChild(JSON.stringify(f.request()));assert.equal(r.decision,'DENY');assert.equal(adapter.inspectProcesses().spawn_count,1);assert.equal(adapter.inspectProcesses().active,0);assert.equal(JSON.stringify(r).includes('SECRET_JOURNAL'),false);
});
test('JSON escaping cannot bypass IPC context byte cap or cause an unobserved promise',async t=>{
 const f=await processFixture(t),text='\u0000'.repeat(9000),q=f.request();f.ports.context.read=()=>text;q.context.hash=digest({text});q.admission.payload_hash=q.context.hash;q.admission.plan_hash=planHash(q);
 const r=await f.launch(q);assert.equal(r.status,'OUTCOME_UNKNOWN');assert.equal(f.adapter.inspectProcesses().spawn_count,0);
});
