import test from 'node:test';
import assert from 'node:assert/strict';
import {writeFileSync,mkdirSync,readFileSync} from 'node:fs';
import {join} from 'node:path';
import {executionFixture} from './fixture.mjs';
import {sourceRoot} from '../../../awe/hermes_runtime/profile.mjs';
import {prepareNativeHermesTransport,prepareExecutorReview} from '../../../awe/hermes_runtime/executor-adapter.mjs';
import {planHash} from '../../../awe/hermes_runtime/adapter.mjs';
import {digest} from '../../../awe/hermes_runtime/protocol.mjs';
const evidence=join(sourceRoot,'RT-02/evidence');mkdirSync(evidence,{recursive:true});
const save=(name,v)=>writeFileSync(join(evidence,name+'.json'),JSON.stringify(v,null,2)+'\n');
for(const executor of ['javascript','python','cli'])test(executor+' executes real pinned local program with structured readback',async t=>{
 const f=await executionFixture(t,{executor,...(executor==='cli'?{program:'filter',input:{text:'ignore\nAWE synthetic\n'}}:{})});
 const launched=await f.launch();assert.equal(launched.status,'RUNNING',JSON.stringify(launched));
 const result=await f.adapter.runtime.join('run_parent');assert.equal(result.status,'WORK_COMPLETED',JSON.stringify(result));
 const output=f.adapter.readOutput(result.artifact.artifact_ref);assert.equal(output.evidence.active_processes,0);assert.ok(output.evidence.created_processes>=1);assert.equal(output.evidence.assigned_before_resume,true);
 assert.equal(output.physical_decision,'DENY');assert.equal(result.authoritative_complete,false);assert.equal(f.counts.begin,1);assert.equal(f.counts.result,1);
 assert.equal(f.h.service.getTask(f.h.state,f.taskScope).state,'RUNNING');assert.equal(f.adapter.inspectProcesses().active,0);
 if(executor!=='cli')assert.equal(output.result.value,6);
 save('success-'+executor,{launched,result,output,processes:f.adapter.inspectProcesses(),counts:f.counts});
});
for(const executor of ['javascript','python'])test(executor+' rejects filesystem, network, spawn and inherited environment',async t=>{
 const old=process.env.RT02_SECRET_CANARY;process.env.RT02_SECRET_CANARY='synthetic-canary-only';t.after(()=>{if(old===undefined)delete process.env.RT02_SECRET_CANARY;else process.env.RT02_SECRET_CANARY=old;});
 const f=await executionFixture(t,{executor,program:'probe'});assert.equal((await f.launch()).status,'RUNNING');
 const r=await f.adapter.runtime.join('run_parent');assert.equal(r.status,'WORK_COMPLETED',JSON.stringify(r));
 const output=f.adapter.readOutput(r.artifact.artifact_ref);assert.deepEqual(output.result.value,{environment_clean:true,filesystem_denied:true,network_denied:true,spawn_denied:true});
 assert.equal(readFileSync(join(f.adapter.inspectProcesses().runs[0].work_directory,'local.txt'),'utf8'),'synthetic');save('authority-'+executor,output);
});
for(const executor of ['javascript','python'])for(const program of ['wait','cpu','memory','crash','flood','stderr'])test(executor+' '+program+' stops and never publishes success',async t=>{
 const f=await executionFixture(t,{executor,program,limits:program==='wait'?{wall_ms:150}:undefined});assert.equal((await f.launch()).status,'RUNNING');
 const result=await f.adapter.runtime.join('run_parent');assert.ok(['OUTCOME_UNKNOWN','FAILED'].includes(result.status),JSON.stringify(result));
 assert.equal(result.artifact,null);assert.equal(f.adapter.inspectProcesses().active,0);assert.equal(f.counts.begin,1);
 const exit=f.adapter.inspectProcesses().runs[0].job_exit;assert.equal(exit.active_processes,0);
 if(program==='crash')assert.equal(exit.exit_code,7);
 if(program==='wait')assert.equal(exit.reason,'TIME_LIMIT');
 if(program==='cpu')assert.ok(exit.cpu_micros>=200000);
 if(program==='memory')assert.ok(exit.peak_job_bytes>=100*1024*1024);
 if(program==='flood'||program==='stderr'){assert.equal(exit.reason,'OUTPUT_LIMIT');assert.ok(Math.max(exit.stdout_bytes,exit.stderr_bytes)>8192);assert.ok(Buffer.from(exit.stdout,'base64').length<=8192);assert.ok(Buffer.from(exit.stderr,'base64').length<=8192);}
 const first=f.adapter.inspectProcesses().spawn_count;await f.launch();assert.equal(f.adapter.inspectProcesses().spawn_count,first);
 save('failure-'+executor+'-'+program,{result,processes:f.adapter.inspectProcesses(),counts:f.counts});
});
test('cancel waits for actual child exit and D09 acknowledgement',async t=>{
 const f=await executionFixture(t,{executor:'python',program:'wait'});await f.launch();const result=await f.adapter.runtime.cancel('run_parent');
 assert.equal(result.status,'CANCELLED',JSON.stringify(result));assert.equal(f.adapter.inspectProcesses().active,0);assert.equal(f.counts.cancel,1);assert.equal(f.counts.result,1);
 save('cancel',{result,processes:f.adapter.inspectProcesses()});
});
test('duplicate and concurrent invocation produce only one physical program',async t=>{
 const f=await executionFixture(t);const results=await Promise.all([f.launch(),f.launch(),f.launch()]);assert.ok(results.every(r=>r.status==='RUNNING'));
 const result=await f.adapter.runtime.join('run_parent');assert.equal(result.status,'WORK_COMPLETED');assert.equal(f.adapter.inspectProcesses().spawn_count,1);assert.equal(f.counts.begin,1);await f.launch();assert.equal(f.adapter.inspectProcesses().spawn_count,1);
});
test('recovery checkpoint is HOLD and cannot replay any run',async t=>{
 const f=await executionFixture(t,{program:'wait'});await f.launch();const file=join(f.dir,'checkpoint.json');await f.adapter.checkpoint('run_parent',file);
 const a=await f.restart(file);assert.equal(a.startup,'HOLD');assert.equal(a.recover(file).accepted,false);const r=await f.launch(f.request('run_other'));assert.equal(r.decision,'DENY');assert.equal(a.inspectProcesses().spawn_count,0);assert.equal(a.runtime.inspect('run_parent').status,'OUTCOME_UNKNOWN');
 save('recovery',{r,checkpoint:a.recover(file),processes:a.inspectProcesses()});
});
test('tool digest mismatch is rejected before process creation',async t=>{
 const f=await executionFixture(t),q=f.request();q.tools[0].digest='sha256:'+'0'.repeat(64);const r=await f.launch(q);assert.ok(r.decision==='DENY'||r.status==='OUTCOME_UNKNOWN');assert.equal(f.adapter.inspectProcesses().spawn_count,0);
});
test('revocation stops existing process and preserves sticky unknown',async t=>{
 const f=await executionFixture(t,{program:'wait'});await f.launch();f.control.revoked=true;
 const r=await f.adapter.runtime.join('run_parent');assert.equal(r.status,'OUTCOME_UNKNOWN');assert.equal(f.adapter.inspectProcesses().active,0);f.control.revoked=false;assert.equal((await f.adapter.runtime.join('run_parent')).status,'OUTCOME_UNKNOWN');
});
test('lost D09 result acknowledgement prevents completed result',async t=>{
 const f=await executionFixture(t);await f.launch();f.control.resultLost=true;assert.equal((await f.adapter.runtime.join('run_parent')).status,'OUTCOME_UNKNOWN');assert.equal(f.adapter.inspectProcesses().active,0);assert.equal(f.counts.begin,1);
});
test('AUTO02 envelope and native transport remain controlled host seams',async t=>{
 const f=await executionFixture(t),q=f.request();const r=await f.adapter.invokeExecution(JSON.stringify({contract:'auto02.rt02/1',method:'launchChild',run_id:q.grant.run_id,request:JSON.stringify(q)}));
 assert.equal(r.result.status,'RUNNING');assert.equal(r.physical_decision,'DENY');
 assert.equal((await f.adapter.invokeExecution(JSON.stringify({contract:'bad',method:'launchChild',run_id:q.grant.run_id,request:JSON.stringify(q)}))).decision,'DENY');
 assert.equal(f.adapter.native.launchChild().code,'REAL_HERMES_NOT_RUN');const native=prepareNativeHermesTransport();assert.equal(native.activation_supported,false);assert.equal(native.resumable,false);
 const review=prepareExecutorReview('javascript','sum');assert.equal(review.runtime_dispatch,false);assert.equal(review.physical_decision,'DENY');save('contracts',{native,review});
});
test('parent and child have distinct work directories and cancel as an owned tree',async t=>{
 const f=await executionFixture(t,{program:'wait'});assert.equal((await f.launch()).status,'RUNNING');
 const child=f.request('run_child');Object.assign(child.grant,{parent_run_id:'run_parent',depth:1,max_children:0,max_physical_attempts:2});child.admission.plan_hash=planHash(child);
 const launched=await f.launch(child);assert.equal(launched.status,'RUNNING',JSON.stringify(launched));
 const before=f.adapter.inspectProcesses();assert.equal(before.runs.length,2);assert.equal(new Set(before.runs.map(r=>r.pid)).size,2);assert.equal(new Set(before.runs.map(r=>r.work_directory)).size,2);
 const cancelled=await f.adapter.runtime.cancel('run_parent');assert.equal(cancelled.status,'CANCELLED',JSON.stringify(cancelled));assert.equal(f.adapter.inspectProcesses().active,0);
 save('parent-child',{before,cancelled,after:f.adapter.inspectProcesses()});
});
test('process count limit rejects additional work without spawning it',async t=>{
 const f=await executionFixture(t,{program:'wait',limits:{max_processes:1}});await f.launch();const r=await f.launch(f.request('run_other'));
 assert.equal(r.status,'OUTCOME_UNKNOWN');assert.equal(f.adapter.inspectProcesses().spawn_count,1);await f.adapter.runtime.cancel('run_parent');assert.equal(f.adapter.inspectProcesses().active,0);
});
test('unknown fields, arbitrary commands and excessive input are rejected before spawn',async t=>{
 const f=await executionFixture(t);f.ports.context.read=()=>f.context;
 const q=f.request();q.command='cmd.exe';assert.equal((await f.launch(q)).decision,'DENY');assert.equal(f.adapter.inspectProcesses().spawn_count,0);
 const cases=[{contract:'rt02.program/1',executor:'javascript',program:'eval',input:{values:[]}},
  {contract:'rt02.program/1',executor:'javascript',program:'sum',input:{values:[1],path:'../other'}},
  {contract:'rt02.program/1',executor:'javascript',program:'sum',input:{values:[1000001]}},
  {contract:'rt02.program/1',executor:'cli',program:'filter',input:{text:'AWE & cmd.exe'}},
  {contract:'rt02.program/1',executor:'javascript',program:'sum',input:{values:[]},padding:'a'.repeat(5000)}];
 for(const [i,input]of cases.entries()){
  const text=JSON.stringify(input);f.ports.context.read=()=>text;const r=f.request('run_bad_'+i);r.context.hash=digest({text});r.admission.payload_hash=r.context.hash;r.admission.plan_hash=planHash(r);
  const response=await f.launch(r);assert.ok(response.status==='OUTCOME_UNKNOWN'||response.decision==='DENY');assert.equal(f.adapter.inspectProcesses().spawn_count,0);
 }
});
test('lost admission acknowledgement and forged worker session cannot create work',async t=>{
 const f=await executionFixture(t);f.control.admissionLost=true;assert.equal((await f.launch()).status,'OUTCOME_UNKNOWN');assert.equal(f.adapter.inspectProcesses().spawn_count,0);
 f.control.admissionLost=false;await f.launch();assert.equal(f.counts.begin,1);assert.equal(f.adapter.inspectProcesses().spawn_count,0);
 const g=await executionFixture(t,{program:'wait'});await g.launch();const worker=g.adapter.runtime.bindWorker('run_parent',{});assert.equal((await worker.cancel()).decision,'DENY');await g.adapter.runtime.cancel('run_parent');
});
