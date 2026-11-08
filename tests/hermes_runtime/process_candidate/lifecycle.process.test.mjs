import test from 'node:test';
import assert from 'node:assert/strict';
import {join} from 'node:path';
import {writeFileSync,readFileSync} from 'node:fs';
import {processFixture} from './fixture.mjs';
import {sourceRoot} from '../../../awe/hermes_runtime/profile.mjs';
import {createInt04ProcessAdapter,INT04_PROCESS_CONTRACT} from '../../../awe/hermes_runtime/int04-process-adapter.mjs';
import {planHash} from '../../../awe/hermes_runtime/adapter.mjs';
const evidence=(name,value)=>writeFileSync(join(sourceRoot,'RT-01/process-candidate/evidence',name+'.json'),JSON.stringify(value,null,2)+'\n');
test('parent and two subagents have separate actual processes, scoped structured outputs and zero physical effects',async t=>{
 const f=await processFixture(t);assert.equal((await f.launch()).status,'RUNNING');
 for(const id of ['run_child_one','run_child_two'])assert.equal((await f.launch(f.child(id))).status,'RUNNING');
 const running=f.adapter.inspectProcesses();assert.equal(running.active,3);assert.equal(new Set(running.runs.map(r=>r.pid)).size,3);
 for(const id of ['run_child_one','run_child_two','run_parent']){
  const r=await f.adapter.runtime.join(id);assert.equal(r.status,'WORK_COMPLETED',JSON.stringify(r));
  const out=f.adapter.readOutput(r.artifact.artifact_ref);assert.equal(out.schema,'rt01.process.result/1');assert.equal(out.utf8_bytes,21);
  assert.equal(Object.hasOwn(out,'history'),false);assert.equal(r.qa,'QA_NOT_RUN');assert.equal(r.authoritative_complete,false);
 }
 const finished=f.adapter.inspectProcesses();assert.equal(finished.active,0);assert.equal(f.counts.begin,3);assert.equal(f.counts.result,3);assert.equal(f.task().state,'RUNNING');
 evidence('parent-child-processes',{running,finished,counts:f.counts,d03_state:f.task().state,real_hermes:'REAL_HERMES_NOT_RUN'});
});
test('tree cancellation acknowledges actual exit of parent and children',async t=>{
 const f=await processFixture(t);await f.launch();await f.launch(f.child());const result=await f.adapter.runtime.cancel('run_parent');assert.equal(result.status,'CANCELLED',JSON.stringify(result));
 const p=f.adapter.inspectProcesses();assert.equal(p.active,0);assert(p.runs.every(r=>r.exited&&r.cancel_proof.exited&&!r.cancel_proof.forced));evidence('cancel-proof',p);
});
test('uncooperative cancellation is escalated to owned ChildProcess.kill and exit is awaited',async t=>{
 const f=await processFixture(t,{syntheticFaults:{run_parent:'ignore_cancel'}});await f.launch();assert.equal((await f.adapter.runtime.cancel('run_parent')).status,'CANCELLED');
 const p=f.adapter.inspectProcesses();assert.equal(p.active,0);assert.equal(p.runs[0].cancel_proof.forced,true);evidence('forced-cancel',p);
});
test('late successful reply during cancellation is discarded; no result is billed as success',async t=>{
 const f=await processFixture(t,{syntheticFaults:{run_parent:'late_result'}});await f.launch();const r=await f.adapter.runtime.cancel('run_parent');assert.equal(r.status,'CANCELLED');assert.equal(r.artifact,null);assert.equal(f.adapter.inspectProcesses().active,0);
});
for(const behavior of ['hang','crash','malformed','flood','stderr_flood','binding_spoof','history','duplicate','nonzero_exit'])test('real process fault '+behavior+' is unknown, stopped and never replayed',async t=>{
 const f=await processFixture(t,{syntheticFaults:{run_parent:behavior}});await f.launch();const r=await f.adapter.runtime.join('run_parent');assert.equal(r.status,'OUTCOME_UNKNOWN',JSON.stringify(r));
 assert.equal(f.adapter.inspectProcesses().active,0);assert.equal((await f.launch()).status,'OUTCOME_UNKNOWN');assert.equal(f.counts.begin,1);assert.equal(f.adapter.inspectProcesses().spawn_count,1);
 evidence('fault-'+behavior,{result:r,process:f.adapter.inspectProcesses()});
});
test('structured known synthetic error maps FAILED rather than invented success',async t=>{
 const f=await processFixture(t,{syntheticFaults:{run_parent:'error'}});await f.launch();assert.equal((await f.adapter.runtime.join('run_parent')).status,'FAILED');assert.equal(f.adapter.inspectProcesses().active,0);
});
test('actual CPU usage trips cooperative resource watchdog and process is stopped',async t=>{
 const f=await processFixture(t,{limits:{max_cpu_micros:200000},syntheticFaults:{run_parent:'cpu'}});await f.launch();const r=await f.adapter.runtime.join('run_parent');assert.equal(r.status,'OUTCOME_UNKNOWN');const p=f.adapter.inspectProcesses();assert.equal(p.active,0);assert(p.runs[0].usage.cpu_micros>200000);evidence('cpu-limit',p);
});
test('actual allocated memory trips RSS watchdog and process is stopped',async t=>{
 const f=await processFixture(t,{limits:{max_rss_bytes:64*1024*1024},syntheticFaults:{run_parent:'memory'}});await f.launch();const r=await f.adapter.runtime.join('run_parent');assert.equal(r.status,'OUTCOME_UNKNOWN');const p=f.adapter.inspectProcesses();assert.equal(p.active,0);assert(p.runs[0].usage.rss_bytes>64*1024*1024);evidence('rss-limit',p);
});
test('hard wall timer stops idle process even when join was never called',async t=>{
 const f=await processFixture(t,{limits:{lifetime_ms:700}});await f.launch();await new Promise(resolve=>setTimeout(resolve,850));
 assert.equal((await f.adapter.runtime.reconcile('run_parent')).status,'OUTCOME_UNKNOWN');assert.equal(f.adapter.inspectProcesses().active,0);evidence('lifetime-limit',f.adapter.inspectProcesses());
});
test('global process cap closes admission without creating a third process',async t=>{
 const f=await processFixture(t,{limits:{max_processes:2}});await f.launch();await f.launch(f.child('run_one'));const r=await f.launch(f.child('run_two'));assert.equal(r.status,'OUTCOME_UNKNOWN');assert.equal(f.adapter.inspectProcesses().spawn_count,2);await f.adapter.close();assert.equal(f.adapter.inspectProcesses().active,0);
});
test('bounded context denied before a process can read it',async t=>{const f=await processFixture(t,{limits:{context_bytes:10}});assert.equal((await f.launch()).status,'OUTCOME_UNKNOWN');assert.equal(f.adapter.inspectProcesses().spawn_count,0);});
test('task/project grant widening and extra dispatch authority are denied before spawn',async t=>{
 const f=await processFixture(t);const req=f.request();req.context.project_id='prj_foreign';req.admission.plan_hash=planHash(req);assert.equal((await f.launch(req)).decision,'DENY');assert.equal(f.adapter.inspectProcesses().spawn_count,0);
 assert.throws(()=>createInt04ProcessAdapter({...f.ports,transport:{}},{contract:INT04_PROCESS_CONTRACT}),/FACTORY_FIELDS/);
});
test('current authority revocation fences result even though synthetic child could compute',async t=>{
 const f=await processFixture(t);await f.launch();f.control.revoked=true;assert.equal((await f.adapter.runtime.join('run_parent')).status,'OUTCOME_UNKNOWN');await f.adapter.close();assert.equal(f.counts.result,0);assert.equal(f.adapter.inspectProcesses().active,0);
});
test('checkpoint contains bounded metadata, restart is HOLD and cannot resume or kill saved PID',async t=>{
 const f=await processFixture(t);await f.launch();const path=join(f.dir,'process-checkpoint.json'),cp=await f.adapter.checkpoint('run_parent',path);
 assert.equal(cp.resumable,false);assert.equal(cp.startup,'HOLD');assert.equal(readFileSync(path,'utf8').includes('AWE synthetic context'),false);
 const restarted=await f.restart(path);assert.equal(restarted.startup,'HOLD');assert.equal(restarted.runtime.inspect('run_parent').status,'OUTCOME_UNKNOWN');
 const r=await f.launch();assert(r.status==='OUTCOME_UNKNOWN'||r.decision==='DENY');assert.equal(restarted.inspectProcesses().spawn_count,0);evidence('restart-checkpoint',{checkpoint:cp,after:restarted.inspectProcesses(),result:r});
});
test('checkpoint tamper and missing file fail closed before process construction',async t=>{
 const f=await processFixture(t);await f.launch();const path=join(f.dir,'checkpoint.json');await f.adapter.checkpoint('run_parent',path);writeFileSync(path,readFileSync(path,'utf8').replace('resumable":false','resumable":true'));
 assert.throws(()=>f.adapter.recover(path),/CORRUPT/);assert.throws(()=>createInt04ProcessAdapter(f.ports,{contract:INT04_PROCESS_CONTRACT,startupCheckpoint:join(f.dir,'missing.json')}));
});
test('versioned INT04 invoke uses existing runtime facade; wrong version/method/run is DENY',async t=>{
 const f=await processFixture(t),call=(changes={})=>f.adapter.invoke(JSON.stringify({contract:INT04_PROCESS_CONTRACT,method:'launchChild',run_id:'run_parent',request:JSON.stringify(f.request()),...changes}));
 assert.equal((await call({contract:'int04.rt01.process/2'})).decision,'DENY');assert.equal((await call({method:'nativeDispatch'})).decision,'DENY');assert.equal((await call({run_id:'run_other'})).decision,'DENY');
 const r=await call();assert.equal(r.contract,INT04_PROCESS_CONTRACT);assert.equal(r.result.status,'RUNNING');assert.equal(r.physical_decision,'DENY');
 for(const method of ['launchChild','join','checkpoint','cancel','reconcile'])assert.equal(f.adapter.native[method]().code,'REAL_HERMES_NOT_RUN');
});
test('host dependency secret exceptions are sanitized before journal and public response',async t=>{
 const f=await processFixture(t);f.ports.context.read=()=>{throw Error('SECRET_CANARY_DO_NOT_EXPORT');};const r=await f.launch();assert.equal(r.decision,'DENY');assert.equal(JSON.stringify(r).includes('SECRET_CANARY'),false);assert.equal(readFileSync(f.path,'utf8').includes('SECRET_CANARY'),false);
});
test('worker facade cannot create processes or claim QA/acceptance/physical permission',async t=>{
 const f=await processFixture(t);await f.launch();const worker=f.adapter.runtime.bindWorker('run_parent',f.session);assert.equal(worker.launchChild,undefined);
 for(const method of ['submitQa','accept','executeTool','requestPhysicalEffect'])assert.equal(worker[method]().physical_decision,'DENY');assert.equal(worker.proposeChild('{}').decision,'DENY');
});
