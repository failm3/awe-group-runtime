// Parent test harness only; child processes use the unchanged network/process guard.
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
const root=path.resolve(import.meta.dirname,'../..'),sandbox=path.join(root,'DATA-02/sandbox');
const run=(action,directory,stage,expected=0)=>{
  const args=['--require',path.join(root,'baseline/offline-guard.cjs'),path.join(import.meta.dirname,'restart-worker.mjs'),action,directory];if(stage)args.push(stage);
  const env={};for(const k of ['SystemRoot','WINDIR','TEMP','TMP'])if(process.env[k])env[k]=process.env[k];
  const out=spawnSync(process.execPath,args,{cwd:root,env,encoding:'utf8',timeout:10000,maxBuffer:65536,windowsHide:true});
  assert.equal(out.status,expected,out.stderr);return out.stdout.trim()?JSON.parse(out.stdout):null;
};
const directory=fs.mkdtempSync(path.join(sandbox,'restart-')),seed=run('seed',directory),restored=run('read',directory);
assert.notEqual(seed.pid,restored.pid);assert.equal(restored.refs,2);
console.log('PASS real-process restart: exact goals/spec history, fresh sessions, no resume');
for(const stage of ['after_stage','after_publish']){
  const dir=fs.mkdtempSync(path.join(sandbox,'crash-'));run('crash',dir,stage,73);run('after-crash',dir,stage);
  console.log('PASS abrupt process exit '+stage+': verified visibility and retained writer HOLD');
}
console.log(JSON.stringify({status:'PASS',tests:3,subprocess_restart:true,power_loss:'NOT_RUN'}));
