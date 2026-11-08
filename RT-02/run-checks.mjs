import {spawnSync} from 'node:child_process';
import {readFileSync,writeFileSync,mkdirSync,readdirSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {createHash} from 'node:crypto';
const root=resolve(import.meta.dirname,'..'),out=join(root,'RT-02/evidence');mkdirSync(out,{recursive:true});
const env={TZ:'UTC'};for(const k of ['SystemRoot','WINDIR','TEMP','TMP'])if(process.env[k])env[k]=process.env[k];
const suites=[['rt02',['tests/hermes_runtime/rt02/executors.test.mjs','tests/hermes_runtime/rt02/job-boundaries.test.mjs'],false],['rt01-process-candidate',['tests/hermes_runtime/process_candidate/lifecycle.process.test.mjs','tests/hermes_runtime/process_candidate/controller.process.test.mjs'],false],['rt01-unit',['tests/hermes_runtime/d09-port.test.mjs','tests/hermes_runtime/events.test.mjs','tests/hermes_runtime/journal-profile.test.mjs','tests/hermes_runtime/lifecycle.test.mjs'],true],['rt01-process',['tests/hermes_runtime/process.test.mjs'],false]];
const selected=process.argv[2];const rows=[];
for(const [name,files,guard]of suites){
 if(selected&&selected!==name)continue;
 const args=[...(guard?['--require','./baseline/offline-guard.cjs']:[]),'--test','--test-isolation=none','--test-concurrency=1','--test-reporter=tap',...files];
 const started=new Date().toISOString(),r=spawnSync(process.execPath,args,{cwd:root,env,encoding:'utf8',timeout:90000,maxBuffer:8*1024*1024,windowsHide:true});
 writeFileSync(join(out,name+'.tap'),r.stdout??'');writeFileSync(join(out,name+'.stderr'),r.stderr??'');
 const count=k=>Number(new RegExp('^# '+k+' (\\d+)','m').exec(r.stdout??'')?.[1]??0);
 const row={name,args,started,finished:new Date().toISOString(),exit:r.status,tests:count('tests'),pass:count('pass'),fail:count('fail'),cancelled:count('cancelled'),skipped:count('skipped'),status:r.status===0&&count('tests')>0?'PASS':'FAIL'};
 rows.push(row);console.log(JSON.stringify(row));
}
writeFileSync(join(out,selected?'results-'+selected+'.json':'results.json'),JSON.stringify({node:process.version,node_hash:createHash('sha256').update(readFileSync(process.execPath)).digest('hex'),rows,real_hermes:'REAL_HERMES_NOT_RUN',physical_decision:'DENY',production_ready:false},null,2)+'\n');
process.exitCode=rows.length&&rows.every(r=>r.status==='PASS')?0:1;
