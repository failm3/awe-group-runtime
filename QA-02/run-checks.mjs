import {mkdirSync,writeFileSync,readFileSync,readdirSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {bytesHash} from '../awe/qa/common.mjs';
import {runnerHash} from '../awe/qa_profiles/runner.mjs';
const root=fileURLToPath(new URL('../',import.meta.url)),started=new Date().toISOString();
const out=join(root,'QA-02/evidence',started.replaceAll(/[:.]/g,'-'));mkdirSync(out,{recursive:true});
const sourceHash=runnerHash();
const env={TZ:'UTC',LANG:'C',NO_COLOR:'1',AWE_OFFLINE:'1'};
for(const key of ['SystemRoot','WINDIR','PATH','TEMP','TMP','USERPROFILE','LOCALAPPDATA'])if(process.env[key])env[key]=process.env[key];
const results=[];
const suites=['contracts','security','state','integration','runtime','context','budget','memory_artifacts','integration_v2','qa'];
const jobs=suites.map(id=>({id,guard:'baseline/offline-guard.cjs',tests:readdirSync(join(root,'tests',id)).filter(x=>x.endsWith('.test.mjs')).map(x=>'tests/'+id+'/'+x)}));
jobs.push({id:'persistence-offline',guard:'baseline/offline-guard.cjs',tests:['tests/persistence/adapter.test.mjs']},
 {id:'qa02-core',guard:'baseline/offline-guard.cjs',tests:['tests/qa02/profiles.test.mjs','tests/qa02/adversarial.test.mjs']},
 {id:'qa02-browser',guard:'awe/qa_profiles/node-guard.cjs',tests:['tests/qa02/browser.test.mjs']});
for(const job of jobs){
 const args=['--require','./'+job.guard,'--test','--test-isolation=none','--test-concurrency=1','--test-reporter=tap',...job.tests];
 const start=new Date().toISOString(),r=spawnSync(process.execPath,args,{cwd:root,env,encoding:'utf8',timeout:180000,maxBuffer:16*1024*1024,windowsHide:true});
 const stdout=r.stdout??'',stderr=r.stderr??'';
 writeFileSync(join(out,job.id+'.tap'),stdout);writeFileSync(join(out,job.id+'.stderr'),stderr);
 const counts=Object.fromEntries([...stdout.matchAll(/^# (tests|pass|fail|cancelled|skipped|todo) (\d+)$/gm)].map(m=>[m[1],Number(m[2])]));
 const row={id:job.id,command:[process.execPath,...args],cwd:root,started_at:start,finished_at:new Date().toISOString(),exit_code:r.status,error:r.error?.message??null,signal:r.signal,counts,
  stdout:{path:job.id+'.tap',sha256:bytesHash(Buffer.from(stdout))},stderr:{path:job.id+'.stderr',sha256:bytesHash(Buffer.from(stderr))}};
 results.push(row);console.log(JSON.stringify({id:job.id,exit:r.status,...counts}));
}
const counts=results.reduce((a,r)=>{for(const [k,n] of Object.entries(r.counts))a[k]=(a[k]??0)+n;return a;},{});
const report={version:'qa02-evidence/1',started_at:started,finished_at:new Date().toISOString(),node:process.version,node_executable_sha256:bytesHash(readFileSync(process.execPath)),qa02_test_code_hash:sourceHash,source_unchanged:sourceHash===runnerHash(),results,counts,
 status:sourceHash===runnerHash()&&results.every(r=>r.exit_code===0&&r.counts.tests>0&&r.counts.fail===0&&r.counts.skipped===0&&r.counts.cancelled===0)?'PASS':'FAIL',
 not_run:['94 BASE03 PostgreSQL tests','INT04 native adoption','AUTO02 native planner integration','LIVE LLM','real Hermes','OS/VM isolation','production acceptance'],physical_decision:'DENY'};
writeFileSync(join(out,'results.json'),JSON.stringify(report,null,2)+'\n');
writeFileSync(join(root,'QA-02/LATEST-TESTS.json'),JSON.stringify({evidence:out,results:report},null,2)+'\n');
writeFileSync(join(out,'EVIDENCE.sha256'),readdirSync(out).sort().map(name=>bytesHash(readFileSync(join(out,name)))+'  '+name).join('\n')+'\n');
console.log(JSON.stringify({status:report.status,counts,evidence:out}));if(report.status!=='PASS')process.exitCode=1;
