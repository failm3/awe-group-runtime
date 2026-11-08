import {spawnSync} from 'node:child_process';
import {readFileSync,readdirSync,mkdirSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve,join} from 'node:path';
const root=resolve(import.meta.dirname,'../..'),base=join(root,'LLM-01/model-broker-2026-11-06');
const dir=join(base,'evidence',new Date().toISOString().replaceAll(':','-'));mkdirSync(dir,{recursive:true});
if(process.version!=='v24.21.0')throw Error('PINNED_NODE_REQUIRED');
const env={TZ:'UTC'};for(const key of ['SystemRoot','WINDIR','PATH','TEMP','TMP','COMSPEC'])if(process.env[key])env[key]=process.env[key];
const previous=process.argv.includes('--profile-only')?JSON.parse(readFileSync(join(base,'LATEST-TESTS.json'),'utf8')):null;
const prior=previous?JSON.parse(readFileSync(previous.receipt,'utf8')):null;
const suites=prior?prior.suites.filter(x=>x.suite!=='model_gateway'):[];
for(const suite of prior?['model_gateway']:['contracts','security','state','memory_artifacts','context','runtime','budget','integration','integration_v2','qa','persistence','model_gateway']) {
 const files=readdirSync(join(root,'tests',suite)).filter(x=>x.endsWith('.test.mjs')&&x!=='postgres.test.mjs').sort().map(x=>'tests/'+suite+'/'+x);
 const args=['--require','./baseline/offline-guard.cjs','--test','--test-reporter=tap','--test-isolation=none','--test-concurrency=1',...files];
 const startedAt=new Date().toISOString(),r=spawnSync(process.execPath,args,{cwd:root,env,encoding:'utf8',windowsHide:true,timeout:60000,maxBuffer:16*1024*1024});
 writeFileSync(join(dir,suite+'.tap'),r.stdout??'');writeFileSync(join(dir,suite+'.stderr.txt'),r.stderr??'');
 const count=k=>Number((r.stdout??'').match(new RegExp('^# '+k+' (\\d+)$','m'))?.[1]??0);
 const row={suite,startedAt,exit:r.status,error:r.error?.code??null,tests:count('tests'),pass:count('pass'),fail:count('fail'),skipped:count('skipped'),command:[process.execPath,...args],status:r.status===0&&count('fail')===0&&count('tests')>0?'PASS':'FAIL'};
 suites.push(row);console.log(JSON.stringify({suite,pass:row.pass,fail:row.fail,status:row.status}));
}
const sources=[];for(const area of ['awe/model_gateway','tests/model_gateway'])for(const f of readdirSync(join(root,area))) {
 const bytes=readFileSync(join(root,area,f));sources.push({path:area+'/'+f,sha256:createHash('sha256').update(bytes).digest('hex')});
}
const receipt={version:'LLM01_MODEL_BROKER_TESTS_V1',recordedAt:new Date().toISOString(),node:process.version,nodeSha256:createHash('sha256').update(readFileSync(process.execPath)).digest('hex'),
 baselineEvidence:prior?.baselineEvidence??previous?.receipt??null,
 suites,sources,baselinePass:suites.filter(x=>x.suite!=='model_gateway').reduce((n,x)=>n+x.pass,0),profilePass:suites.find(x=>x.suite==='model_gateway').pass,
 notRun:[{suite:'D09_REAL_PG',tests:39},{suite:'INT03_REAL_PG',tests:42},{suite:'AUD01_REAL_PG',tests:13}],
 notRunReason:'No working database touched; these real PG suites require separately isolated tooling/harness. Native D09/SEC02 dispatch remains DENY.',liveCalls:0,physicalDecision:'DENY'};
writeFileSync(join(dir,'results.json'),JSON.stringify(receipt,null,2)+'\n');writeFileSync(join(base,'LATEST-TESTS.json'),JSON.stringify({directory:dir,receipt:join(dir,'results.json'),baselinePass:receipt.baselinePass,profilePass:receipt.profilePass},null,2)+'\n');
console.log(JSON.stringify({receipt:join(dir,'results.json'),baselinePass:receipt.baselinePass,profilePass:receipt.profilePass}));
if(suites.some(x=>x.status==='FAIL'))process.exitCode=1;
