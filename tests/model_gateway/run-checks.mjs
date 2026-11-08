import {spawnSync} from 'node:child_process';
import {mkdirSync,writeFileSync,readdirSync,readFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {createHash} from 'node:crypto';
const root=resolve(import.meta.dirname,'../..'),evidence=join(root,'LLM-01/evidence');mkdirSync(evidence,{recursive:true});
if(process.version!=='v24.21.0')throw Error('PINNED_NODE_REQUIRED');
const env={};for(const k of ['SystemRoot','WINDIR','PATH','TEMP','TMP','COMSPEC'])if(process.env[k])env[k]=process.env[k];
const profileOnly=process.argv.includes('--profile-only');
const previous=profileOnly?JSON.parse(readFileSync(join(evidence,'test-results.json'),'utf8')):null;
env.TZ='UTC';const rows=profileOnly?previous.suites.filter(x=>x.suite!=='model_gateway' && x.status!=='NOT_RUN'):[];
const suites=profileOnly?['model_gateway']:['contracts','security','state','memory_artifacts','context','runtime','budget','integration','integration_v2','qa','persistence','model_gateway'];
for(const suite of suites) {
  const files=readdirSync(join(root,'tests',suite)).filter(x=>x.endsWith('.test.mjs') && x!=='postgres.test.mjs').map(x=>'tests/'+suite+'/'+x);
  const args=['--require','./baseline/offline-guard.cjs','--test','--test-reporter=tap','--test-isolation=none','--test-concurrency=1',...files];
  const r=spawnSync(process.execPath,args,{cwd:root,env,encoding:'utf8',windowsHide:true,timeout:60000,maxBuffer:8*1024*1024});
  writeFileSync(join(evidence,suite+'.tap'),r.stdout??'');writeFileSync(join(evidence,suite+'.stderr.txt'),r.stderr??'');
  const count=k=>Number((r.stdout??'').match(new RegExp('^# '+k+' (\\d+)$','m'))?.[1]??0);
  const row={suite,command:[process.execPath,...args],exit:r.status,error:r.error?.code??null,tests:count('tests'),pass:count('pass'),fail:count('fail'),skip:count('skipped'),status:r.status===0?'PASS':'FAIL'};rows.push(row);console.log(JSON.stringify(row));
}
// Metadata probe only: no cluster, service, WSL or installation. Existing INT03 harness hardcodes Linux /tmp identity.
const tools=profileOnly?previous.pgTools:['initdb','pg_ctl','psql','pg_dump','pg_restore'].map(n=>{const r=spawnSync(n,['--version'],{env,encoding:'utf8',windowsHide:true,timeout:5000});return {name:n,available:r.status===0,version:r.status===0?r.stdout.trim():null,error:r.error?.code??null};});
for(const [suite,tests] of [['D09_REAL_PG',39],['INT03_REAL_PG',42],['AUD01_REAL_PG',13]])rows.push({suite,tests,pass:0,fail:0,status:'NOT_RUN',reason:'PostgreSQL tools unavailable on this Windows host; WSL inventory separately denied. No installs or baseline harness edits authorized.'});
const result={version:'LLM01_TEST_RUN_V1',recordedAt:new Date().toISOString(),node:process.version,nodeSha256:createHash('sha256').update(readFileSync(process.execPath)).digest('hex'),
  baselineRecordedAt:previous?.baselineRecordedAt??previous?.recordedAt??new Date().toISOString(),profileRecordedAt:new Date().toISOString(),
  base:'b0b27f2f405fa520dad4cf0196a791480b9e5b61',physicalDecision:'DENY',liveBench:'LIVE_BENCH_NOT_RUN',pgTools:tools,suites:rows,
  baselinePass:rows.filter(x=>x.suite!=='model_gateway').reduce((n,x)=>n+x.pass,0),baselineNotRun:94,profilePass:rows.find(x=>x.suite==='model_gateway').pass};
writeFileSync(join(evidence,'test-results.json'),JSON.stringify(result,null,2)+'\n');
if(rows.some(x=>x.status==='FAIL'))process.exitCode=1;
