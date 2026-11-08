import fs from 'node:fs';
import path from 'node:path';
import {spawnSync,execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {verifyActiveSources} from './review.mjs';
const root=path.resolve(import.meta.dirname,'../..'),base=path.join(root,'AUTO-01');
const out=path.join(base,'evidence',new Date().toISOString().replaceAll(':','-'));fs.mkdirSync(out,{recursive:true});
const sha=b=>createHash('sha256').update(b).digest('hex');
const env={TZ:'UTC',AUTO01_EVIDENCE_DIR:out};for(const k of ['SystemRoot','WINDIR','PATH','TEMP','TMP','COMSPEC'])if(process.env[k])env[k]=process.env[k];
const files=dir=>fs.readdirSync(path.join(root,dir)).filter(n=>n.endsWith('.test.mjs')&&!['postgres.test.mjs','process.test.mjs','restart-process.test.mjs'].includes(n)).sort().map(n=>dir+'/'+n);
const suites=[{name:'auto01',files:files('AUTO-01/tests'),guard:true}];
for(const name of ['contracts','security','state','integration','runtime','context','budget','memory_artifacts','integration_v2','qa','persistence','tool_registry','hermes_runtime','model_gateway','execution_security','integration_v4'])suites.push({name,files:files('tests/'+name),guard:true,count:['qa','execution_security','integration_v4'].includes(name)});
suites.push({name:'rt01-process-regression',files:['tests/hermes_runtime/process.test.mjs']},{name:'rt01-process-candidate',files:['tests/hermes_runtime/process_candidate/lifecycle.process.test.mjs','tests/hermes_runtime/process_candidate/controller.process.test.mjs']},{name:'int04-process',files:['tests/integration_v4/restart-process.test.mjs']},{name:'integration01',files:files('INTEGRATION-01/tests')});
for(const d of ['SEC-01/evidence','RT-01/process-candidate/evidence'])fs.mkdirSync(path.join(root,d),{recursive:true});
const upstream=JSON.parse(fs.readFileSync(path.join(base,'UPSTREAM-SOURCES.json')));
function upstreamCheck(){return upstream.files.filter(r=>!fs.existsSync(path.join(upstream.source,r.path))||sha(fs.readFileSync(path.join(upstream.source,r.path)))!==r.sha256).map(r=>r.path);}
const before=upstreamCheck(),rows=[],activeBefore=verifyActiveSources();
for(const suite of suites){
 const args=[...(suite.guard?['--require','./baseline/offline-guard.cjs']:[]),...(suite.count?['--import','./tests/execution_security/count-evaluator.mjs']:[]),'--test','--test-isolation=none','--test-concurrency=1','--test-reporter=tap',...suite.files];
 const start=new Date().toISOString(),r=spawnSync(process.execPath,args,{cwd:root,env,encoding:'utf8',timeout:120000,maxBuffer:32*1024*1024,windowsHide:true});
 fs.writeFileSync(path.join(out,suite.name+'.tap'),r.stdout??'');fs.writeFileSync(path.join(out,suite.name+'.stderr.txt'),r.stderr??'');
 const number=k=>Number(new RegExp('^# '+k+' (\\d+)','m').exec(r.stdout??'')?.[1]??0);
 const row={name:suite.name,status:r.status===0&&number('tests')>0&&number('fail')===0&&number('skipped')===0&&number('cancelled')===0?'PASS':'FAIL',exit:r.status,error:r.error?.code??null,tests:number('tests'),pass:number('pass'),fail:number('fail'),skipped:number('skipped'),cancelled:number('cancelled'),startedAt:start,finishedAt:new Date().toISOString(),command:['node',...args]};
 rows.push(row);fs.writeFileSync(path.join(out,'partial-results.json'),JSON.stringify(rows,null,2));console.log(JSON.stringify({name:row.name,status:row.status,pass:row.pass,fail:row.fail}));
}
const activeAfter=verifyActiveSources();if(activeBefore.sha256!==activeAfter.sha256)throw Error('ACTIVE_MANIFEST_CHANGED');
const result={format:'AUTO01_TEST_RESULTS_V1',status:rows.every(r=>r.status==='PASS')?'PASS':'FAIL',activeSources:activeAfter,node:process.version,nodeSha256:sha(fs.readFileSync(process.execPath)),gitBase:execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8',windowsHide:true}).trim(),branch:execFileSync('git',['branch','--show-current'],{cwd:root,encoding:'utf8',windowsHide:true}).trim(),upstreamManifestSha256:sha(fs.readFileSync(path.join(base,'UPSTREAM-SOURCES.json'))),rows,totalPass:rows.reduce((n,r)=>n+r.pass,0),totalFail:rows.reduce((n,r)=>n+r.fail,0),upstreamDriftBefore:before,upstreamDriftAfter:upstreamCheck(),physicalDecision:'DENY',realAutonomyVerified:false,notRun:['LIVE LLM','REAL Hermes','121 genuine PostgreSQL tests / working databases','Physical external actions','Browser AUTO01 integration','Independent semantic quality acceptance','Native recovery/resume'],commitMergePushDeploy:'NOT_PERFORMED'};
fs.writeFileSync(path.join(out,'results.json'),JSON.stringify(result,null,2)+'\n');fs.writeFileSync(path.join(base,'LATEST-TESTS.json'),JSON.stringify({directory:path.relative(root,out).replaceAll('\\','/'),status:result.status,totalPass:result.totalPass,totalFail:result.totalFail},null,2)+'\n');
console.log(JSON.stringify({out,status:result.status,totalPass:result.totalPass,totalFail:result.totalFail,upstreamDrift:result.upstreamDriftAfter}));if(result.status!=='PASS')process.exitCode=1;
