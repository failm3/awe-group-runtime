import fs from 'node:fs';import path from 'node:path';import {fileURLToPath} from 'node:url';import {spawnSync} from 'node:child_process';import crypto from 'node:crypto';
const root=fileURLToPath(new URL('../../',import.meta.url));
const out=path.join(root,'.private/baseline-checks');fs.mkdirSync(out,{recursive:true});
const list=dir=>fs.readdirSync(path.join(root,dir),{withFileTypes:true}).flatMap(e=>e.isDirectory()?list(dir+'/'+e.name):e.name.endsWith('.test.mjs')?[dir+'/'+e.name]:[]).sort();
const env={TZ:'UTC',LANG:'C',NO_COLOR:'1'};for(const k of ['SystemRoot','WINDIR','PATH','TEMP','TMP','LOCALAPPDATA'])if(process.env[k])env[k]=process.env[k];
const commands=[];const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
function run(id,files,guard){const args=['--require',guard,'--test','--test-reporter=tap','--test-isolation=none','--test-concurrency=1',...files],t=Date.now(),r=spawnSync(process.execPath,args,{cwd:root,env,encoding:'utf8',timeout:90000,maxBuffer:12*1024*1024,windowsHide:true});const stdout=r.stdout??'',stderr=r.stderr??'';fs.writeFileSync(path.join(out,id+'.tap'),stdout);fs.writeFileSync(path.join(out,id+'.stderr.txt'),stderr);const summary=Object.fromEntries([...stdout.matchAll(/^# (tests|pass|fail|skipped|cancelled) (\d+)$/gm)].map(m=>[m[1],Number(m[2])]));const record={id,command:['node',...args],exit:r.status,error:r.error?.code??null,duration_ms:Date.now()-t,summary,stdout_sha256:sha(stdout),stderr_sha256:sha(stderr)};commands.push(record);console.log(JSON.stringify(record));}
run('legacy-contracts',['tests/contracts/contracts.test.mjs'],'./baseline/offline-guard.cjs');
run('auto-compatibility',list('AUTO-01/tests'),'./baseline/offline-guard.cjs');
run('a1-contracts',list('E1/tests/contracts'),'./baseline/offline-guard.cjs');
run('c1-fixtures',list('E1/tests/infra'),'./E1/qa/network-guard.cjs');
run('a1-integration',list('E1/tests/integration'),'./baseline/offline-guard.cjs');
run('qa1',list('E1/qa'),'./E1/qa/network-guard.cjs');
const totals={tests:0,pass:0,fail:0,skipped:0,cancelled:0};for(const c of commands)for(const k of Object.keys(totals))totals[k]+=c.summary[k]??0;const ok=commands.every(c=>c.exit===0&&!c.error)&&totals.tests>0&&totals.fail===0&&totals.cancelled===0&&totals.skipped===0;
const report={schema:'awe.clean-export-baseline-test/1',status:ok?'PASS':'FAIL',commands,totals,native_postgresql_tests:false,live_model_calls:0,scope:'Reviewed clean export compatibility only; not E1 Pilot acceptance'};fs.writeFileSync(path.join(out,'RESULTS.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({status:report.status,totals}));if(!ok)process.exitCode=1;
