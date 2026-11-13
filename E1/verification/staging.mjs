import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../../',import.meta.url));
const mode=process.argv[2];
if(!['--offline','--native'].includes(mode)||process.argv.length!==3)throw Error('Choose --offline or --native; this runner never generates model responses');
const hash=v=>crypto.createHash('sha256').update(v).digest('hex');
const walk=dir=>fs.readdirSync(path.join(root,dir),{withFileTypes:true}).flatMap(e=>e.isDirectory()?(e.name.startsWith('.')?[]:walk(dir+'/'+e.name)):e.isFile()?[dir+'/'+e.name]:[]).sort();
const pins=()=>[...['E1/coordinator','E1/broker','E1/host','E1/executors/coding'].flatMap(walk).filter(f=>/\.(mjs|sql)$/.test(f)),'E1/verification/staging.mjs','E1/verification/offline.mjs'].map(file=>({file,sha256:hash(fs.readFileSync(path.join(root,file)))}));
const source_before=pins(),started_at=new Date().toISOString(),runs=[];
const out=path.join(root,'.private/validation/'+mode.slice(2));fs.mkdirSync(out,{recursive:true});
const env={};for(const k of ['SystemRoot','WINDIR','PATH','TEMP','TMP','LOCALAPPDATA'])if(process.env[k])env[k]=process.env[k];
Object.assign(env,{TZ:'UTC',LANG:'C',NO_COLOR:'1'});
if(mode==='--native')env.AWE_E1_NATIVE_TEST='1';
function run(id,args){
 const start=Date.now(),r=spawnSync(process.execPath,args,{cwd:root,env,encoding:'utf8',timeout:240000,windowsHide:true,maxBuffer:12*1024*1024});
 const stdout=r.stdout??'',stderr=r.stderr??'';fs.writeFileSync(path.join(out,id+'.tap'),stdout);fs.writeFileSync(path.join(out,id+'.stderr'),stderr);
 const summary=Object.fromEntries([...stdout.matchAll(/^# (tests|pass|fail|cancelled|skipped) (\d+)$/gm)].map(m=>[m[1],Number(m[2])]));
 if(id==='baseline'){const baseline=JSON.parse(fs.readFileSync(path.join(root,'.private/baseline-checks/RESULTS.json')));Object.assign(summary,baseline.totals);}
 const row={id,command:['node',...args],exit_status:r.status,error:r.error?.code??null,duration_ms:Date.now()-start,summary,stdout_sha256:hash(stdout),stderr_sha256:hash(stderr)};runs.push(row);console.log(JSON.stringify(row));
}
if(mode==='--offline'){
 run('baseline',['E1/verification/offline.mjs']);
 const files=[...['E1/tests/coordinator','E1/tests/broker','E1/tests/executors','E1/tests/host'].flatMap(walk).filter(f=>f.endsWith('.test.mjs')&&!f.includes('native')), 'E1/qa2/model-seams.test.mjs','E1/qa2/maintenance-oracle.test.mjs'];
 run('e1-offline',['--test','--test-concurrency=1','--test-reporter=tap',...files]);
}else{
 const files=[...walk('E1/tests/coordinator').filter(f=>f.endsWith('.test.mjs')&&f.includes('native')),'E1/qa2/native-seams.test.mjs','E1/qa2/native-processes.test.mjs',...walk('E1/qa2').filter(f=>f.endsWith('.test.mjs')&&/quiescen|host-seam/.test(f))];
 run('e1-native',['--test','--test-concurrency=1','--test-reporter=tap',...new Set(files)]);
}
const source_after=pins(),source_stable=JSON.stringify(source_before)===JSON.stringify(source_after),totals={tests:0,pass:0,fail:0,cancelled:0,skipped:0};
for(const r of runs)for(const key of Object.keys(totals))totals[key]+=r.summary[key]??0;
const ok=source_stable&&runs.every(r=>r.exit_status===0&&!r.error&&r.summary.tests>0&&r.summary.tests===r.summary.pass&&r.summary.fail===0&&r.summary.cancelled===0&&r.summary.skipped===0);
const result={schema:'awe.e1.staging-test-run/1',status:ok?'PASS':'FAIL',mode:mode.slice(2),started_at,finished_at:new Date().toISOString(),node:process.version,platform:process.platform,postgresql:mode==='--native'?'NATIVE_WSL_E1_5433':'NOT_CONNECTED_BY_TEST_RUNNER',new_model_generation_requests:0,external_effects:0,source_stable,source_before,source_after,commands:runs,totals,accepted:false};
fs.writeFileSync(path.join(out,'RESULTS.json'),JSON.stringify(result,null,2)+'\n');
if(ok){fs.mkdirSync(path.join(root,'E1/evidence2'),{recursive:true});fs.writeFileSync(path.join(root,'E1/evidence2/'+mode.slice(2).toUpperCase()+'-TESTS.json'),JSON.stringify(result,null,2)+'\n');}
console.log(JSON.stringify({status:result.status,mode:result.mode,totals,source_stable}));if(!ok)process.exitCode=1;
