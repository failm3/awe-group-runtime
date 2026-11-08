import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
const hash=v=>crypto.createHash('sha256').update(v).digest('hex');
function pins(){const result=[];function walk(root){if(!fs.existsSync(root))return;for(const item of fs.readdirSync(root,{withFileTypes:true})){if(item.name==='.portable')continue;const file=path.join(root,item.name);if(item.isSymbolicLink())throw new Error('QA3_SOURCE_SYMLINK_DENIED');if(item.isDirectory())walk(file);else if(/\.(?:mjs|cjs|sql|py)$/.test(file))result.push({path:file.split(path.sep).join('/'),sha256:hash(fs.readFileSync(file))});}}for(const root of ['E1/cloud','E1/coordinator','E1/broker','E1/mission','E1/contracts','E1/host/router-cheap','E1/qa3'])walk(root);return result.sort((a,b)=>a.path.localeCompare(b.path));}
const args=['--require','./E1/qa3/native-guard.cjs','--test','--test-concurrency=1','--test-reporter=tap','E1/qa3/native-integration.test.mjs'];
const env={TZ:'UTC',LANG:'C',NO_COLOR:'1'};for(const key of ['SystemRoot','WINDIR','PATH','TEMP','TMP'])if(process.env[key])env[key]=process.env[key];
const before=pins(),started_at=new Date().toISOString(),result=spawnSync(process.execPath,args,{env,encoding:'utf8',windowsHide:true,timeout:120000,maxBuffer:8*1024*1024}),after=pins(),output=(result.stdout??'')+(result.stderr??'');
const totals=Object.fromEntries([...output.matchAll(/^# (tests|pass|fail|skipped|cancelled) (\d+)$/gm)].map(x=>[x[1],Number(x[2])]));
const record={schema:'awe.qa3.native-command/1',command:'node '+args.join(' '),started_at,finished_at:new Date().toISOString(),node:process.version,exit_status:result.status,error:result.error?.code??null,signal:result.signal,totals,implementation_stable_during_run:JSON.stringify(before)===JSON.stringify(after),source_before:before,source_after:after,output_sha256:hash(output),real_key_access:false,actual_provider_calls:0,network_calls:0,host_resource:'EXISTING_E1_LOCAL_TEST_ONLY_POSTGRESQL_5433',project_namespace:'prj_qa3_*',funding:'EXPLICIT_SYNTHETIC_UNIQUE_KEYS_ONLY',ddl:false,cluster_lifecycle:false};
fs.writeFileSync('E1/qa3/NATIVE.tap',output);fs.writeFileSync('E1/qa3/NATIVE.json',JSON.stringify(record,null,2)+'\n');console.log(JSON.stringify({...record,source_before:undefined,source_after:undefined},null,2));console.log(output);
process.exitCode=result.status===0&&record.implementation_stable_during_run&&totals.tests===9&&totals.pass===9&&totals.fail===0&&totals.skipped===0?0:1;
