import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';

const hash=value=>crypto.createHash('sha256').update(value).digest('hex');
const files=process.argv.slice(2);
assert.ok(files.length>0 && files.every(file=>/^E1\/qa3\/[a-z0-9-]+\.test\.mjs$/.test(file)), 'QA3_TEST_PATH_DENIED');
const roots=['E1/cloud','E1/coordinator','E1/broker','E1/contracts','E1/mission','E1/host/router-cheap','E1/qa3'];
function pins(){
  const result=[];
  function walk(root){if(!fs.existsSync(root))return;for(const item of fs.readdirSync(root,{withFileTypes:true})){if(item.name==='.portable')continue;const file=path.join(root,item.name);assert.equal(item.isSymbolicLink(),false,'QA3_SOURCE_SYMLINK_DENIED');if(item.isDirectory())walk(file);else if(/\.(?:mjs|cjs|sql|py)$/.test(item.name))result.push({path:file.split(path.sep).join('/'),sha256:hash(fs.readFileSync(file))});}}
  roots.forEach(walk);return result.sort((a,b)=>a.path.localeCompare(b.path));
}
const before=pins(),started_at=new Date().toISOString();
const args=['--require','./E1/qa3/offline-guard.cjs','--test','--test-concurrency=1','--test-reporter=tap',...files];
const env={TZ:'UTC',LANG:'C',NO_COLOR:'1'};
for(const key of ['SystemRoot','WINDIR','PATH','TEMP','TMP'])if(process.env[key])env[key]=process.env[key];
const result=spawnSync(process.execPath,args,{env,encoding:'utf8',windowsHide:true,timeout:60000,maxBuffer:4*1024*1024});
const output=(result.stdout??'')+(result.stderr??''),after=pins();
const totals=Object.fromEntries([...output.matchAll(/^# (tests|pass|fail|skipped|cancelled) (\d+)$/gm)].map(x=>[x[1],Number(x[2])]));
const record={schema:'awe.qa3.offline-command/1',command:'node '+args.join(' '),started_at,finished_at:new Date().toISOString(),node:process.version,exit_status:result.status,error:result.error?.code??null,signal:result.signal,totals,implementation_stable_during_run:JSON.stringify(before)===JSON.stringify(after),source_before:before,source_after:after,output_sha256:hash(output),host_private_config_read:false,key_access:false,provider_calls:0,native_connections:0,external_effects:0};
fs.writeFileSync('E1/qa3/OFFLINE.tap',output);
fs.writeFileSync('E1/qa3/OFFLINE.json',JSON.stringify(record,null,2)+'\n');
console.log(JSON.stringify({...record,source_before:undefined,source_after:undefined},null,2));
console.log(output);
process.exitCode=result.status===0&&record.implementation_stable_during_run&&totals.fail===0&&totals.skipped===0?0:1;
