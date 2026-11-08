import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
const root=fs.realpathSync(process.cwd()),qa=path.resolve(root,'E1/qa3'),hash=v=>crypto.createHash('sha256').update(v).digest('hex');
const tests=['pricing-adversarial','funding-adversarial','broker-adversarial','host-boundary'].map(name=>'E1/qa3/'+name+'.test.mjs');
const seeds=[...tests,'E1/qa3/offline-guard.cjs','E1/qa3/fixtures.mjs',...['schemas','registry','head','model','canary','benchmark','index'].map(name=>'E1/broker/'+name+'.mjs')];
const pending=seeds.map(file=>path.resolve(root,file)),sources=new Map();
while(pending.length){
 const abs=pending.pop(),relative=path.relative(root,abs).split(path.sep).join('/');if(sources.has(relative))continue;
 assert.ok(abs.startsWith(root+path.sep)&&!relative.split('/').some(part=>['.private','.git','.local','.reference','node_modules'].includes(part))&&/\.(?:mjs|cjs)$/.test(relative),'QA3_PORTABLE_SOURCE_DENIED');
 assert.equal(fs.lstatSync(abs).isSymbolicLink(),false);const bytes=fs.readFileSync(abs);sources.set(relative,bytes);
 const imports=[...bytes.toString('utf8').matchAll(/(?:\bfrom\s*|\bimport\s*|\bimport\s*\(\s*)['"](\.{1,2}\/[^'"]+)['"]/g)];
 for(const match of imports)pending.push(path.resolve(path.dirname(abs),match[1]));
}
const scratchParent=path.resolve(qa,'.portable');if(!fs.existsSync(scratchParent))fs.mkdirSync(scratchParent);
assert.equal(fs.lstatSync(scratchParent).isSymbolicLink(),false);assert.equal(fs.realpathSync(scratchParent).toLowerCase(),scratchParent.toLowerCase());
const scratch=path.join(scratchParent,'public-'+crypto.randomBytes(8).toString('hex'));fs.mkdirSync(scratch);assert.ok(fs.realpathSync(scratch).startsWith(scratchParent+path.sep));
for(const [relative,bytes] of sources){const dest=path.resolve(scratch,relative);assert.ok(dest.startsWith(scratch+path.sep));fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,bytes,{flag:'wx'});}
assert.equal(fs.existsSync(path.join(scratch,'.private')),false);assert.equal(fs.existsSync(path.join(scratch,'.git')),false);
const env={TZ:'UTC',LANG:'C',NO_COLOR:'1'};for(const key of ['SystemRoot','WINDIR','PATH','TEMP','TMP'])if(process.env[key])env[key]=process.env[key];
const args=['--require','./E1/qa3/offline-guard.cjs','--test','--test-concurrency=1','--test-reporter=tap',...tests],started_at=new Date().toISOString();
const result=spawnSync(process.execPath,args,{cwd:scratch,env,encoding:'utf8',windowsHide:true,timeout:60000,maxBuffer:4*1024*1024}),output=(result.stdout??'')+(result.stderr??'');
const totals=Object.fromEntries([...output.matchAll(/^# (tests|pass|fail|skipped|cancelled) (\d+)$/gm)].map(x=>[x[1],Number(x[2])]));
const source_pins=[...sources].map(([file,bytes])=>({path:file,sha256:hash(bytes)})).sort((a,b)=>a.path.localeCompare(b.path));
const changed=source_pins.filter(x=>hash(fs.readFileSync(path.join(scratch,x.path)))!==x.sha256);
const record={schema:'awe.qa3.public-portability/1',status:result.status===0&&totals.pass===29&&totals.tests===29&&totals.fail===0&&totals.skipped===0&&changed.length===0?'PASS_PUBLIC_ONLY_EXPORT':'FAIL',started_at,finished_at:new Date().toISOString(),node:process.version,exit_status:result.status,error:result.error?.code??null,totals,source_pins,output_sha256:hash(output),source_files_changed:changed,private_config_before:false,private_config_after:fs.existsSync(path.join(scratch,'.private')),git_directory:false,host_private_config_dependency:false,key_access:false,provider_calls:0,native_connections:0,command:'node '+args.join(' ')};
fs.writeFileSync('E1/qa3/PORTABILITY.tap',output);fs.writeFileSync('E1/qa3/PORTABILITY.json',JSON.stringify(record,null,2)+'\n');console.log(JSON.stringify({...record,source_pins:undefined},null,2));
if(record.status!=='PASS_PUBLIC_ONLY_EXPORT')console.log(output);assert.equal(record.status,'PASS_PUBLIC_ONLY_EXPORT');
