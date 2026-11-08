import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {bytesDigest} from '../awe/executable_tools/protocol.mjs';
import {loadPins,verifyPins} from '../awe/executable_tools/pins.mjs';
const root=fileURLToPath(new URL('../',import.meta.url)),out=path.join(root,'TOOLS-02/evidence/current');fs.mkdirSync(out,{recursive:true});
const lock=loadPins();for(const binary of ['node','python','git'])verifyPins(lock,binary);
const env={TZ:'UTC',LANG:'C',NO_COLOR:'1'};for(const key of ['SystemRoot','WINDIR','PATH','TEMP','TMP'])if(process.env[key])env[key]=process.env[key];
function tracked(){const r=spawnSync('git',['ls-files','-z'],{cwd:root,encoding:'utf8',windowsHide:true});if(r.status!==0)throw Error('GIT_INVENTORY');return r.stdout.split('\0').filter(Boolean).map(p=>({path:p,digest:bytesDigest(fs.readFileSync(path.join(root,p)))}));}
const before=tracked(),commands=[];
function command(id,args){
 const r=spawnSync(process.execPath,args,{cwd:root,env,encoding:'utf8',windowsHide:true,timeout:90000,maxBuffer:32*1024*1024});
 fs.writeFileSync(path.join(out,id+'.stdout'),r.stdout??'');fs.writeFileSync(path.join(out,id+'.stderr'),r.stderr??'');
 const counts=Object.fromEntries([...(r.stdout??'').matchAll(/^# (tests|pass|fail|cancelled|skipped|todo) (\d+)$/gm)].map(m=>[m[1],+m[2]]));
 const record={id,args,exit:r.status,error:r.error?.code??null,...counts,stdout_digest:bytesDigest(Buffer.from(r.stdout??'')),stderr_digest:bytesDigest(Buffer.from(r.stderr??''))};commands.push(record);console.log(JSON.stringify(record));
}
const started=new Date().toISOString();
for(const suite of ['contracts','security','state','integration','runtime','budget','context','memory_artifacts','integration_v2','qa','persistence']){
 const files=fs.readdirSync(path.join(root,'tests',suite)).filter(x=>x.endsWith('.test.mjs')&&x!=='postgres.test.mjs').sort().map(x=>'tests/'+suite+'/'+x);
 command('baseline-'+suite,['--require','./baseline/offline-guard.cjs','--test','--test-isolation=none','--test-concurrency=1','--test-reporter=tap',...files]);
}
command('tr01-offline',['--require','./baseline/offline-guard.cjs','--test','--test-isolation=none','--test-concurrency=1','--test-reporter=tap','tests/tool_registry/registry.test.mjs','tests/tool_registry/sync.test.mjs']);
const toolTests=fs.readdirSync(path.join(root,'tests/executable_tools')).filter(x=>x.endsWith('.test.mjs')).sort().map(x=>'tests/executable_tools/'+x);
command('tools02',['--require','./tests/integration_v3/egress-guard.cjs','--test','--test-isolation=none','--test-concurrency=1','--test-reporter=tap',...toolTests]);
command('demo',['--require','./tests/integration_v3/egress-guard.cjs','TOOLS-02/demo.mjs']);
if(process.argv.includes('--with-owning-rt01'))command('rt01-conformance',['--require','./tests/integration_v3/egress-guard.cjs','TOOLS-02/rt01-conformance.mjs']);
const sourceStable=JSON.stringify(before)===JSON.stringify(tracked());
const imported=JSON.parse(fs.readFileSync(path.join(root,'TOOLS-02/IMPORTED-FILES.json')));
const importsStable=imported.entries.every(f=>bytesDigest(fs.readFileSync(path.join(root,f.path)))==='sha256:'+f.sha256);
const diff=spawnSync('git',['diff','--exit-code','--check'],{cwd:root,encoding:'utf8',windowsHide:true});
const unchanged=spawnSync('git',['diff','--exit-code','--name-only'],{cwd:root,encoding:'utf8',windowsHide:true});
const temp=fs.readdirSync(path.join(root,'TOOLS-02/sandbox'));
const receipt={contract:'tools02.evidence/1',status:commands.every(r=>r.exit===0&&(r.fail??0)===0&&(r.skipped??0)===0)&&sourceStable&&importsStable&&diff.status===0&&unchanged.status===0&&temp.length===0?'PASS':'FAIL',started,finished:new Date().toISOString(),environment:{node:process.version,node_digest:bytesDigest(fs.readFileSync(process.execPath)),platform:process.platform,arch:process.arch,python:'3.13.2',git:'2.49.0.windows.1',runtime_lock_digest:bytesDigest(fs.readFileSync(path.join(root,'TOOLS-02/runtime-lock.json')))},commands,tracked_files:before.length,tracked_bytes_stable:sourceStable,tracked_diff_empty:unchanged.status===0,imported_bytes_stable:importsStable,diff_check:diff.status===0,sandbox_empty:temp.length===0,not_run:['PostgreSQL D09/INT03/TR01','Real SEC/D04/D09 admission composition','Full AUTO/INT04 -> RT01 -> TOOLS02 -> D07/D08 e2e','Native browser/API/network','REAL Hermes','Hostile-code OS sandbox and full Python dependency attestation','Independent human/organization acceptance','Commit/merge/push/deploy'],production_ready:false};
fs.writeFileSync(path.join(out,'receipt.json'),JSON.stringify(receipt,null,2)+'\n');fs.writeFileSync(path.join(out,'tracked-bytes.json'),JSON.stringify(before,null,2)+'\n');
fs.writeFileSync(path.join(out,'EVIDENCE.sha256'),fs.readdirSync(out).filter(x=>x!=='EVIDENCE.sha256').sort().map(n=>bytesDigest(fs.readFileSync(path.join(out,n))).slice(7)+'  '+n).join('\n')+'\n');
console.log(JSON.stringify({status:receipt.status,baseline:commands.filter(c=>c.id.startsWith('baseline-')).reduce((n,c)=>n+(c.pass??0),0),tr01:commands.find(c=>c.id==='tr01-offline')?.pass,tools02:commands.find(c=>c.id==='tools02')?.pass,sandbox_empty:receipt.sandbox_empty}));if(receipt.status!=='PASS')process.exitCode=1;
