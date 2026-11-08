import {readFileSync,writeFileSync,mkdirSync,mkdtempSync,readdirSync,existsSync,copyFileSync} from 'node:fs';
import {join,resolve,dirname,relative} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const root=resolve(import.meta.dirname,'..'),dir=join(root,'RT-02');
const hash=b=>createHash('sha256').update(b).digest('hex'),read=p=>readFileSync(join(root,p));
const need=(ok,msg)=>{if(!ok)throw Error(msg);};
const cmd=(file,args,ok=[0])=>{const r=spawnSync(file,args,{cwd:root,encoding:'utf8',windowsHide:true,timeout:30000,maxBuffer:4*1024*1024});need(ok.includes(r.status),(r.stderr??'')+(r.stdout??''));return r.stdout;};
const imports=JSON.parse(read('RT-02/import-manifest.json')),ownership=JSON.parse(read('RT-02/evidence/ownership-before.json'));
for(const row of imports.rows){need(hash(readFileSync(join(imports.source,row.path)))===row.sha256,'SOURCE_CHANGED:'+row.path);need(hash(read('RT-02/before/'+row.path))===row.sha256,'SNAPSHOT_CHANGED:'+row.path);}
for(const row of ownership.protectedFiles)need(hash(read(row.path))===row.sha256,'PROTECTED_CHANGED:'+row.path);
for(const row of ownership.rows)need(hash(readFileSync(row.path))===row.sha256,'EXTERNAL_SOURCE_CHANGED:'+row.path);
need(cmd('git',['rev-parse','HEAD']).trim()===imports.base,'BASE_CHANGED');need(cmd('git',['diff','--name-only']).trim()==='','TRACKED_FILES_CHANGED');need(cmd('git',['diff','--cached','--name-only']).trim()==='','STAGING_CHANGED');
const walk=p=>readdirSync(join(root,p),{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(p+'/'+e.name):[p+'/'+e.name]);
const existing=new Map(imports.rows.map(r=>[r.path,r.sha256]));
const owned=[...walk('awe/hermes_runtime'),...walk('tests/hermes_runtime'),...readdirSync(dir).filter(n=>/\.(mjs|py|md|json|ps1)$/.test(n)&&!['CHANGES.json','MANIFEST.json'].includes(n)).map(n=>'RT-02/'+n)].sort();
const changes=owned.map(path=>({path,before_sha256:existing.get(path)??null,after_sha256:hash(read(path))})).filter(r=>r.before_sha256!==r.after_sha256);
writeFileSync(join(dir,'CHANGES.json'),JSON.stringify({base_head:imports.base,source:imports.source,changes},null,2)+'\n');
const lock=JSON.parse(read('RT-02/runtime-lock.json'));cmd(lock.executables.python.path,['-I','-S','-B','RT-02/make-diff.py']);
mkdirSync(join(dir,'sandbox'),{recursive:true});const replay=mkdtempSync(join(dir,'sandbox/diff-replay-'));
for(const row of imports.rows){const target=join(replay,row.path);mkdirSync(dirname(target),{recursive:true});copyFileSync(join(dir,'before',row.path),target);}
const target=relative(root,replay).replaceAll('\\','/');
cmd('git',['apply','--check','--ignore-space-change','--directory='+target,'RT-02/delta.patch']);
cmd('git',['apply','--ignore-space-change','--directory='+target,'RT-02/delta.patch']);
for(const row of changes)need(read(row.path).toString().replaceAll('\r\n','\n')===readFileSync(join(replay,row.path),'utf8').replaceAll('\r\n','\n'),'DIFF_REPLAY_CHANGED:'+row.path);
for(const path of owned.filter(p=>/\.(mjs|cjs)$/.test(p)))cmd(process.execPath,['--check',path]);
for(const path of owned.filter(p=>p.endsWith('.py')))cmd(lock.executables.python.path,['-I','-S','-B','-c','import ast,pathlib;ast.parse(pathlib.Path(__import__("sys").argv[1]).read_text(encoding="utf-8"))',path]);
for(const [name,pin]of Object.entries(lock.executables))need('sha256:'+hash(readFileSync(pin.path))===pin.hash,'EXECUTABLE_PIN:'+name);
for(const [path,pin]of Object.entries(lock.sources))need('sha256:'+hash(read(path))===pin,'SOURCE_PIN:'+path);
const results=JSON.parse(read('RT-02/evidence/results.json'));
for(const [i,row]of results.rows.entries()){
 const file='RT-02/evidence/results-'+row.name+'.json';if(!existsSync(join(root,file)))continue;
 const latest=JSON.parse(read(file)).rows.find(r=>r.name===row.name);if(latest&&latest.started>row.started)results.rows[i]=latest;
}
need(results.rows.length===4&&results.rows.every(r=>r.status==='PASS'&&r.fail===0&&r.cancelled===0&&r.skipped===0),'TESTS_NOT_PASS');
writeFileSync(join(dir,'evidence/results.json'),JSON.stringify(results,null,2)+'\n');
const verification={checked_at:new Date().toISOString(),base:imports.base,source_files_unchanged:imports.rows.length,protected_files_unchanged:ownership.protectedFiles.length,external_sources_unchanged:ownership.rows.length,tracked_changes:0,staged_changes:0,changed_files:changes.length,patch_check:'PASS',patch_replay:'PASS',patch_sha256:hash(read('RT-02/delta.patch')),pass:results.rows.reduce((s,r)=>s+r.pass,0),fail:0,real_hermes:'REAL_HERMES_NOT_RUN',physical_decision:'DENY',production_ready:false};
writeFileSync(join(dir,'evidence/verification.json'),JSON.stringify(verification,null,2)+'\n');console.log(JSON.stringify(verification));
