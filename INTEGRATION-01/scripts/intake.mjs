import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
const root=path.resolve(import.meta.dirname,'../..'),out=path.join(root,'INTEGRATION-01');
const sha=b=>createHash('sha256').update(b).digest('hex');
const specs=[
 {id:'INT04',root:'C:/Users/1/AWE-GROUP-INT04',paths:['awe/integration_v4','awe/execution_security','awe/tool_registry','awe/qa/evaluator.mjs','tests/integration_v4','tests/execution_security','tests/tool_registry','INT-04/README.md','INT-04/ARCHITECTURE.md','INT-04/REPORT.md','INT-04/COMPATIBILITY.md','INT-04/BLOCKERS.md','INT-04/TEST-RESULTS.json','INT-04/BASE-03-DIFF.patch','INT-04/FINAL-SOURCE-CHECK.json']},
 {id:'RT01',root:'C:/Users/1/AWE-GROUP-RT01',paths:['awe/hermes_runtime','tests/hermes_runtime','RT-01/README.md','RT-01/CONTRACTS.md','RT-01/REPORT.md','RT-01/process-candidate/README.md','RT-01/process-candidate/CONTRACT.md','RT-01/process-candidate/REPORT.md','RT-01/process-candidate/CHANGES.json','RT-01/process-candidate/delta.patch','RT-01/process-candidate/evidence/results.json']},
 {id:'LLM01',root:'C:/Users/1/AWE-GROUP-LLM01',paths:['awe/model_gateway','tests/model_gateway','LLM-01/README.md','LLM-01/CONTRACTS.md','LLM-01/TEST-REPORT.md','LLM-01/model-broker-2026-11-06/README.md','LLM-01/model-broker-2026-11-06/TEST-REPORT.md','LLM-01/model-broker-2026-11-06/REAL-PROVIDER-CONTRACT.md','LLM-01/model-broker-2026-11-06/CHANGES.patch','LLM-01/model-broker-2026-11-06/LATEST-TESTS.json','LLM-01/model-broker-2026-11-06/EXECUTION-EVIDENCE.json']},
 {id:'UI',root:'C:/Users/1/.codex/worktrees/8cc9/AWE-GROUP-Implementation',paths:['UI-MVP']}
];
function files(p){const s=fs.lstatSync(p);if(s.isSymbolicLink())throw Error('SOURCE_LINK_DENIED');if(!s.isDirectory())return [p];return fs.readdirSync(p,{withFileTypes:true}).filter(e=>!['sandbox','node_modules','.git'].includes(e.name)).flatMap(e=>files(path.join(p,e.name)));}
function git(source,args){return execFileSync('git',['-C',source,'--work-tree='+source,...args],{env:{...process.env,GIT_OPTIONAL_LOCKS:'0'},encoding:'utf8',windowsHide:true});}
fs.mkdirSync(path.join(out,'evidence','intake'),{recursive:true});
if(fs.existsSync(path.join(out,'SOURCE-LOCK.json')))throw Error('SNAPSHOT_ALREADY_EXISTS');
const sources=[],overlays=[],conflicts=[];
for(const s of specs){
 const head=git(s.root,['rev-parse','HEAD']).trim(),branch=git(s.root,['branch','--show-current']).trim();
 const status=git(s.root,['status','--porcelain=v1','--untracked-files=normal']),diff=git(s.root,['diff','--binary','HEAD']);
 fs.writeFileSync(path.join(out,'evidence','intake',s.id+'-status.txt'),status);fs.writeFileSync(path.join(out,'evidence','intake',s.id+'-tracked.patch'),diff);
 const rows=[];
 for(const file of [...new Set(s.paths.flatMap(p=>files(path.join(s.root,p))))].sort()){
  const rel=path.relative(s.root,file).replaceAll('\\','/'),bytes=fs.readFileSync(file),hash=sha(bytes);
  const destination=path.join(out,'snapshots',s.id,rel);fs.mkdirSync(path.dirname(destination),{recursive:true});fs.writeFileSync(destination,bytes,{flag:'wx'});
  if(sha(fs.readFileSync(file))!==hash)throw Error('SOURCE_CHANGED_DURING_READ '+file);
  const row={path:rel,bytes:bytes.length,sha256:hash};rows.push(row);
  const code=rel.startsWith('awe/')||rel.startsWith('tests/');
  if(code){const target=path.join(root,rel);if(fs.existsSync(target)&&sha(fs.readFileSync(target))!==hash)conflicts.push({path:rel,selected:s.id,before_sha256:sha(fs.readFileSync(target)),after_sha256:hash});fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,bytes);overlays.push({source:s.id,...row});}
 }
 sources.push({...s,head,branch,status_sha256:sha(Buffer.from(status)),tracked_diff_sha256:sha(Buffer.from(diff)),files:rows});
}
const extra=path.join(specs[0].root,'awe/integration_v3/postgres.mjs');
const lock={version:'INTEGRATION01_SOURCE_LOCK_V1',createdAt:new Date().toISOString(),node:process.version,baseline:'b0b27f2f405fa520dad4cf0196a791480b9e5b61',sources,overlays,conflicts,excluded:[{path:extra,sha256:sha(fs.readFileSync(extra)),reason:'SEC02/native PostgreSQL changes inspected in diff, excluded from E0 runtime; no SQL applied'}]};
for(const s of sources)for(const f of s.files)if(sha(fs.readFileSync(path.join(s.root,f.path)))!==f.sha256)throw Error('SOURCE_DRIFT_BEFORE_FREEZE '+s.id+'/'+f.path);
fs.writeFileSync(path.join(out,'SOURCE-LOCK.json'),JSON.stringify(lock,null,2)+'\n',{flag:'wx'});
const ui=path.join(out,'ui');fs.cpSync(path.join(out,'snapshots/UI/UI-MVP'),ui,{recursive:true,filter:p=>!p.includes(path.sep+'evidence')&&!p.includes(path.sep+'reference')});
console.log(JSON.stringify({status:'PASS',sources:sources.map(s=>({id:s.id,branch:s.branch,head:s.head,files:s.files.length})),overlays:overlays.length,conflicts:conflicts.map(c=>({path:c.path,selected:c.selected})),excluded:lock.excluded},null,2));
