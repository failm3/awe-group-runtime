import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
const root=path.resolve(import.meta.dirname,'../..'),base=path.join(root,'AUTO-01');
export const sha=b=>createHash('sha256').update(b).digest('hex');
const skip=new Set(['upstream','evidence','sandbox','delivery','node_modules','.git','snapshots']);
function walk(dir){return fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name)).flatMap(e=>{if(skip.has(e.name))return [];if(e.isSymbolicLink())throw Error('SOURCE_LINK_DENIED');const p=path.join(dir,e.name);return e.isDirectory()?walk(p):[p];});}
function activeFiles(){return [...new Set(['awe','contracts','tests','INTEGRATION-01','AUTO-01'].flatMap(d=>walk(path.join(root,d))).filter(p=>/\.(?:mjs|cjs|js|html|css|json)$/.test(p)&&!/(?:SOURCES|TESTS|RESULTS|LOCK|CHECK|BROWSER|PACKAGE|COMPOSITION|EXCLUDED|REQUIREMENTS|CHANGES|LATEST)/i.test(path.basename(p)))),'baseline/offline-guard.cjs'].map(p=>path.isAbsolute(p)?p:path.join(root,p)).sort();}
export function verifyActiveSources(){
 const file=path.join(base,'ACTIVE-SOURCES.json'),m=JSON.parse(fs.readFileSync(file));
 const drift=m.files.filter(f=>!fs.existsSync(path.join(root,f.path))||sha(fs.readFileSync(path.join(root,f.path)))!==f.sha256).map(f=>f.path);
 const known=new Set(m.files.map(f=>f.path));for(const p of activeFiles())if(!known.has(path.relative(root,p).replaceAll('\\','/')))drift.push('ADDED '+p);
 if(drift.length)throw Error('AUTO01_ACTIVE_SOURCE_DRIFT '+drift.join(','));return {sha256:sha(fs.readFileSync(file)),files:m.files.length};
}
export function buildReview(){
 const upstream=JSON.parse(fs.readFileSync(path.join(base,'UPSTREAM-SOURCES.json'))),changes=[],chunks=[];
 for(const f of upstream.files){
  const original=path.join(base,'upstream',f.path),current=path.join(root,f.path);
  if(sha(fs.readFileSync(original))!==f.sha256)throw Error('PRISTINE_SNAPSHOT_CORRUPT '+f.path);
  const bytes=fs.readFileSync(current),hash=sha(bytes);if(hash===f.sha256)continue;
  changes.push({path:f.path,before:f.sha256,after:hash,bytes:bytes.length});
  const r=spawnSync('git',['diff','--no-index','--no-ext-diff','--text','--',original,current],{cwd:root,encoding:'utf8',windowsHide:true});
  if(![0,1].includes(r.status))throw Error('DIFF_FAILED '+r.stderr);
  const lines=r.stdout.split('\n'),index=lines.findIndex(l=>l.startsWith('@@'));
  chunks.push('diff --git a/'+f.path+' b/'+f.path+'\n--- a/'+f.path+'\n+++ b/'+f.path+'\n'+lines.slice(index).join('\n'));
 }
 for(const p of walk(base).filter(p=>/\.(?:mjs|json|md)$/.test(p)&&!/(?:ACTIVE-SOURCES|UPSTREAM-SOURCES|LATEST-TESTS|SOURCE-CHANGES)/.test(path.basename(p)))){
  const rel=path.relative(root,p).replaceAll('\\','/'),bytes=fs.readFileSync(p),lines=bytes.toString('utf8').trimEnd().split('\n');
  changes.push({path:rel,before:null,after:sha(bytes),bytes:bytes.length});chunks.push('diff --git a/'+rel+' b/'+rel+'\nnew file mode 100644\n--- /dev/null\n+++ b/'+rel+'\n@@ -0,0 +1,'+lines.length+' @@\n'+lines.map(l=>'+'+l).join('\n')+'\n');
 }
 fs.writeFileSync(path.join(base,'AUTO01-SOURCE.diff'),chunks.join('\n'));
 fs.writeFileSync(path.join(base,'SOURCE-CHANGES.json'),JSON.stringify({base:'actual uncommitted Integration01 bytes, not Git HEAD',upstreamManifestSha256:sha(fs.readFileSync(path.join(base,'UPSTREAM-SOURCES.json'))),changes},null,2)+'\n');
 const files=activeFiles().map(p=>({path:path.relative(root,p).replaceAll('\\','/'),bytes:fs.statSync(p).size,sha256:sha(fs.readFileSync(p))}));
 fs.writeFileSync(path.join(base,'ACTIVE-SOURCES.json'),JSON.stringify({version:'AUTO01_ACTIVE_SOURCES_V1',profile:'MOCK_ONLY',physicalDecision:'DENY',files},null,2)+'\n');
 return {modifiedUpstream:changes.filter(c=>c.before).map(c=>c.path),newFiles:changes.filter(c=>!c.before).length,active:files.length,diffSha256:sha(fs.readFileSync(path.join(base,'AUTO01-SOURCE.diff')))};
}
if(process.argv[1]&&path.resolve(process.argv[1])===path.join(base,'scripts/review.mjs'))console.log(JSON.stringify(process.argv.includes('--verify')?verifyActiveSources():buildReview(),null,2));
