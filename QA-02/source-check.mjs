import {readFileSync,writeFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url)),sha=b=>createHash('sha256').update(b).digest('hex');
const lock=JSON.parse(readFileSync(new URL('./SOURCE-LOCK.json',import.meta.url)));
const files=lock.files.map(r=>{
 const snapshot=readFileSync(join(root,'QA-02/sources',r.id,r.path));let current=null,error=null;
 try{current=sha(readFileSync(join(r.root,r.path)));}catch(e){error=e.code;}
 return {...r,snapshot_match:sha(snapshot)===r.sha256,current_sha256:current,current_match:current===r.sha256,current_error:error};
});
const github=JSON.parse(readFileSync(new URL('./sources/github/metadata.json',import.meta.url))).map(r=>{
 const b=readFileSync(new URL('./sources/github/'+r.snapshot_file,import.meta.url));
 return {...r,bytes:b.length,sha256:sha(b),exact_git_blob:createHash('sha1').update('blob '+b.length+'\0').update(b).digest('hex')===r.blob_sha};
});
const git=(args)=>execFileSync('git',args,{cwd:root,encoding:'utf8',windowsHide:true}).trim();
const baseline=git(['ls-files','-z']).split('\0').filter(Boolean).map(path=>{const bytes=readFileSync(join(root,path));return {path,bytes:bytes.length,sha256:sha(bytes)};});
const result={version:'qa02-source-check/1',checked_at:new Date().toISOString(),base:git(['rev-parse','HEAD']),branch:git(['branch','--show-current']),tracked_diff:git(['diff','--name-only']),files,github,baseline,
 external_drift:files.filter(r=>!r.current_match).map(r=>({id:r.id,path:r.path,expected:r.sha256,current:r.current_sha256})),
 status:files.every(r=>r.snapshot_match)&&github.every(r=>r.exact_git_blob)?'PASS':'FAIL'};
writeFileSync(new URL('./SOURCE-CHECK.json',import.meta.url),JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify({status:result.status,base:result.base,branch:result.branch,tracked_diff:result.tracked_diff,baseline_files:baseline.length,snapshots:files.length,github:github.length,external_drift:result.external_drift.length}));
if(result.status!=='PASS'||result.base!==lock.base||result.tracked_diff)process.exitCode=1;
