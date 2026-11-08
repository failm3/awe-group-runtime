import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {bytesDigest} from '../awe/executable_tools/protocol.mjs';
const root=fileURLToPath(new URL('../',import.meta.url)),out=path.join(root,'TOOLS-02/delivery');fs.mkdirSync(out,{recursive:true});
const git=args=>{const r=spawnSync('git',args,{cwd:root,encoding:'utf8',windowsHide:true,maxBuffer:64*1024*1024});if(r.error)throw r.error;return r;};
if(git(['diff','--exit-code']).status!==0)throw Error('TRACKED_SOURCE_CHANGED');
const imports=JSON.parse(fs.readFileSync(path.join(root,'TOOLS-02/IMPORTED-FILES.json'))),imported=new Set(imports.entries.map(e=>e.path));
for(const f of imports.entries)if(bytesDigest(fs.readFileSync(path.join(root,f.path)))!=='sha256:'+f.sha256)throw Error('IMPORTED_DRIFT');
const list=git(['ls-files','--others','--exclude-standard','-z']);if(list.status!==0)throw Error('ADDITIONS_LIST');
const paths=list.stdout.split('\0').filter(p=>p&&!p.startsWith('TOOLS-02/delivery/')&&!p.startsWith('TOOLS-02/sandbox/')&&p!=='TOOLS-02/preliminary.tap').sort();
for(const p of paths)if(!['TOOLS-02/','awe/executable_tools/','tests/executable_tools/'].some(prefix=>p.startsWith(prefix))&&!imported.has(p))throw Error('OUT_OF_SCOPE '+p);
const files=paths.map(p=>{const b=fs.readFileSync(path.join(root,p));return {path:p,bytes:b.length,digest:bytesDigest(b),group:imported.has(p)?'TR01_INPUT':'TOOLS02_ADDITION'};});
let full='',candidate='';
// Every payload entry is an added UTF8 text file. Construct addition hunks from
// raw bytes, bypassing Git clean/eol filters so historical CRLF evidence survives.
for(const p of paths){
 const bytes=fs.readFileSync(path.join(root,p)),text=bytes.toString('utf8');if(!Buffer.from(text).equals(bytes)||bytes.includes(0))throw Error('NON_UTF8_PAYLOAD '+p);
 const blob=createHash('sha1').update(Buffer.from('blob '+bytes.length+'\0')).update(bytes).digest('hex');
 let patch='diff --git '+JSON.stringify('a/'+p)+' '+JSON.stringify('b/'+p)+'\nnew file mode 100644\nindex 0000000..'+blob.slice(0,7)+'\n';
 if(bytes.length){const lines=text.split('\n'),ended=text.endsWith('\n');if(ended)lines.pop();patch+='--- /dev/null\n+++ '+JSON.stringify('b/'+p)+'\n@@ -0,0 +1,'+lines.length+' @@\n'+lines.map(line=>'+'+line+'\n').join('');if(!ended)patch+='\\ No newline at end of file\n';}
 full+=patch;if(!imported.has(p))candidate+=patch;
}
fs.writeFileSync(path.join(out,'BASE03-to-TOOLS02.patch'),full);fs.writeFileSync(path.join(out,'TR01-to-TOOLS02.patch'),candidate);
fs.writeFileSync(path.join(out,'FILES.json'),JSON.stringify({base:imports.base,inputs:imports.entries.length,files,scope:'All untracked payload bytes except delivery exports, empty sandbox and preliminary scratch log'},null,2)+'\n');
const sandbox=path.join(root,'TOOLS-02/sandbox');fs.mkdirSync(sandbox,{recursive:true});const replay=fs.mkdtempSync(path.join(sandbox,'tools02-diff-')),prefix=path.relative(root,replay).replaceAll('\\','/');
try{
 const candidateCheck=git(['-c','core.autocrlf=false','apply','--check','--whitespace=nowarn','--directory='+prefix,'TOOLS-02/delivery/TR01-to-TOOLS02.patch']);if(candidateCheck.status!==0)throw Error('CANDIDATE_PATCH_CHECK '+candidateCheck.stderr);
 for(const mode of ['--check',null]){const args=['-c','core.autocrlf=false','apply','--whitespace=nowarn','--directory='+prefix];if(mode)args.push(mode);args.push('TOOLS-02/delivery/BASE03-to-TOOLS02.patch');const r=git(args);if(r.status!==0)throw Error('PATCH_REPLAY '+r.stderr);}
 for(const f of files)if(bytesDigest(fs.readFileSync(path.join(replay,f.path)))!==f.digest)throw Error('REPLAY_BYTE_DRIFT '+f.path);
 const summary={status:'PASS',base:imports.base,tracked_changes:0,tr01_input_files:files.filter(f=>f.group==='TR01_INPUT').length,tools02_new_files:files.filter(f=>f.group==='TOOLS02_ADDITION').length,payload_bytes:files.reduce((n,f)=>n+f.bytes,0),patch_apply_check:'PASS_BOTH_PATCHES',patch_replay_byte_check:'PASS',patches:['BASE03-to-TOOLS02.patch','TR01-to-TOOLS02.patch'].map(name=>({name,digest:bytesDigest(fs.readFileSync(path.join(out,name)))}))};
 fs.writeFileSync(path.join(out,'DIFF-SUMMARY.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary));
}finally{
 const target=path.resolve(replay);if(path.dirname(target)!==path.resolve(sandbox)||!path.basename(target).startsWith('tools02-diff-'))throw Error('CLEANUP_PATH');fs.rmSync(target,{recursive:true});
}
fs.writeFileSync(path.join(out,'ARTIFACTS.sha256'),['BASE03-to-TOOLS02.patch','TR01-to-TOOLS02.patch','FILES.json','DIFF-SUMMARY.json'].map(n=>bytesDigest(fs.readFileSync(path.join(out,n))).slice(7)+'  '+n).join('\n')+'\n');
