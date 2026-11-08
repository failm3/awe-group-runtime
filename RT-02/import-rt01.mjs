import {readFileSync,writeFileSync,mkdirSync,readdirSync,lstatSync,existsSync,copyFileSync} from 'node:fs';
import {join,dirname,resolve} from 'node:path';
import {createHash} from 'node:crypto';
const root=resolve(import.meta.dirname,'..'),source='C:/Users/1/AWE-GROUP-RT01';
const sha=b=>createHash('sha256').update(b).digest('hex');
const walk=p=>readdirSync(join(source,p),{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(p+'/'+e.name):[p+'/'+e.name]);
const paths=[...walk('awe/hermes_runtime'),...walk('tests/hermes_runtime'),...readdirSync(join(source,'RT-01')).filter(n=>/\.(mjs|md|json|ps1)$/.test(n)).map(n=>'RT-01/'+n),...readdirSync(join(source,'RT-01/process-candidate')).filter(n=>/\.(mjs|md|json|ps1|patch)$/.test(n)).map(n=>'RT-01/process-candidate/'+n)].filter(p=>!p.includes('__pycache__'));
const out=join(root,'RT-02/import-manifest.json');
if(existsSync(out))throw Error('IMPORT_ALREADY_RECORDED');
const rows=[];
for(const path of paths.sort()){
 const from=join(source,path),to=join(root,path),bytes=readFileSync(from);
 if(lstatSync(from).isSymbolicLink())throw Error('SOURCE_LINK');
 const previous=existsSync(to)?sha(readFileSync(to)):null;
 // Preserve any pre-existing candidate bytes before refreshing from actual RT01.
 const before=join(root,'RT-02/before',path);mkdirSync(dirname(before),{recursive:true});writeFileSync(before,bytes,{flag:'wx'});
 if(previous!==sha(bytes)){if(previous)throw Error('CANDIDATE_DIFF_REQUIRES_REVIEW:'+path);mkdirSync(dirname(to),{recursive:true});copyFileSync(from,to);}
 if(sha(readFileSync(to))!==sha(bytes))throw Error('COPY_HASH_MISMATCH');
 rows.push({path,sha256:sha(bytes),candidate_before_sha256:previous,source_after_sha256:sha(readFileSync(from))});
}
writeFileSync(out,JSON.stringify({source,source_branch:'codex/awe-rt01-hermes',base:'b0b27f2f405fa520dad4cf0196a791480b9e5b61',imported_at:new Date().toISOString(),rows},null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({files:rows.length,all_sha256_equal:rows.every(r=>r.sha256===r.source_after_sha256),source_unchanged:true}));
