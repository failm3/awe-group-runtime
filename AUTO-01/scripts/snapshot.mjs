import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
const root=path.resolve(import.meta.dirname,'../..');
const source='C:/Users/1/.codex/visualizations/2026/11/06/01a1af92-cac0-7712-822c-d35d8f224206/AWE-GROUP-INTEGRATION01';
const excluded=new Set(['.git','node_modules','evidence','sandbox','delivery','__pycache__']);
const sha=b=>createHash('sha256').update(b).digest('hex');
function walk(dir){return fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name)).flatMap(e=>{if(excluded.has(e.name))return [];if(e.isSymbolicLink())throw Error('SOURCE_LINK_DENIED');const p=path.join(dir,e.name);return e.isDirectory()?walk(p):[p];});}
const rows=[];
for(const p of walk(source)){const rel=path.relative(source,p).replaceAll('\\','/'),bytes=fs.readFileSync(p),target=path.join(root,rel);fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,bytes);rows.push({path:rel,bytes:bytes.length,sha256:sha(bytes)});}
const manifest={format:'AUTO01_UPSTREAM_BYTES_V1',source,gitBase:'b0b27f2f405fa520dad4cf0196a791480b9e5b61',branch:'codex/awe-auto01-autonomy',excludedDirectories:[...excluded],files:rows};
fs.writeFileSync(path.join(root,'AUTO-01/UPSTREAM-SOURCES.json'),JSON.stringify(manifest,null,2)+'\n');
// Pristine bytes live in a review snapshot, never imported as runtime modules.
for(const row of rows){const p=path.join(source,row.path),b=fs.readFileSync(p);if(sha(b)!==row.sha256)throw Error('UPSTREAM_DRIFT '+row.path);const target=path.join(root,'AUTO-01/upstream',row.path);fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,b);}
console.log(JSON.stringify({copied:rows.length,upstreamUnchangedDuringCopy:true,root}));
