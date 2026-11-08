import {readFileSync,writeFileSync,mkdirSync,existsSync,readdirSync,statSync} from 'node:fs';
import {resolve,dirname,relative} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url));
const source='C:/Users/1/AWE-GROUP-TR01';
const sha=b=>createHash('sha256').update(b).digest('hex');
const files=[];
function walk(dir){for(const name of readdirSync(resolve(source,dir))){const p=dir+'/'+name;if(statSync(resolve(source,p)).isDirectory())walk(p);else files.push(p);}}
walk('awe/tool_registry');walk('tests/tool_registry');
files.push('TR-01/CONTRACTS.md','TR-01/README.md','TR-01/TAXONOMY.md','TR-01/source/catalog/90 - Данные/all-records-classified.json');
const entries=[];
for(const path of files.sort()){
 const target=resolve(root,path),bytes=readFileSync(resolve(source,path));
 if(existsSync(target)&&sha(readFileSync(target))!==sha(bytes))throw Error('IMPORT_TARGET_DRIFT '+path);
 mkdirSync(dirname(target),{recursive:true});writeFileSync(target,bytes);
 entries.push({path,bytes:bytes.length,sha256:sha(bytes)});
}
const context=[];
for(const path of ['C:/Users/1/AWE-GROUP-RT01/awe/hermes_runtime/ports.d.ts','C:/Users/1/AWE-GROUP-RT01/awe/hermes_runtime/process-ports.d.ts','C:/Users/1/AWE-GROUP-RT01/RT-01/CONTRACTS.md','C:/Users/1/AWE-GROUP-RT01/RT-01/process-candidate/CONTRACT.md','C:/Users/1/AWE-GROUP-INT04/awe/integration_v4/offline-host.mjs']){
 if(existsSync(path)){const b=readFileSync(path);context.push({path,bytes:b.length,sha256:sha(b)});}
}
writeFileSync(resolve(root,'TOOLS-02/IMPORTED-FILES.json'),JSON.stringify({base:'b0b27f2f405fa520dad4cf0196a791480b9e5b61',source,scope:'Selected TR01 modules, regression fixtures and owning contract readbacks; no delivery/evidence/live refresh copied',entries,context},null,2)+'\n');
console.log(JSON.stringify({imported:entries.length,context:context.length,root:relative(process.cwd(),root)}));
