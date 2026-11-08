// Maintainer-only pin generation. Never called from dispatch, tests or recovery.
import {readFileSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
const root=resolve(import.meta.dirname,'..'),hash=p=>'sha256:'+createHash('sha256').update(readFileSync(p)).digest('hex');
const executables=Object.fromEntries(Object.entries({node:process.execPath,python:'C:/Users/1/AppData/Local/Programs/Python/Python313/python.exe',cli:'C:/Windows/System32/findstr.exe'}).map(([k,path])=>[k,{path,hash:hash(path)}]));
const sources=Object.fromEntries(['awe/hermes_runtime/executors/javascript.cjs','awe/hermes_runtime/executors/python.py','awe/hermes_runtime/executors/job-host.py','baseline/offline-guard.cjs'].map(p=>[p,hash(join(root,p))]));
writeFileSync(join(root,'RT-02/runtime-lock.json'),JSON.stringify({contract:'rt02.runtime-lock/1',platform:'win32',node:'v24.21.0',python:'3.13.2',executables,sources},null,2)+'\n');
console.log('Pinned local runtime and reviewed synthetic sources.');
