'use strict';
const {syncBuiltinESMExports}=require('node:module');
const denied=()=>{throw Object.assign(new Error('QA3_NATIVE_EFFECT_DENIED'),{code:'QA3_NATIVE_EFFECT_DENIED'});};
globalThis.fetch=denied;
Object.defineProperty(globalThis,'__QA3_NATIVE_GUARD_ACTIVE__',{value:true,writable:false,configurable:false});
for(const [name,methods] of Object.entries({'node:http':['request','get','createServer'],'node:https':['request','get','createServer'],'node:net':['connect','createConnection','createServer'],'node:tls':['connect','createServer'],'node:dgram':['createSocket']})){const module=require(name);for(const method of methods)module[method]=denied;}
const child=require('node:child_process'),spawn=child.spawn;
for(const name of ['spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=denied;
child.spawn=(executable,args,options)=>{
 const role=args?.[7],roles=['awe_e1_coord','awe_e1_test','awe_e1_qa'];
 const expected=['--distribution','Ubuntu','--user','root','--exec','/usr/sbin/runuser','--user',role,'--','/usr/lib/postgresql/18/bin/psql','--no-psqlrc','--no-password','--quiet','--tuples-only','--no-align','--set','ON_ERROR_STOP=on','--host','/var/lib/awe-e1-test/awe_e1_a2a3_20261108/socket','--port','5433','--dbname','awe_e1_test','--username',role];
 if(executable!=='wsl.exe'||!roles.includes(role)||JSON.stringify(args)!==JSON.stringify(expected)||Object.keys(options?.env??{}).some(k=>!['SystemRoot','WINDIR','PATH','WSL_UTF8'].includes(k)))return denied();
 const process=spawn(executable,args,options),write=process.stdin.write.bind(process.stdin);
 process.stdin.write=(chunk,...rest)=>{
  const sql=String(chunk);
  if(/^\s*(?:CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE)\b/mi.test(sql)||/^\\(?:i|ir|!|copy|connect|c)(?:\s|$)/mi.test(sql))return denied();
  return write(chunk,...rest);
 };return process;
};
syncBuiltinESMExports();
