import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
const [name,...files]=process.argv.slice(2);
if(!/^[a-z0-9-]+$/.test(name)||!files.length||files.some(x=>!/^E1\/qa2\/[a-z0-9.-]+\.test\.mjs$/.test(x)))throw new Error('Unsafe QA run name or file');
const hash=v=>crypto.createHash('sha256').update(v).digest('hex');
function pins(){
 const rows=[];
 function walk(root){for(const x of fs.readdirSync(root,{withFileTypes:true})){const p=path.join(root,x.name);if(x.isSymbolicLink())throw new Error('Symlink in pinned implementation');if(x.isDirectory())walk(p);else if(/\.(mjs|cjs|sql|json)$/.test(x.name))rows.push({path:p.split(path.sep).join('/'),sha256:hash(fs.readFileSync(p))});}}
 for(const root of ['E1/coordinator','E1/broker','E1/contracts','E1/mission','E1/host'])if(fs.existsSync(root))walk(root);
 for(const p of [...new Set([...files,'E1/qa2/native-fixture.mjs','E1/qa2/maintenance-oracle.mjs','E1/qa2/run-qa.mjs'])])if(fs.existsSync(p))rows.push({path:p,sha256:hash(fs.readFileSync(p))});
 return rows.sort((a,b)=>a.path.localeCompare(b.path));
}
const before=pins(),args=['--test','--test-concurrency=1','--test-reporter=tap',...files],start=new Date().toISOString();
const result=spawnSync(process.execPath,args,{encoding:'utf8',maxBuffer:16*1024*1024,timeout:180000});
const after=pins(),output=(result.stdout??'')+(result.stderr??'');
fs.writeFileSync('E1/qa2/'+name+'.tap',output);
const record={schema:'awe.qa2.command-result/1',command:'node '+args.join(' '),node:process.version,started_at:start,finished_at:new Date().toISOString(),exit_status:result.status,signal:result.signal,error:result.error?.code??null,implementation_stable_during_run:JSON.stringify(before)===JSON.stringify(after),source_before:before,source_after:after,output_sha256:hash(output),log:'E1/qa2/'+name+'.tap'};
fs.writeFileSync('E1/qa2/'+name+'.command.json',JSON.stringify(record,null,2)+'\n');
console.log(JSON.stringify({...record,source_before_count:before.length,source_after_count:after.length,source_before:undefined,source_after:undefined},null,2));
console.log(output);
process.exitCode=result.status===0&&record.implementation_stable_during_run?0:1;
