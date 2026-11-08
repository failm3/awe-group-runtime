import fs from 'node:fs';
import path from 'node:path';
import {createFuseCandidate} from './host.mjs';
import {createInt04OfflineHost} from '../INTEGRATION-01/adapters/int04-host.mjs';
const legacy=process.argv.includes('--legacy-preflight');
const text=process.argv.slice(2).filter(x=>x!=='--legacy-preflight').join(' ')||'AWE GROUP — MASTER-INTEGRATION-01\n';
if(!legacy){const host=await createInt04OfflineHost({profile:'MASTER01'});console.log(JSON.stringify(await host.prepare({goal:'Создай текстовый файл result.txt с точным содержимым',filename:'result.txt',text}),null,2));}
else {
const f=await createFuseCandidate();await f.converse(text);
const summary={...f.snapshot(),archive:f.archive,restore_view:f.restoreView(),cross_project:f.foreignRead()};
const directory=path.resolve(import.meta.dirname,'../MASTER-INTEGRATION-01/evidence/legacy-fuse');fs.mkdirSync(directory,{recursive:true});
const file=path.join(directory,'demo-'+Date.now()+'.json');fs.writeFileSync(file,JSON.stringify(summary,null,2)+'\n');
console.log(JSON.stringify({status:summary.phase,tasks:Object.values(summary.tasks).map(t=>({id:t.id,state:t.state})),
 positive_e2e:summary.positive_e2e,accepted:false,authoritative_complete:false,physical_decision:'DENY',effects:summary.effects,report:file},null,2));
}
