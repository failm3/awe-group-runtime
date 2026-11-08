import {readFileSync,readdirSync,mkdirSync,writeFileSync,copyFileSync} from 'node:fs';
import {join,dirname} from 'node:path';
import {createHash} from 'node:crypto';
const root=new URL('../',import.meta.url).pathname.replace(/^\/([A-Z]:)/,'$1');
const sha=b=>createHash('sha256').update(b).digest('hex');
const sources=[
 ['D08','C:/Users/1/.codex/worktrees/awe-d08-offline/AWE-GROUP-Implementation',['awe/qa','tests/qa','D-08/STATE-MATRIX.md','D-08/CONTRACT-CHANGE-REQUESTS.md']],
 ['INTEGRATION01','C:/Users/1/.codex/visualizations/2026/11/06/01a1af92-cac0-7712-822c-d35d8f224206/AWE-GROUP-INTEGRATION01',['INTEGRATION-01/CONTRACTS.md','INTEGRATION-01/REPORT.md','INTEGRATION-01/SOURCE-LOCK.json','INTEGRATION-01/adapters/evaluator.mjs','INTEGRATION-01/adapters/int04-host.mjs','awe/qa/evaluator.mjs']],
 ['AUTO01','C:/Users/1/.codex/visualizations/2026/11/06/01a1b0c2-bca3-7843-ae90-f9c6888e316e/AWE-GROUP-AUTO01',['AUTO-01/AUTO-02-CONTRACT.md','AUTO-01/contracts.mjs']],
 ['INT04','C:/Users/1/AWE-GROUP-INT04',['INT-04/ARCHITECTURE.md','INT-04/COMPATIBILITY.md','awe/qa/evaluator.mjs']]
];
function files(base,path){const entries=readdirSync(join(base,path),{withFileTypes:true});return entries.flatMap(e=>e.isDirectory()?files(base,path+'/'+e.name):[path+'/'+e.name]);}
const rows=[];
for(const [id,base,paths] of sources)for(const path of paths.flatMap(p=>p.endsWith('.md')||p.endsWith('.json')||p.endsWith('.mjs')?[p]:files(base,p))){
 const bytes=readFileSync(join(base,path)),target=join(root,'QA-02/sources',id,path);
 mkdirSync(dirname(target),{recursive:true});copyFileSync(join(base,path),target);
 const baseline=path.startsWith('awe/qa/')?sha(readFileSync(join(root,path))):null;
 rows.push({id,root:base,path,bytes:bytes.length,sha256:sha(bytes),baseline_sha256:baseline,equal_to_baseline:baseline?baseline===sha(bytes):null,activated:false});
}
writeFileSync(join(root,'QA-02/SOURCE-LOCK.json'),JSON.stringify({version:'qa02-source-lock/1',created_at:new Date().toISOString(),base:'b0b27f2f405fa520dad4cf0196a791480b9e5b61',github_ref:'407c92f31f604204d5c16f5bbcce07197a051f34',files:rows},null,2)+'\n');
console.log(JSON.stringify({files:rows.length,D08:rows.filter(r=>r.id==='D08'&&r.baseline_sha256).map(r=>({path:r.path,equal:r.equal_to_baseline}))}));
