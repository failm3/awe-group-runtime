import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const root=path.resolve(import.meta.dirname,'../..'),base=path.join(root,'INTEGRATION-01'),out=path.join(base,'review');fs.mkdirSync(out,{recursive:true});
const pairs=[
 ['01-derived-int04-host','INTEGRATION-01/snapshots/INT04/awe/integration_v4/offline-host.mjs','INTEGRATION-01/adapters/int04-host.mjs'],
 ['02-fixed-d08-entry','INTEGRATION-01/snapshots/INT04/awe/qa/evaluator.mjs','awe/qa/evaluator.mjs'],
 ['03-sec-source-pins','INTEGRATION-01/snapshots/INT04/awe/execution_security/evaluation.mjs','awe/execution_security/evaluation.mjs'],
 ['04-d07-storage-port','tests/memory_artifacts/fixtures.mjs','INTEGRATION-01/adapters/d07-fixture.mjs'],
 ['05-ui-app','INTEGRATION-01/snapshots/UI/UI-MVP/src/app.mjs','INTEGRATION-01/ui/src/app.mjs'],
 ['06-ui-domain','INTEGRATION-01/snapshots/UI/UI-MVP/src/domain.mjs','INTEGRATION-01/ui/src/domain.mjs'],
 ['07-ui-styles','INTEGRATION-01/snapshots/UI/UI-MVP/styles.css','INTEGRATION-01/ui/styles.css']
];
const rows=[];for(const [name,before,after]of pairs){const r=spawnSync('git',['--no-pager','diff','--no-index','--no-ext-diff','--',before,after],{cwd:root,encoding:'utf8',windowsHide:true,maxBuffer:4*1024*1024});if(![0,1].includes(r.status))throw Error(r.stderr);const file=name+'.patch';fs.writeFileSync(path.join(out,file),r.stdout);rows.push({file:'review/'+file,before,after,sha256:createHash('sha256').update(r.stdout).digest('hex')});}
fs.writeFileSync(path.join(out,'PATCHES.json'),JSON.stringify({status:'CANDIDATE_ONLY_PENDING_INT04_REVIEW',patches:rows},null,2)+'\n');console.log(JSON.stringify({status:'PASS',patches:rows.length}));
