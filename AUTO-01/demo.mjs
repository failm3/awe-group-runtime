import readline from 'node:readline/promises';
import fs from 'node:fs';
import path from 'node:path';
import {MemoryStorage} from '../awe/state/memory-storage.mjs';
import {harness} from '../tests/state/harness.mjs';
import {fixture} from './fixture.mjs';
const directory=path.resolve(import.meta.dirname,'sandbox/cli');fs.mkdirSync(directory,{recursive:true});
const stateFile=path.join(directory,'d03.snapshot.json');
const h=harness({storage:fs.existsSync(stateFile)?new MemoryStorage({snapshot:fs.readFileSync(stateFile,'utf8')}):new MemoryStorage()});
const f=await fixture({h}),rl=readline.createInterface({input:process.stdin,output:process.stdout});let i=f.host.snapshot().history.length;
console.log('AUTO-01 E0 MOCK. Обычный диалог; /quit — выход. Все результаты синтетические.');
for await(const line of rl){
 if(line==='/quit'){rl.close();break;}
 let response;
 try{response=await f.host.converse({text:line,idempotencyKey:'message-'+(++i),expectedRevision:f.host.snapshot().revision});}
 catch(e){console.log(e.message);continue;}
 let s=response.snapshot;
 console.log(s.history.at(-1)?.text??s.phase);
 fs.writeFileSync(stateFile,h.storage.snapshot());
 console.log(JSON.stringify({phase:s.phase,spec:s.spec?.ref??null,plan:s.plan?.content??null,tasks:s.tasks,questions:s.questions,blockers:s.blockers,realAutonomyVerified:false},null,2));
 for(const [id,r] of Object.entries(s.results))for(const ref of r.artifacts)console.log(f.host.readArtifact(id,ref.artifact_ref).toString('utf8'));
}
