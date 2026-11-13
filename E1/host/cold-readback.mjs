import fs from 'node:fs';
import {createPsqlSession,createCoordinator} from '../coordinator/index.mjs';
import {verifyPersistedTaskArtifact} from './artifact-binding.mjs';
const [resourcePath,project_id,mission_id,consumer_id]=process.argv.slice(2);
const resource=JSON.parse(fs.readFileSync(resourcePath,'utf8')),db=await createPsqlSession(resource,{role:'qa'});
try{
 const coordinator=createCoordinator({db,project_id}),snapshot=await coordinator.snapshot(),cursor=await coordinator.getCursor(consumer_id);
 const mission=snapshot.missions.find(m=>m.mission_id===mission_id);
 const attempts=snapshot.attempts.filter(a=>a.mission_id===mission_id);
 for(const task of [...snapshot.tasks,...snapshot.task_history.map(t=>t.body)].filter(t=>t.mission_id===mission_id&&t.result))verifyPersistedTaskArtifact(task);
 console.log(JSON.stringify({schema:'awe.e1.cold-process-readback/1',pid:process.pid,mission_id,mission_state:mission?.state,plan_digest:mission?.plan_digest,attempts:attempts.map(a=>({attempt_id:a.attempt_id,state:a.state,usage:a.usage,request_hash:a.request_hash})),project:snapshot.project,cursor,current_tasks:snapshot.tasks.filter(t=>t.mission_id===mission_id&&t.is_current).map(t=>({task_id:t.task_id,state:t.state,result_hash:t.result_hash,plan_digest:t.plan_digest})),archived_tasks:snapshot.task_history.filter(t=>t.mission_id===mission_id).length,postgresql:'NATIVE',new_model_wire_attempts:0}));
}finally{await db.close();}
