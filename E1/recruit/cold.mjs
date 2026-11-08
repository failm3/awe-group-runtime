import fs from 'node:fs';
import {createPsqlSession,createCoordinator} from '../coordinator/index.mjs';
import {digest,need} from '../contracts/index.mjs';
const [configPath]=process.argv.slice(2),config=JSON.parse(fs.readFileSync(configPath)),db=await createPsqlSession(JSON.parse(fs.readFileSync(config.resourcePath)),{role:'qa'});
try{
 const view=createCoordinator({db,project_id:config.project_id}),state=await view.snapshot(),tasks=state.tasks.filter(t=>t.mission_id===config.mission_id&&t.is_current),attempts=state.attempts.filter(a=>a.mission_id===config.mission_id);
 for(const task of tasks)if(task.result)need(digest(task.result)===task.result_hash&&digest(task.result.output)===task.result.artifact_digest,'RECRUIT_COLD_DIGEST');
 const artifact_digest=digest(tasks.filter(t=>t.result).map(t=>({task_id:t.task_id,result_hash:t.result_hash})).sort((a,b)=>a.task_id.localeCompare(b.task_id)));
 console.log(JSON.stringify({schema:'awe.recruit.cold-readback/1',pid:process.pid,mission_id:config.mission_id,project_id:config.project_id,mission_state:state.missions.find(m=>m.mission_id===config.mission_id)?.state,artifact_digest,tasks,attempts,postgresql:'NATIVE_E1_5433',new_model_wire_attempts:0}));
}finally{await db.close();}
