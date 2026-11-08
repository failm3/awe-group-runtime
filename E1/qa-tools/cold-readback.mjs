import {pathToFileURL} from 'node:url';
import {createPsqlSession} from '../coordinator/psql-session.mjs';
import {createCoordinator} from '../coordinator/coordinator.mjs';
import {digest,need,immutable} from '../contracts/index.mjs';
import {inspectNativeToolTask,toolQaReviewContext} from './oracle.mjs';

export async function coldReadNativeTools({resource,project_id,mission_id,expected}) {
  const db=await createPsqlSession(resource,{role:'qa'});
  try {
    const coordinator=createCoordinator({db,project_id}),snapshot=await coordinator.snapshot(),events=await coordinator.events();
    const mission=snapshot.missions.find(m=>m.mission_id===mission_id);
    need(mission?.state==='COMPLETE'&&snapshot.tasks.filter(t=>t.mission_id===mission_id&&t.is_current).length===expected.length,'QA_TOOLS_COLD_MISSION');
    const outputs=expected.map(item=>{
      const passed=events.filter(event=>event.mission_id===mission_id&&event.task_id===item.binding.task_id&&event.kind==='QA_PASS'&&event.body.result_hash===item.binding.result_hash&&event.body.evaluator_id===item.binding.evaluator_id);
      need(passed.length===1,'QA_TOOLS_COLD_QA_EVENT');
      // Historical replay checks review validity at the native QA event time;
      // a later expiry does not rewrite a previously accepted tool result.
      const inspected=inspectNativeToolTask({...toolQaReviewContext(item.reviewContext,item.binding.task_id),snapshot,binding:item.binding,expectedState:'ACCEPTED',now:passed[0].at});
      return {task_id:inspected.task_id,result_hash:inspected.result_hash,artifact_digest:inspected.artifact_digest,output:inspected.output,execution_digest:inspected.execution_digest,qa_event_digest:digest(passed[0]),producer_id:inspected.producer_id,fence:inspected.fence};
    });
    return immutable({type:'COLD_VERIFIED',schema:'awe.e1.tool-canary-cold/1',pid:process.pid,status:'PASS',project_id,mission_id,outputs,model_attempts:0,spent:Number(snapshot.project.spent),reserved:Number(snapshot.project.reserved),quota_used:Number(snapshot.project.quota_used),proof_scope:'BOUNDED_NATIVE_UTILITY_DISPATCH_NOT_AUTONOMY',accepted:false});
  } finally {await db.close();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  process.once('message',async message=>{try{process.send?.(await coldReadNativeTools(message));}catch(error){process.send?.({type:'ERROR',pid:process.pid,code:error.code??'QA_TOOLS_COLD_FAILED'});}});
  process.on('disconnect',()=>process.exit(0));process.send?.({type:'QA_READY',pid:process.pid});
}
