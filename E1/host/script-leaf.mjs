import {createAuthorityClient} from '../coordinator/index.mjs';
import {canonicalize,digest} from '../contracts/index.mjs';
// Fixed parser: untrusted source is JSON data, never eval/shell/imported code.
process.once('message',async config=>{
 try{
  const client=createAuthorityClient(config),claim=await client.claim({capabilities:['e1.code.parse'],mission_id:config.mission_id,task_id:config.task_id,lease_ms:10000});
  if(claim.status!=='CLAIMED'){process.send?.({type:'WAIT',value:claim});process.disconnect?.();return;}
  if(claim.task.capability.capability_id!=='e1.code.parse'||claim.task.effect.effect_class!=='NONE')throw Error('E1_SCRIPT_CAPABILITY_DENIED');
  const started_at=new Date().toISOString(),output={text:canonicalize(JSON.parse(claim.task.input.instruction))};
  const result={output_schema_digest:claim.task.capability.output_schema.digest,output,artifact_digest:digest(output),trace:{pid:process.pid,started_at,finished_at:new Date().toISOString()}};
  await client.complete({mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence,result,result_hash:digest(result)});
  process.send?.({type:'COMPLETED',pid:process.pid,claim,result_hash:digest(result)});process.disconnect?.();
 }catch(e){process.send?.({type:'ERROR',code:e.code??'E1_SCRIPT_LEAF_FAILED'});process.exitCode=1;process.disconnect?.();}
});
