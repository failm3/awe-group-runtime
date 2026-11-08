import {createAuthorityClient} from './authority-server.mjs';
import {digest} from '../contracts/index.mjs';

// Fixed dependency-free read/compute leaf. The parent sends only one scoped
// authority credential and task limits over IPC. No database resource descriptor,
// DB password, migration API, arbitrary program or shell string is accepted.
process.once('message',async config=>{
  try {
    const client=createAuthorityClient(config),claim=await client.claim({capabilities:config.capabilities,lease_ms:config.lease_ms??5000,mission_id:config.mission_id,task_id:config.task_id});
    if(claim.status!=='CLAIMED'){process.send?.({type:'WAIT',value:claim});process.disconnect?.();return;}
    const started_at=new Date().toISOString(),scope={mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence};
    process.send?.({type:'CLAIMED',pid:process.pid,scope,started_at,received_keys:Object.keys(config).sort()});
    if(claim.task.effect.effect_class!=='NONE')throw Object.assign(new Error('A2_READ_LEAF_EFFECT_DENIED'),{code:'A2_READ_LEAF_EFFECT_DENIED'});
    const delay_ms=config.delay_ms??100;await new Promise(resolve=>setTimeout(resolve,delay_ms));
    const output={text:'Computed: '+claim.task.input.instruction};
    const result={output_schema_digest:claim.task.capability.output_schema.digest,output,artifact_digest:digest(output),trace:{pid:process.pid,started_at,finished_at:new Date().toISOString()}};
    const completed=await client.complete({...scope,result,result_hash:digest(result)});
    process.send?.({type:'COMPLETED',pid:process.pid,scope,result_hash:digest(result),...completed});process.disconnect?.();
  }catch(error){process.send?.({type:'ERROR',code:error.code??'A2_LEAF_FAILURE'});process.exitCode=1;process.disconnect?.();}
});
