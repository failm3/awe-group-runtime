import {createAuthorityClient} from '../coordinator/index.mjs';
import {digest,need} from '../contracts/index.mjs';
import {readFixtureSource,rankListings,draftApplications} from './pipeline.mjs';
import {rankWithVerifiedCode} from './coding/consume.mjs';

process.once('message',async config=>{
 try{
  const client=createAuthorityClient(config),claim=await client.claim({mission_id:config.mission_id,task_id:config.task_id,capabilities:config.capabilities,lease_ms:config.interrupt_after_claim?1000:30000});
  need(claim.status==='CLAIMED','RECRUIT_CLAIM_REQUIRED');
  if(config.interrupt_after_claim){process.send?.({type:'CLAIMED_FOR_CRASH',pid:process.pid,task_id:claim.task_id,fence:claim.fence});await new Promise(()=>{});return;}
  const capability=claim.task.capability.capability_id,input=JSON.parse(claim.task.input.instruction);
  need(claim.task.effect.effect_class==='NONE'&&capability.startsWith('e1.recruit.'),'RECRUIT_CAPABILITY_DENIED');
  const deps=config.dependencies??{};need(Object.keys(deps).sort().join()===claim.task.depends_on.slice().sort().join(),'RECRUIT_DEPENDENCIES');
  for(const item of Object.values(deps))need(item.artifact_digest===digest(item.output),'RECRUIT_DEPENDENCY_DIGEST');
  let artifact;
  if(capability==='e1.recruit.read')artifact=await readFixtureSource(input);
  else if(capability==='e1.recruit.rank')artifact=rankListings(Object.values(deps).map(d=>JSON.parse(d.output.payload)));
  else if(capability==='e1.recruit.rank-coded')artifact=await rankWithVerifiedCode(Object.values(deps).map(d=>JSON.parse(d.output.payload)),input.scoreInput);
  else if(capability==='e1.recruit.draft')artifact=draftApplications(JSON.parse(deps.rank.output.payload),input.facts);
  else throw Error('RECRUIT_NOT_IMPLEMENTED');
  const output={payload:JSON.stringify(artifact)},result={output_schema_digest:claim.task.capability.output_schema.digest,output,artifact_digest:digest(output),trace:{producer:'AWE_E1_RUNTIME_FIXED_SCRIPT',pid:process.pid,capability,dependency_result_hashes:Object.values(deps).map(d=>d.result_hash)}};
  const completed=await client.complete({mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence,result,result_hash:digest(result)});
  process.send?.({type:'COMPLETED',pid:process.pid,task_id:claim.task_id,fence:claim.fence,result_hash:digest(result),status:completed.status});process.disconnect?.();
 }catch(e){process.send?.({type:'ERROR',code:e.code??e.message??'RECRUIT_WORKER_FAILED'});process.exitCode=1;process.disconnect?.();}
});
