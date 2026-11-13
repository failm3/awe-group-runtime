import {createAuthorityClient} from '../coordinator/index.mjs';
import {evaluateMaintenanceArtifact} from '../qa2/maintenance-oracle.mjs';
// Separate fixed QA process receives a scoped QA credential, no database handle.
process.once('message',async config=>{
 try{
  const evaluation=evaluateMaintenanceArtifact(config.evaluation),client=createAuthorityClient(config);
  const value=await client.qaEvaluate({...config.binding,verdict:evaluation.verdict,checks:evaluation.checks});
  process.send?.({type:'EVALUATED',pid:process.pid,evaluation,value});process.disconnect?.();
 }catch(e){process.send?.({type:'ERROR',code:e.code??e.message??'E1_QA_LEAF_FAILED'});process.exitCode=1;process.disconnect?.();}
});
