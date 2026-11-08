import {pathToFileURL} from 'node:url';
import {createAuthorityClient} from '../coordinator/authority-server.mjs';
import {digest,need} from '../contracts/index.mjs';
import {inspectNativeToolTask,toolQaReviewContext} from './oracle.mjs';

export async function evaluateNativeTool({url,token,binding,reviewContext}) {
  const client=createAuthorityClient({url,token}),snapshot=await client.snapshot();
  let examined;
  try {examined=inspectNativeToolTask({...toolQaReviewContext(reviewContext,binding.task_id),snapshot,binding});}
  catch(error) {
    const checks=['schema','sources','scope','product'].map(check_id=>({check_id,passed:false}));
    const rejected=await client.qaEvaluate({...binding,verdict:'FAIL',checks});
    return {type:'EVALUATED',pid:process.pid,verdict:'FAIL',reason:error.code??'QA_TOOLS_REJECT',checks,value:rejected,accepted:false};
  }
  const value=await client.qaEvaluate({...binding,verdict:'PASS',checks:examined.checks});
  need(value.status==='ACCEPTED','QA_TOOLS_NATIVE_ACCEPTANCE');
  return {type:'EVALUATED',pid:process.pid,verdict:'PASS',value,evaluation:examined,evidence_digest:digest(examined),accepted:false};
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  process.once('message',async message=>{try{process.send?.(await evaluateNativeTool(message));}catch(error){process.send?.({type:'ERROR',pid:process.pid,code:error.code??'QA_TOOLS_LEAF_FAILED'});}});
  process.on('disconnect',()=>process.exit(0));process.send?.({type:'QA_READY',pid:process.pid});
}
