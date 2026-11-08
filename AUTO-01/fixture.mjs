import {harness} from '../tests/state/harness.mjs';
import {createArtifactStore} from '../awe/context/store.mjs';
import {createInt04OfflineHost} from '../INTEGRATION-01/adapters/int04-host.mjs';
import {createMockModel,createMockExecutors} from './mock.mjs';

// Same synthetic D03 trust composition as INT04/Integration01. This is a test
// host, not a production session, authority issuer, QA service, or money ledger.
export async function fixture({h,sessionId='auto',projectId='prj_alpha',model=createMockModel(),executors=createMockExecutors(),artifacts=createArtifactStore({max_entries:512,max_bytes:4194304,max_object_bytes:16384}),maxReplans=3}={}){
 h??=harness();
 try{h.service.getProject(h.owner,projectId);}catch{await h.project(projectId);}
 const host=await createInt04OfflineHost({profile:'AUTO01',h,projectId,sessionId,model,executors,artifacts,maxReplans});
 return {host,h,model,executors,artifacts,
  message:(text,key='message')=>host.postMessage({text,idempotencyKey:key,expectedRevision:host.snapshot().revision}),
  run:(key='run',maxSteps=64)=>host.run({idempotencyKey:key,expectedRevision:host.snapshot().revision,maxSteps})};
}
