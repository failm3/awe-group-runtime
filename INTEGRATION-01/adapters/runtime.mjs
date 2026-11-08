import {createInt04ProcessAdapter,INT04_PROCESS_CONTRACT} from '../../awe/hermes_runtime/int04-process-adapter.mjs';
import {canonicalize,digest} from '../../contracts/canonical.mjs';
import {createHash} from 'node:crypto';
const hash=bytes=>'sha256:'+createHash('sha256').update(bytes).digest('hex');
export function createIntegratedRuntime(args){
 const {integrationMemory:m,integrationOptions:options={},transport,artifacts,...ports}=args;
 const attempts=ports.attempts;let lost=false;
 ports.attempts={...attempts,result:async(...a)=>{const ack=await attempts.result(...a);if(options.lostAck&&!lost){lost=true;throw Error('INTEGRATION01_RESULT_ACK_LOST_AFTER_COMMIT');}return ack;}};
 const bridge=createInt04ProcessAdapter(ports,{contract:INT04_PROCESS_CONTRACT,syntheticFaults:options.childFailure?{run_int04_child:'error'}:{}});
 return {...bridge.runtime,
  integrationProcesses:()=>bridge.inspectProcesses(),
  async integrationEvidence(){
   const outputs=[];
   for(const runId of ['run_int04_child','run_int04_parent']){
    const run=bridge.runtime.inspect(runId);if(run.status!=='WORK_COMPLETED')throw Error('INTEGRATION01_RUNTIME_NOT_COMPLETE');
    const output=bridge.readOutput(run.artifact.artifact_ref),bytes=Buffer.from(canonicalize(output));
    if(hash(bytes)!==run.artifact.artifact_hash)throw Error('INTEGRATION01_RUNTIME_HASH');
    const id=runId==='run_int04_child'?'art_int01_child':'art_int01_parent',stored=m.stageArtifact(id,m.files(bytes.toString('utf8')));
    const read=m.artifacts.read(m.session('act_worker'),JSON.stringify({artifact_id:id,version:stored.version,path:'site/index.txt'}));
    if(!read.ok||hash(Buffer.from(read.value.bytes_base64,'base64'))!==hash(bytes))throw Error('INTEGRATION01_PROCESS_D07_READBACK');
    outputs.push({run_id:runId,output,artifact:run.artifact,stored_reference:stored.reference,stored_version:stored.version,readback_hash:hash(bytes),readback_version:read.value.version,readback_artifact:read.value.artifact,readback_path:read.value.path,bytes:bytes.length});
   }
   return {contract:INT04_PROCESS_CONTRACT,processes:bridge.inspectProcesses(),outputs,full_transcripts_transferred:false,physical_decision:'DENY'};
  },
  integrationClose:()=>bridge.close(),
  integrationCheckpoint:(run,file)=>bridge.checkpoint(run,file)
 };
}
