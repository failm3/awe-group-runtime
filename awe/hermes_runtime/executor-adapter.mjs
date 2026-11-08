import {createInt04ProcessAdapter,INT04_PROCESS_CONTRACT} from './int04-process-adapter.mjs';
import {EXECUTION_CONTRACT,programManifest,executionLock} from './execution-profile.mjs';
import {parseIntent,exact,need,deny,digest,freeze} from './protocol.mjs';
export {programManifest,EXECUTION_CONTRACT};
export function createExecutorAdapter(ports,options={}){
 need(Object.keys(options).every(k=>['contract','limits','startupCheckpoint'].includes(k))&&options.contract===EXECUTION_CONTRACT,'RT_HOST_CONTRACT_VERSION');
 const base=createInt04ProcessAdapter(ports,{contract:INT04_PROCESS_CONTRACT,executorProfile:EXECUTION_CONTRACT,...(options.limits?{limits:options.limits}:{}),...(options.startupCheckpoint?{startupCheckpoint:options.startupCheckpoint}:{})});
 return Object.freeze({...base,execution_contract:EXECUTION_CONTRACT,
  async invokeExecution(raw){try{
   const q=parseIntent(raw);exact(q,['contract','method','run_id','request']);
   need(q.contract==='auto02.rt02/1','RT_HOST_CONTRACT_VERSION');
   const reply=await base.invoke(JSON.stringify({...q,contract:INT04_PROCESS_CONTRACT}));
   return freeze({...reply,contract:'auto02.rt02/1',execution_contract:EXECUTION_CONTRACT,retry_owner:'D03_D09',resumable:false});
  }catch{return {...deny('RT_HOST_REQUEST_DENIED'),contract:'auto02.rt02/1'};}}
 });
}
// Discovery/binding remains a proposal. This does not create dispatch authority.
export function prepareExecutorReview(executor,program){
 const tool=programManifest(executor,program);
 const runtime=executionLock.executables[executor==='javascript'?'node':executor==='python'?'python':'cli'];
 return freeze({contract:'rt02.tr01.review/1',adapter_id:'d04_rt02_executor_v1',execution_contract:EXECUTION_CONTRACT,tool_id:tool.tool_id,runtime_artifact_digest:runtime.hash,execution_binding_digest:tool.digest,manifest_is_not_binary:true,
  input_schema_digest:digest({contract:'rt02.program/1',executor,program,input:executor==='cli'?'text-ascii-2048':'safe-integer-array-100'}),
  physical_decision:'DENY',runtime_dispatch:false,gates:['TR01_CURRENT_SCOPED_BINDING','SEC_CURRENT_AUTHORITY','D09_ONE_USE_ADMISSION','D03_LIVE_TASK']});
}
// Preparation is pure metadata; no plugin import, executable path or activation option.
export function prepareNativeHermesTransport(){
 return freeze({contract:'rt02.hermes.transport/1',state:'PREPARED_BLOCKED',real_hermes:'REAL_HERMES_NOT_RUN',physical_decision:'DENY',
  lifecycle_contract:INT04_PROCESS_CONTRACT,execution_contract:EXECUTION_CONTRACT,runtime_lock_digest:digest(executionLock),
  methods:['launchChild','streamEvents','join','cancel','checkpoint','reconcile'],
  required_gates:['NATIVE_PROTOCOL_COMPATIBILITY','SEC_SIGNED_ONE_USE_DISPATCH','D09_DURABLE_NATIVE_LINEAGE','OS_PRINCIPAL_AND_EGRESS','TR01_EXACT_TOOLSET','LLM01_PINNED_BROKER','D08_INDEPENDENT_ACCEPTANCE'],
  cancellation:'cancel + confirmed exit of owned process tree',recovery:'HOLD_RECONCILE_REQUIRED',resumable:false,activation_supported:false});
}
