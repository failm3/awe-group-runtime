import {createHermesRuntime} from './adapter.mjs';
import {createProcessSupervisor} from './process-supervisor.mjs';
import {createNativeHermesTransport} from './native-binding.mjs';
import {writeProcessCheckpoint,readProcessCheckpoint} from './process-checkpoint.mjs';
import {need,exact,parseIntent,copy,freeze,deny} from './protocol.mjs';
export const INT04_PROCESS_CONTRACT='int04.rt01.process/1';
const dependencyFailure='RT_HOST_DEPENDENCY_FAILURE';
const sanitized=code=>typeof code==='string'&&/^(RT_PROCESS_|RT_CHECKPOINT_|RT_HOST_)[A-Z_]+$/.test(code)?code:'RT_HOST_REQUEST_DENIED';
function syncPort(p,methods){need(p&&methods.every(k=>typeof p[k]==='function'),'RT_HOST_PORT_REQUIRED');return Object.freeze(Object.fromEntries(methods.map(k=>[k,(...a)=>{try{const v=p[k](...a);if(v?.then){Promise.resolve(v).catch(()=>{});throw Error(dependencyFailure);}return v;}catch{throw Error(dependencyFailure);}}])));}
function asyncPort(p,methods){need(p&&methods.every(k=>typeof p[k]==='function'),'RT_HOST_PORT_REQUIRED');return Object.freeze(Object.fromEntries(methods.map(k=>[k,async(...a)=>{try{return await p[k](...a);}catch{throw Error(dependencyFailure);}}])));}
/** INT04 host-to-host seam; reuses the existing RT01 state machine, D03 state,
 * SEC checks and D09 attempt ports. This factory owns only process control.
 */
export function createInt04ProcessAdapter(ports,options={}){
 need(ports&&Object.keys(ports).every(k=>['state','security','context','models','tools','attempts','journal','clock','supervisor','timeoutMs'].includes(k)),'RT_HOST_FACTORY_FIELDS');
 need(typeof ports.clock==='function','RT_HOST_CLOCK');
 need(Object.keys(options).every(k=>['contract','limits','syntheticFaults','startupCheckpoint','executorProfile'].includes(k))&&options.contract===INT04_PROCESS_CONTRACT,'RT_HOST_CONTRACT_VERSION');
 const startup=options.startupCheckpoint?readProcessCheckpoint(options.startupCheckpoint):null;
 need(options.executorProfile===undefined||options.syntheticFaults===undefined,'RT_HOST_CONTRACT_VERSION');
 const process=createProcessSupervisor(options.executorProfile?{executorProfile:options.executorProfile,limits:options.limits}:{limits:options.limits,syntheticFaults:options.syntheticFaults});
 const journal=syncPort(ports.journal,['read','append']);
 const recovering=Boolean(startup)||journal.read().length>0;let closed=false;
 const host=createHermesRuntime({state:syncPort(ports.state,['read']),security:syncPort(ports.security,['authorizeLaunch','current','authenticate']),
  context:asyncPort(ports.context,['read']),models:syncPort(ports.models,['check']),tools:syncPort(ports.tools,['check']),
  attempts:asyncPort(ports.attempts,['begin','result','cancel']),journal,clock:()=>{try{return ports.clock();}catch{throw Error(dependencyFailure);}},
  supervisor:ports.supervisor,timeoutMs:ports.timeoutMs??1000,transport:process.api,artifacts:{verify:(r,c)=>process.verify(r,c)}});
 const publicView=v=>{const out=copy(v);if(out.reason!==undefined&&out.reason!==null)out.reason=sanitized(out.reason);if(out.code)out.code=sanitized(out.code);return freeze(out);};
 const runtime=Object.freeze(Object.fromEntries(Object.keys(host).map(k=>[k,k==='bindWorker'?((run,session)=>{
  const worker=host.bindWorker(run,session);
  const authenticated=()=>{try{worker.status();return true;}catch{return false;}};
  return Object.freeze({...worker,status:()=>publicView(worker.status()),join:async()=>authenticated()?runtime.join(run):deny('RT_HOST_WORKER_DENIED'),cancel:async()=>authenticated()?runtime.cancel(run):deny('RT_HOST_WORKER_DENIED')});
 }):k==='inspect'?((...a)=>publicView(host[k](...a))):async(...a)=>{
  if(closed)return deny('RT_HOST_CLOSED');
  if(k==='launchChild'&&recovering)return deny('RT_HOST_STARTUP_HOLD');
  const result=await host[k](...a);
  // A D03/SEC denial can occur before the transport is called. Still stop all
  // owned processes in the affected run tree; never leave them until wall time.
  if(result.status==='OUTCOME_UNKNOWN'||result.decision==='DENY')try{
   const run=result.run_id??(k==='launchChild'?parseIntent(a[0]).grant.run_id:a[0]);await process.terminate(run);
  }catch{}
  return publicView(result);
 }])));
 let checkpointTail=Promise.resolve();
 const bridge={contract:INT04_PROCESS_CONTRACT,runtime,native:createNativeHermesTransport(),startup:recovering?'HOLD':'E0_NEW_HOST',
  readOutput:ref=>process.readOutput(ref),inspectProcesses:()=>process.inspect(),
  checkpoint(run,file){const next=checkpointTail.then(async()=>{const runtimeCheckpoint=await host.checkpoint(run);need(!runtimeCheckpoint.decision,'RT_CHECKPOINT_RUNTIME_DENIED');
   const projection=process.snapshot(run);need(projection.request_hash===runtimeCheckpoint.request_hash,'RT_CHECKPOINT_BINDING');return writeProcessCheckpoint(file,{runtime:runtimeCheckpoint,process:projection});});checkpointTail=next.catch(()=>{});return next;},
  recover:file=>readProcessCheckpoint(file),close:()=>{closed=true;return process.close();},
  async invoke(text){try{
   const q=parseIntent(text);exact(q,['contract','method','run_id','request']);need(q.contract===INT04_PROCESS_CONTRACT,'RT_HOST_CONTRACT_VERSION');
   need(['launchChild','streamEvents','join','cancel','reconcile','checkpoint'].includes(q.method),'RT_HOST_METHOD');
   need(typeof q.run_id==='string','RT_HOST_RUN_ID');
   if(q.method==='launchChild'){need(typeof q.request==='string'&&parseIntent(q.request).grant.run_id===q.run_id,'RT_HOST_RUN_ID');}
   else need(q.request===null,'RT_HOST_REQUEST_FIELDS');
   const value=await runtime[q.method](q.method==='launchChild'?q.request:q.run_id);
   return freeze({contract:INT04_PROCESS_CONTRACT,result:value,physical_decision:'DENY'});
  }catch(e){return freeze({contract:INT04_PROCESS_CONTRACT,...deny(sanitized(e.message))});}}
 };return Object.freeze(bridge);
}
