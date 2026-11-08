import {randomUUID} from 'node:crypto';
import {CONTRACT,ensure,exact,parse,requestShape,inputShape,identifier,digest,bytesDigest,freeze,copy,denial,scopeShape} from './protocol.mjs';
import {createScope,scopeInfo,writeScoped,readScoped,listScoped,closeScope} from './scope.mjs';
import {sourceFor,specShape} from './programs.mjs';
import {loadPins,runtimeDigest,verifyPins} from './pins.mjs';
import {runProgram,runCli,limitsShape,inspectProcesses} from './process.mjs';
import {verifyProgram,expectedStats} from './verification.mjs';
const BUILTINS=[['fs_read','fs.read'],['fs_write','fs.write'],['fs_list','fs.list'],['js_stats','js.text.stats'],['python_stats','python.text.stats'],['node_version','cli.node_version'],['git_version','cli.git_version'],['browser_snapshot','browser.snapshot'],['api_get','api.get']];
const adapter=cap=>cap.startsWith('fs.')?'scoped-fs/1':cap.startsWith('js.')?'js.template/1':cap.startsWith('python.')?'python.template/1':cap.startsWith('cli.')?'cli.fixed/1':cap.startsWith('browser.')?'browser.fixture/1':'api.fixture/1';
const watch=async(p,ms)=>{let t;try{return await Promise.race([p,new Promise((_,reject)=>{t=setTimeout(()=>reject(Error('TOOLS_PORT_TIMEOUT')),ms);})]);}finally{clearTimeout(t);}};
function manifestFor(id,cap,source,lock,limits){
 const input_schema={contract:'tools02.input/1',capability:cap,additionalProperties:false,max_text_utf8:4096};
 const output_schema={contract:'tools02.output/1',capability:cap,max_bytes:limits.max_output_bytes};
 return freeze({contract:'tools02.manifest/1',id,version:'1.0.0',capability:cap,adapter:adapter(cap),source_digest:source===null?null:bytesDigest(Buffer.from(source)),
  artifact_digest:runtimeDigest(lock),input_schema_hash:digest(input_schema),output_schema_hash:digest(output_schema),input_schema,output_schema,
  effect_class:cap==='fs.write'?'IDEMPOTENT_WRITE':'READ_ONLY',write_semantics:cap==='fs.write'?'CREATE_EXCLUSIVE':null,
  timeout_ms:limits.timeout_ms,max_output_bytes:limits.max_output_bytes,network_scope:'NONE',credential_policy:'FIXTURE_VALUES_ONLY',mode:'E0_LOCAL_SYNTHETIC'});
}
/** Trusted host assembly only. Admission and independent review are existing-owner
 * ports, never created from agent JSON. No issuer, task scheduler or retry ledger. */
export function createExecutableTools(options){
 exact(options,['scope','admission','reviewer','generator_id','limits']);scopeShape(options.scope);
 const {admission,reviewer,generator_id}=options;
 ensure(admission&&typeof admission.execute==='function'&&typeof admission.current==='function','TOOLS_ADMISSION_REQUIRED');
 ensure(identifier(generator_id),'TOOLS_GENERATOR');const limits=limitsShape(options.limits),lock=loadPins(),scope=freeze(copy(options.scope)),fsScope=createScope(scope);
 const entries=new Map(),candidates=new Map(),controllers=new Set(),jobs=new Set();let closed=false;
 const track=job=>{jobs.add(job);job.finally(()=>jobs.delete(job)).catch(()=>{});return job;};
 const alive=()=>ensure(!closed,'TOOLS_CLOSED');
 const add=(id,cap,source,provenance)=>{ensure(!entries.has(id),'TOOLS_ALREADY_REGISTERED');ensure(entries.size<32,'TOOLS_REGISTRATION_LIMIT');const manifest=manifestFor(id,cap,source,lock,limits);
  const e={manifest,pin:freeze({id,digest:digest(manifest)}),source,disabled:false,provenance};entries.set(id,e);return e.pin;};
 for(const [id,cap] of BUILTINS)add('tool_'+id,cap,cap==='js.text.stats'?sourceFor('JS'):cap==='python.text.stats'?sourceFor('PYTHON'):null,'REVIEWED_REPOSITORY_FIXTURE');
 const find=pin=>{exact(pin,['id','digest']);const e=entries.get(pin.id);ensure(e&&!e.disabled&&e.pin.digest===pin.digest,'TOOLS_PIN_DENIED');return e;};
 const current=binding=>{alive();const result=admission.current(binding);if(result?.then){Promise.resolve(result).catch(()=>{});throw Error('TOOLS_CURRENT_ASYNC');}ensure(result===true,'TOOLS_CURRENT_DENIED');};
 async function perform(e,input,barrier,signal){
  const cap=e.manifest.capability;
  if(cap.startsWith('js.')||cap.startsWith('python.')){
   const template=cap.endsWith('word_count')?'text.word_count.v1':'text.stats.v1';
   const r=await runProgram({lock,scope,language:cap.startsWith('js.')?'JS':'PYTHON',source:e.source,template,input,limits,beforeSpawn:barrier,signal});
   ensure(digest(r.output)===digest(expectedStats(input.text,template)),'TOOLS_READBACK');return r.output;
  }
  if(cap.startsWith('cli.'))return (await runCli({lock,scope,kind:cap,limits,beforeSpawn:barrier,signal})).output;
  verifyPins(lock,'node');barrier();
  if(cap==='fs.read'){const data=readScoped(fsScope,input.path);return {text:new TextDecoder('utf-8',{fatal:true}).decode(data),bytes:data.length,digest:bytesDigest(data)};}
  if(cap==='fs.write')return writeScoped(fsScope,input.path,input.text);
  if(cap==='fs.list')return {files:listScoped(fsScope)};
  if(cap==='browser.snapshot')return {fixture_id:'welcome',title:'Synthetic welcome',text:'AWE local fixture',dom_digest:bytesDigest(Buffer.from('<h1>AWE local fixture</h1>')),network_requests:0};
  if(cap==='api.get')return {fixture_id:'inventory',status:200,body:{items:[{id:'item_fixture',quantity:2}]},network_requests:0};
  throw Error('TOOLS_ADAPTER');
 }
 async function execute(text){
  let attempted=false,controller,live=true,used=false,workDone=false,output,q;const effectJobs=new Set();
  try{alive();q=requestShape(parse(text));ensure(q.scope.project_id===scope.project_id&&q.scope.task_id===scope.task_id&&q.scope.operation_id!==scope.operation_id,'TOOLS_SCOPE_DENIED');
   const e=find(q.pin),input=inputShape(e.manifest.capability,q.input),binding=freeze({...copy(q),manifest_digest:q.pin.digest,artifact_digest:e.manifest.artifact_digest,capability:e.manifest.capability});
   controller=new AbortController();controllers.add(controller);
   const doEffect=async()=>{
    ensure(live&&!used,'TOOLS_EFFECT_REPLAY');used=true;
    const barrier=()=>{ensure(live&&!controller.signal.aborted,'TOOLS_CANCELLED');find(q.pin);current(binding);attempted=true;};
    output=await perform(e,input,barrier,controller.signal);ensure(live,'TOOLS_LATE_RESULT');
    ensure(Buffer.byteLength(JSON.stringify(output))<=limits.max_output_bytes,'TOOLS_OUTPUT_LIMIT');
    current(binding);workDone=true;return freeze({output_digest:digest(output),local_execution:true});
   };
   const effect=()=>{const job=doEffect();effectJobs.add(job);job.catch(()=>{});return job;};
   // Host owns durable admission, mark-sent and completion. Only its callback can enter the adapter.
   const ack=await watch(Promise.resolve().then(()=>admission.execute(binding,effect)),limits.timeout_ms+1000);
   exact(ack,['status','request_digest']);ensure(ack.status==='COMMITTED'&&ack.request_digest===digest(binding)&&used&&workDone,'TOOLS_ADMISSION_ACK');
   current(binding);return freeze({contract:CONTRACT,decision:'EXECUTED_LOCAL',outcome:'CONFIRMED',run_id:q.run_id,actor_id:q.actor_id,scope:q.scope,pin:q.pin,input_hash:q.input_hash,
    output,output_hash:digest(output),physical_decision:'DENY',external_requests:0,retry_allowed:false,authoritative_complete:false,qa:'NOT_RUN'});
  }catch(error){return attempted?freeze({contract:CONTRACT,decision:'OUTCOME_UNKNOWN',code:denial(error).code,scope:q?.scope??null,physical_decision:'DENY',retry_allowed:false,output:null}):denial(error);}
  finally{live=false;controller?.abort();await Promise.allSettled([...effectJobs]);if(controller)controllers.delete(controller);}
 }
 const view=c=>freeze({id:c.id,spec:copy(c.spec),status:c.status,source_digest:c.source_digest,source_path:scopeInfo(c.directory).root+'/'+c.file,source:readScoped(c.directory,c.file).toString('utf8'),test_evidence:c.smoke??null,verification_evidence:c.verification??null,manifest_digest:digest(c.manifest)});
 const get=id=>{alive();const c=candidates.get(id);ensure(c,'TOOLS_CANDIDATE');return c;};
 const read=c=>{const source=readScoped(c.directory,c.file).toString('utf8');ensure(source===sourceFor(c.spec.language,c.spec.template)&&bytesDigest(Buffer.from(source))===c.source_digest,'TOOLS_CANDIDATE_DRIFT');return source;};
 const stage=async(id,from,to,action)=>{const c=get(id);ensure(c.status===from&&!c.busy,'TOOLS_FACTORY_STATE');c.busy=true;
  try{const result=await action(c);alive();c.status=to;return result;}catch(e){c.status='QUARANTINED';throw e;}finally{c.busy=false;}};
 const factory=Object.freeze({
  generate(spec){alive();spec=specShape(copy(spec));ensure(!entries.has(spec.tool_id),'TOOLS_ALREADY_REGISTERED');
   ensure(candidates.size<16,'TOOLS_CANDIDATE_LIMIT');
   const id='candidate_'+randomUUID(),directory=createScope(scope),source=sourceFor(spec.language,spec.template),file=spec.language==='JS'?'candidate.mjs':'candidate.py';writeScoped(directory,file,source);
   const cap=(spec.language==='JS'?'js.':'python.')+(spec.template==='text.stats.v1'?'text.stats':'text.word_count');
   const c={id,spec,directory,file,source_digest:bytesDigest(Buffer.from(source)),manifest:manifestFor(spec.tool_id,cap,source,lock,limits),status:'GENERATED',busy:false};candidates.set(id,c);return view(c);
  },
  test:id=>track(stage(id,'GENERATED','TESTED',async c=>{c.smoke=await verifyProgram({lock,scope,language:c.spec.language,source:read(c),template:c.spec.template,limits,phase:'SMOKE'});read(c);return c.smoke;})),
  verify:id=>track(stage(id,'TESTED','VERIFIED',async c=>{
   ensure(reviewer&&identifier(reviewer.identity)&&reviewer.identity!==generator_id&&typeof reviewer.review==='function','TOOLS_INDEPENDENT_REVIEW_REQUIRED');
   const source=read(c);c.verification=await verifyProgram({lock,scope,language:c.spec.language,source,template:c.spec.template,limits,phase:'INDEPENDENT_CHALLENGES'});
   const report=freeze({contract:'tools02.review/1',candidate_id:c.id,generator_id,reviewer_id:reviewer.identity,source_digest:c.source_digest,smoke_digest:digest(c.smoke),verification_digest:digest(c.verification),manifest_digest:digest(c.manifest)});
   const ack=await watch(Promise.resolve().then(()=>reviewer.review(copy(report))),2500);
   exact(ack,['decision','report_digest']);ensure(ack.decision==='APPROVE_SYNTHETIC_TEMPLATE'&&ack.report_digest===digest(report),'TOOLS_REVIEW_DENIED');read(c);c.review=report;return report;
  })),
  register(id){const c=get(id);ensure(c.status==='VERIFIED'&&!c.busy&&c.review,'TOOLS_FACTORY_STATE');const source=read(c);
   ensure(c.review.source_digest===c.source_digest&&c.review.manifest_digest===digest(c.manifest),'TOOLS_REVIEW_BINDING');verifyPins(lock,'node');
   const pin=add(c.spec.tool_id,c.manifest.capability,source,'INDEPENDENT_SYNTHETIC_REVIEW');c.status='REGISTERED';return pin;},
  inspect:id=>view(get(id))
 });
 const api={contract:CONTRACT,
  execute:text=>track(execute(text)),
  check(pins){try{alive();ensure(Array.isArray(pins)&&pins.length<=32&&new Set(pins.map(p=>p.id)).size===pins.length,'TOOLS_PINS');pins.forEach(find);return true;}catch{return false;}},
  resolve(capability){alive();const found=[...entries.values()].filter(e=>!e.disabled&&e.manifest.capability===capability);ensure(found.length>0,'TOOLS_CAPABILITY_MISSING');return found.map(e=>e.pin);},
  manifest(pin){return find(pin).manifest;},
  inspect:()=>freeze({mode:'E0_LOCAL_SYNTHETIC',registered:[...entries.values()].map(e=>({pin:e.pin,capability:e.manifest.capability,disabled:e.disabled,provenance:e.provenance})),processes:inspectProcesses(),scope:scopeInfo(fsScope),production_ready:false}),
  quarantine(id){alive();ensure(entries.has(id),'TOOLS_PIN_DENIED');entries.get(id).disabled=true;},factory,
  async close(){if(closed)return;closed=true;for(const c of controllers)c.abort();await Promise.allSettled([...jobs]);
   // Factory review/test calls are host-only and must be joined before closing the host.
   ensure(![...candidates.values()].some(c=>c.busy),'TOOLS_FACTORY_BUSY');for(const c of candidates.values())closeScope(c.directory);closeScope(fsScope);}
 };return Object.freeze(api);
}
