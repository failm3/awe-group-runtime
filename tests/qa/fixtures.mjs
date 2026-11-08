import {jointFixture} from '../integration_v2/harness.mjs';
import {must} from '../memory_artifacts/fixtures.mjs';
import {bytesHash,canonicalize,copy,digest} from '../../awe/qa/common.mjs';
import {createFixtureIssuer} from '../../awe/qa/authority.mjs';
import {createD03QaPort} from '../../awe/qa/state-port.mjs';
import {createQaService} from '../../awe/qa/service.mjs';
import {createD07ArtifactReader,createInt02EvidenceReader} from '../../awe/qa/ports.mjs';

// The host reuses real synthetic INT02 execution; QA receives no evaluator callback from the author.
export async function fixture(options={}) {
  const j=await jointFixture(options.joint), out=await j.workflow();
  if(!out.artifact_file) return {j,out};
  const h=j.f.h;
  let head={project_id:'prj_alpha',task_id:'task_one',artifact:copy(out.output.artifact),
    version:out.chain.rows[5].evidence.version,file_hash:out.artifact_file.content_hash,bytes:out.artifact_file.bytes,
    path:out.artifact_file.path,provenance_hash:out.chain.rows[5].evidence.provenance_hash};
  let chain=copy(out.chain),completion=copy(out.outcome),sources=[],opinions=null;
  const token=j.m.session('act_worker'), role=(name)=>({role:name,active:true,subject:'fixture-'+name,
    scopes:[{project_id:'prj_alpha',task_id:'task_one'}]});
  const principals={worker:role('EXECUTOR'),qa:role('EXAMINER'),auditor:role('AUDITOR'),owner:role('OWNER'),
    foreign:{...role('EXAMINER'),scopes:[{project_id:'prj_beta',task_id:'task_one'}]}};
  if(options.alias) principals.qa.subject=principals.worker.subject;
  if(options.ownerAlias) principals.owner.subject=principals.qa.subject;
  const issuer=createFixtureIssuer({principals,workerId:'worker',clock:()=>Date.parse(h.now())});
  const qaSession=issuer.control.session('qa'),ownerSession=issuer.control.session('owner');
  const statePort=createD03QaPort({state:h.service,storage:h.storage,reader:h.state,supervisor:h.supervisor,scope:j.f.taskScope,clock:h.now});
  const artifacts=createD07ArtifactReader({artifacts:j.m.artifacts,token,readHead:()=>head});
  const evidence=createInt02EvidenceReader({readChain:()=>chain,readCompletion:()=>completion,
    readModelOperation:()=>j.b.ledger.operation('op-one'),readSources:()=>sources,readOpinions:()=>opinions});
  const requirements={kind:'INT02_OUTPUT_V1',project_id:'prj_alpha',task_id:'task_one',spec:copy(j.f.task().spec),
    expected_text:'synthetic work result',expected_tools:[{id:'call_model',name:j.f.tool.id,arguments:copy(j.f.payload)}],
    citations:[],forbidden_literals:['FOREIGN_CANARY_SECRET'],...copy(options.requirements??{})};
  const make=(overrides={})=>createQaService({statePort,artifacts,evidence,issuer,requirements,initialReference:head,...overrides});
  const service=make();
  function grant(binding=service.binding(),session=qaSession,action='VERIFY',expires=Date.parse(h.now())+5000) {
    return issuer.control.grant(session,action,binding,expires);
  }
  async function report() { return service.worker.report({work:'WORK_COMPLETED',reference:head,expected_revision:service.inspect().revision}); }
  async function start(key='qa-first',g=grant(),session=qaSession) {
    const handle=await service.verifier.start(session,g,{expected_revision:service.inspect().revision,key});
    return {handle,grant:g,session};
  }
  async function finish(run) {return service.verifier.finish(run.session,run.grant,run.handle);}
  async function verify() {await report();const run=await start();return {...run,proof:await finish(run)};}
  async function accept(run,key='owner-first') {
    const g=grant(service.owner.binding(run.handle),ownerSession,'ACCEPT');
    return {record:await service.owner.accept(ownerSession,g,run.handle,{expected_revision:service.inspect().revision,key}),grant:g};
  }
  // Trusted adversarial fixture mutation: produces a real NEW immutable D07 artifact/version.
  // Chain hashes can be recomputed by the attacker; independent receipt/ledger/spec checks still apply.
  function replace(mutator,{rechain=true}={}) {
    const previous=JSON.parse(artifacts.read(head).toString('utf8'));mutator(previous);
    if(rechain) {
      if(previous.receipt) chain.rows[4].evidence=copy(previous.receipt);
      if(previous.model) chain.rows[2].evidence.model=copy(previous.model);
      chain.rows=chain.rows.slice(0,5).map((row,i,rows)=>{row.previous=i?rows[i-1].hash:null;const {hash,...body}=row;row.hash=digest(body);return row;});
      previous.chain={quarantined:false,rows:copy(chain.rows)};
    }
    const bytes=Buffer.from(canonicalize(previous));
    const output=j.m.stageArtifact('art_int02_output',j.m.files(bytes.toString()),{version:head.version+1});
    head={...head,artifact:output.reference.artifact,version:output.version,provenance_hash:output.provenance_hash,
      file_hash:bytesHash(bytes),bytes:bytes.length};
    if(rechain) {
      const body={sequence:5,kind:'D07_ARTIFACT',previous:chain.rows[4].hash,evidence:{reference:output.reference,version:output.version,
        provenance_hash:output.provenance_hash,file_hash:head.file_hash,readback:'SCOPED_E0_LOCAL_READ_ONLY',independent_qa:'NOT_RUN'}};
      chain.rows.push({...body,hash:digest(body)});
    }
    // Assert actual storage read, not a fabricated return DTO.
    must(j.m.artifacts.read(token,JSON.stringify({artifact_id:'art_int02_output',version:head.version,path:head.path})));
    return copy(head);
  }
  return {j,out,h,service,issuer,qaSession,ownerSession,statePort,artifacts,evidence,requirements,grant,report,start,finish,verify,accept,replace,make,
    get head(){return copy(head);},get chain(){return chain;},setCompletion(v){completion=v;},setSources(v){sources=copy(v);},setOpinions(v){opinions=v;}};
}
