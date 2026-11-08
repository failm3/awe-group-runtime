import assert from 'node:assert/strict';
import {readFileSync,mkdirSync,writeFileSync} from 'node:fs';
import path from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {createPsqlSession,createCoordinator} from '../coordinator/index.mjs';
import {createCodingRunStore} from '../coordinator/coding-run.mjs';
import {digest} from '../contracts/index.mjs';
import {sha256} from '../qa-coding/tree-proof.mjs';
import {inspectSupervisor} from './supervision.mjs';
import {priorRecord} from './prior.mjs';
import {verifyRepairCold} from './cold.mjs';

const root=fileURLToPath(new URL('../../',import.meta.url));
const read=p=>JSON.parse(readFileSync(p,'utf8'));
export async function inspectCompletedRun(runId,descriptor){
  assert.match(runId,/^[a-z][a-z0-9_]{0,39}$/);
  assert.equal(path.resolve(descriptor),path.join(root,'.private','e1-resource.json'));
  const filename=path.join(root,'E1','coding','evidence','REPAIR-'+runId+'.json'),bytes=readFileSync(filename),report=JSON.parse(bytes);
  assert.equal(report.schema,'awe.e1.two-file-bounded-repair/1');
  assert.equal(report.status,'TWO_FILE_BOUNDED_REPAIR_PASS');assert.equal(report.run_id,runId);
  assert.equal(report.source_digest,digest(report.source_pins));
  for(const f of report.source_pins){
    assert.match(f.path,/^E1\/(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_.-]+$/);
    assert.equal(sha256(readFileSync(path.join(root,f.path))),'sha256:'+f.sha256);
  }
  const host=read(path.join(root,'E1','coding','evidence','SUPERVISOR-'+runId+'.json'));
  const recovery=inspectSupervisor({state:host,faults:report.fault_witnesses,runId,sourceDigest:report.source_digest});
  assert.deepEqual(report.supervised_child_faults,host.observed_exits.slice(0,2));
  const prior=priorRecord(),project_id=report.fixture.spec.project_id;
  const db=await createPsqlSession(read(descriptor),{role:'qa'});
  try{
    const store=createCodingRunStore({db,project_id}),client=createCoordinator({db,project_id}),priorClient=createCoordinator({db,project_id:prior.project_id});
    const row=await store.read(runId);assert.equal(row.binding_digest,report.outer.binding_digest);assert.equal(row.binding.source_digest,report.source_digest);
    const codeId=row.state.refs.code_task_id;assert.ok(['code_r02','code_r03'].includes(codeId));
    const snapshot=await client.snapshot(),code=snapshot.tasks.find(t=>t.is_current&&t.task_id===codeId&&t.mission_id===row.mission_id);
    assert.ok(code);assert.equal(digest(report.final_code),code.result_hash);
    const artifact=code.result.evidence.coding_artifact,ref='coding_'+runId+'_'+codeId;
    const wt='wt_'+digest({base_sha:artifact.base_sha,branch:artifact.branch,grant_ref:ref}).slice(7,39);
    const round=path.join(root,'.private','repair-'+runId,'rounds',codeId);
    const git={repository_root:path.join(round,'repository'),worktree_root:path.join(round,'worktrees',wt)};
    const cold=await verifyRepairCold({client,priorClient,store,run_id:runId,git,prior_qa_pid:report.final_product_qa.pid});
    const snapshots=[...snapshot.tasks,...snapshot.task_history.map(h=>h.body)];
    const [f1,f2]=report.fault_witnesses.map(f=>f.metadata);
    assert.equal(f1.accounting_status,'CONFIRMED');for(const key of ['mission_id','task_id','worker_id','fence','attempt_id','logical_request_id'])assert.equal(String(f1.scope[key]),String(f2.scope[key]));
    assert.equal(f1.scope.mission_id,row.mission_id);
    const interrupted=snapshots.find(t=>t.mission_id===row.mission_id&&t.task_id===f2.scope.task_id&&t.result_hash===f2.result_hash);
    assert.ok(interrupted);assert.equal(digest(interrupted.result),interrupted.result_hash);
    assert.equal(f1.response_ref,digest(interrupted.result.evidence.model_receipt));
    assert.equal(f2.head_sha,interrupted.result.evidence.coding_artifact.head_sha);
    assert.equal(f2.tree_sha,interrupted.result.evidence.coding_artifact.tree_sha);
    const attempts=snapshot.attempts.filter(a=>a.mission_id===row.mission_id&&a.task_id===f2.scope.task_id);
    assert.equal(attempts.length,1);assert.equal(attempts[0].state,'CONFIRMED');
    for(const key of ['worker_id','fence','logical_request_id','attempt_id'])assert.equal(String(attempts[0][key]),String(f2.scope[key]));
    const records=await client.events({});
    const complete=records.filter(e=>e.kind==='RESULT_PROPOSED'&&e.task_id===interrupted.task_id&&e.mission_id===row.mission_id&&e.body.result_hash===interrupted.result_hash);
    assert.equal(complete.length,1);
    const intent=report.local_intent;
    assert.equal(intent.head_sha,artifact.head_sha);assert.equal(intent.artifact_digest,artifact.artifact_digest);
    assert.equal(intent.draft,true);assert.equal(intent.automatic_merge,false);assert.equal(intent.production_release,false);
    const intentFile=read(path.join(round,'intents',digest(intent).slice(7)+'.json'));
    assert.equal(intentFile.external_mutations,0);assert.equal(intentFile.intent_digest,digest(intent));
    assert.equal(digest(intentFile.intent),digest(intent));assert.equal(digest(intentFile.qa),intent.qa_digest);
    const out={...cold,observed_at:new Date().toISOString(),runtime_report_sha256:sha256(bytes),
      conclusion:'TWO_FILE_BOUNDED_REPAIR_WITH_AUTOMATIC_CHILD_RECOVERY',local_intent_digest:digest(intent),
      controller_recovery:{...recovery,interrupted_task:interrupted.task_id,interrupted_attempt:attempts[0].attempt_id,persisted_model_digest:f1.response_ref,interrupted_result_hash:f2.result_hash,
        corresponding_native_results:complete.length,corresponding_model_wires:attempts.length}};
    const dest=path.join(root,'E1','qa-repair','evidence','COLD-'+runId+'.json');
    mkdirSync(path.dirname(dest),{recursive:true});writeFileSync(dest,JSON.stringify(out,null,2)+'\n',{flag:'wx'});
    return {status:out.status,conclusion:out.conclusion,run_id:runId,aggregate:out.aggregate,faults:recovery.fault_stages,
      original_G1:'FAILED_PRESERVED',full_G2:'NOT_PROVEN',new_model_calls:0,external_effects:0};
  }finally{await db.close();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{assert.equal(process.argv.length,4);console.log(JSON.stringify(await inspectCompletedRun(process.argv[2],process.argv[3])));}
  catch(e){console.error(JSON.stringify({status:'COLD_REPAIR_NOT_PROVEN',code:e.code??'QA_REPAIR_READBACK_REJECTED',check:e.stack?.match(/([a-z-]+\.mjs):(\d+):\d+/)?.slice(1).join(':')??'unknown'}));process.exitCode=1;}
}
