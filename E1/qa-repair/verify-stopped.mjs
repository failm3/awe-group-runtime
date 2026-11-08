// One read-only reconciliation after the controller stopped and owner released the unfinished lease.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {digest} from '../contracts/index.mjs';
import {createPsqlSession,createCoordinator} from '../coordinator/index.mjs';
import {createCodingRunStore} from '../coordinator/coding-run.mjs';
import {PATCH_PROPOSAL_SCHEMA,validatePatchProposal} from '../executors/coding/contracts.mjs';
import {PROGRAM_PROFILE_DIGEST} from '../host/program-runner/profiles.mjs';
import {runProgram} from '../host/program-runner/runner.mjs';
import {evaluateComponent} from '../qa-coding/oracle.mjs';
import {inspectCommittedTrees} from '../qa-coding/git-readback.mjs';
import {sha256} from '../qa-coding/tree-proof.mjs';
import {checkPriorNative,checkAggregate,readOriginalTrees,priorRecord} from './prior.mjs';
import {checkHeadReceipt,checkStageAttempt,checkCode,checkRepairTree,actualPromptHash,inspectHead} from './bindings.mjs';
const root=fileURLToPath(new URL('../../',import.meta.url)),run='repair_normalize_01';
const read=file=>JSON.parse(fs.readFileSync(file,'utf8'));
function persistedModel(round,attempt){
  const scope={mission_id:attempt.mission_id,task_id:attempt.task_id,worker_id:attempt.worker_id,fence:String(attempt.fence),attempt_id:attempt.attempt_id,logical_request_id:attempt.logical_request_id};
  const dir=path.join(round,'recovery');
  const journal=read(path.join(dir,'model_'+digest(scope).slice(7)+'.json'));
  assert.equal(journal.state,'RESPONSE_PERSISTED');assert.equal(journal.scope_digest,digest(scope));
  function deref(ref){assert.match(ref,/^sha256:[a-f0-9]{64}$/);const v=read(path.join(dir,'obj_'+ref.slice(7)+'.json'));assert.equal(digest(v),ref);return v;}
  const model=deref(journal.response_ref),context=deref(journal.context_ref);
  assert.equal(digest(context),journal.context_digest);
  assert.equal(model.host_binding_digest,digest(model.native_receipt));
  assert.equal(digest(model.native_receipt.native_attempt),digest(attempt));
  assert.equal(model.native_receipt.response.evidence_level,'LIVE_LOCAL_MODEL');
  assert.equal(model.native_receipt.response.accounting_status,'CONFIRMED');
  assert.equal(model.native_receipt.response.request_hash,attempt.request_hash);
  assert.equal(actualPromptHash(model.native_receipt.input.instruction,PATCH_PROPOSAL_SCHEMA,2048),attempt.request_hash);
  assert.equal(digest(model.proposal),digest(model.native_receipt.response.output));
  return {model,response_ref:journal.response_ref,context_ref:journal.context_ref};
}
export async function inspectStopped(descriptor){
  assert.equal(path.resolve(descriptor),path.join(root,'.private','e1-resource.json'));
  const prior=priorRecord(), runRoot=path.join(root,'.private','repair-'+run), sup=read(path.join(root,'E1/coding/evidence','SUPERVISOR-'+run+'.json'));
  assert.equal(sup.status,'STOPPED');assert.equal(sup.run_id,run);assert.equal(sup.operator_phase_commands,0);
  const exits=sup.observed_exits,faults=[0,1].map(i=>read(path.join(runRoot,'FAULT-'+i+'.json')));
  assert.deepEqual(exits.map(e=>e.exit_code),[90,90,1]);assert.deepEqual(exits.map(e=>e.known_injected_fault),['AFTER_MODEL_PERSISTED','AFTER_NATIVE_COMPLETED',null]);
  assert.equal(new Set([sup.supervisor_pid,...exits.map(e=>e.pid)]).size,4);
  for(const [i,f] of faults.entries()){
    assert.equal(f.pid,exits[i].pid);assert.equal(f.supervisor_pid,sup.supervisor_pid);assert.equal(f.stage,exits[i].known_injected_fault);
    assert.equal(exits[i].original_process_observed_dead,true);assert.ok(Date.parse(f.at)<=Date.parse(exits[i].ended_at));
  }
  const config=read(path.join(runRoot,'config.json'));
  assert.equal(digest(config.source_pins),sup.source_digest);
  for(const pin of config.source_pins){assert.match(pin.path,/^E1\/(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_.-]+$/);assert.equal(sha256(fs.readFileSync(path.join(root,pin.path))),'sha256:'+pin.sha256);}
  const db=await createPsqlSession(read(descriptor),{role:'qa'});
  try{
    const project_id='prj_coding_'+run,mission_id='mission_coding_'+run;
    const cur=createCoordinator({db,project_id}),old=createCoordinator({db,project_id:prior.project_id}),store=createCodingRunStore({db,project_id});
    const priorS=await old.snapshot(),priorEvents=await old.events();const priorChecked=checkPriorNative(priorS,priorEvents);
    const original=readOriginalTrees(prior,priorChecked.t,priorChecked.artifact);
    const s=await cur.snapshot(),events=await cur.events(),row=await store.read(run);
    assert.equal(row.phase,'STOPPED');assert.equal(row.binding.source_digest,sup.source_digest);
    assert.equal(row.binding.prior_attempt_refs[0].attempt_id,prior.native_attempt.attempt_id);
    assert.equal(row.binding.prior_attempt_refs[0].result_hash,prior.result_hash);
    assert.equal(row.binding.oracle_digest,prior.oracle_commitment);assert.equal(row.binding.brief_digest,prior.issue_digest);
    assert.equal(row.binding.original_base_sha,prior.head_sha);
    const counts=checkAggregate(s,mission_id,prior);assert.equal(counts.total_wires,4);assert.equal(counts.remaining,0);
    assert.equal(row.counters.total,4);assert.equal(row.counters.unknown,0);assert.equal(row.counters.new_total,3);
    assert.equal(s.leases.length,0);const m=s.missions.find(x=>x.mission_id===mission_id);assert.equal(m.state,'CANCELLED');
    const pool=[...s.tasks,...s.task_history.map(x=>x.body)].filter(x=>x.mission_id===mission_id);
    const head=pool.find(x=>x.task_id==='head_plan'&&x.state==='ACCEPTED');
    assert.ok(head);assert.equal(head.result_hash,digest(head.result));checkHeadReceipt(head,checkStageAttempt(s,head));
    assert.equal(head.result.output.decision,'REPAIR');assert.equal(head.result.output.max_code_attempts,2);assert.ok(inspectHead(head.result.output));
    const r02=pool.find(x=>x.task_id==='code_r02'&&x.state==='FAILED'&&x.result_hash===faults[1].metadata.result_hash);
    assert.ok(r02);assert.equal(digest(r02.result),r02.result_hash);
    const a02=checkStageAttempt(s,r02),{a,output,producerPass}=checkCode(r02,a02,prior);
    assert.equal(a.base_sha,prior.head_sha);assert.equal(producerPass,false);
    assert.equal(faults[1].metadata.head_sha,a.head_sha);assert.equal(faults[1].metadata.tree_sha,a.tree_sha);
    for(const f of faults){for(const k of ['mission_id','task_id','worker_id','attempt_id','logical_request_id','fence'])assert.equal(String(f.metadata.scope[k]),String(a02[k]));}
    const round2=path.join(runRoot,'rounds','code_r02'),round3=path.join(runRoot,'rounds','code_r03');
    const cache2=persistedModel(round2,a02);assert.equal(cache2.response_ref,faults[0].metadata.response_ref);
    assert.equal(cache2.response_ref,a.model_receipt_digest);assert.equal(faults[0].metadata.context_digest,cache2.context_ref);
    const wt='wt_'+digest({base_sha:a.base_sha,branch:a.branch,grant_ref:'coding_'+run+'_code_r02'}).slice(7,39);
    const repaired=inspectCommittedTrees({repository_root:path.join(round2,'repository'),worktree_root:path.join(round2,'worktrees',wt),branch:a.branch,base_sha:a.base_sha,head_sha:a.head_sha});
    assert.equal(repaired.base.tree_sha,original.final.tree_sha);checkRepairTree(repaired,output,a);
    const rerun=await evaluateComponent({trees:{base:original.base,final:repaired.final},runProgram,profileDigest:PROGRAM_PROFILE_DIGEST});
    assert.equal(rerun.verdict,'FAIL');assert.equal(rerun.probes.find(p=>p.label==='cli').passed,false);
    const votes=events.filter(e=>e.task_id==='code_r02'&&e.mission_id===mission_id&&e.kind==='QA_FAIL'&&e.body.result_hash===r02.result_hash);
    assert.equal(votes.length,1);assert.equal(votes[0].body.evaluator_id,'e1_qa');
    assert.equal(events.filter(e=>e.task_id==='code_r02'&&e.kind==='RESULT_PROPOSED'&&e.body.result_hash===r02.result_hash).length,1);
    const r03=s.tasks.find(t=>t.is_current&&t.task_id==='code_r03'&&t.mission_id===mission_id);
    assert.equal(r03.state,'CANCELLED');assert.equal(r03.result,null);assert.equal(r03.result_hash,null);
    const a03=s.attempts.find(at=>at.task_id==='code_r03'),cache3=persistedModel(round3,a03), proposal3=cache3.model.proposal;
    assert.equal(proposal3.base_sha,a.head_sha);assert.equal(cache3.model.native_receipt.task_input_digest,digest(r03.document.input));
    const baseline={base_sha:a.head_sha,files:repaired.final.files.map(f=>({...f,ancestry_verified:true,ancestor_symlinks:false}))};
    assert.throws(()=>validatePatchProposal(proposal3,{grant:{base_sha:a.head_sha,path_allowlist:['cli.py','normalizer.py'],max_files:2,max_patch_bytes:32768},baseline}),err=>err.code==='CODING_NO_CHANGE');
    assert.equal(fs.readFileSync(path.join(round3,'repository','.git','refs','heads','main'),'utf8').trim(),a.head_sha);
    assert.equal(fs.existsSync(path.join(round3,'repository','.git','refs','heads','codex','coding_'+run+'_code_r03')),false);
    assert.equal(fs.readdirSync(path.join(round3,'git-journal')).filter(n=>/^wt_.*\.json$/.test(n)).length,0);
    assert.equal(events.filter(e=>e.task_id==='code_r03'&&['QA_PASS','RESULT_PROPOSED'].includes(e.kind)).length,0);
    const artifactRoot=path.join(root,'E1/coding/artifacts',run);
    let exportsVerified=false;
    if(fs.existsSync(artifactRoot)){
      // Failure evidence can be published after the first audit; final product files cannot.
      assert.deepEqual(fs.readdirSync(artifactRoot).sort(),['code_r02','code_r03-rejected-proposal.json']);
      const exportDir=path.join(artifactRoot,'code_r02');
      assert.deepEqual(fs.readdirSync(exportDir).sort(),['cli.py','normalizer.py']);
      for(const file of repaired.final.files)assert.equal(sha256(fs.readFileSync(path.join(exportDir,file.path))),file.digest);
      const rejected=read(path.join(artifactRoot,'code_r03-rejected-proposal.json'));
      assert.equal(rejected.status,'REJECTED_CODING_NO_CHANGE');assert.equal(rejected.source_edited_by_sol,false);
      assert.equal(rejected.native_attempt_id,a03.attempt_id);assert.equal(digest(rejected.proposal),digest(proposal3));
      assert.equal(digest(rejected.usage),digest(a03.usage));exportsVerified=true;
    }
    const product=s.tasks.find(t=>t.is_current&&t.task_id==='product_gate');assert.equal(product.state,'CANCELLED');assert.equal(product.result,null);
    const status={schema:'awe.qa-repair.final-stopped/1',status:'STOPPED_CAP_EXHAUSTED',verified_at:new Date().toISOString(),source_digest:sup.source_digest,qa_pid:process.pid,
      run_id:run,project_id,mission_id,native_mission_state:m.state,outer_phase:row.phase,outer_revision:row.revision,remaining:counts.remaining,aggregate:counts,
      original_g1:{state:'FAILED',result_hash:prior.result_hash,source_head:prior.head_sha,attempt:prior.native_attempt.attempt_id,qa_fail_events:1},
      head:{verdict:'ACCEPTED_BOUNDED_PLAN_ONLY',result_hash:head.result_hash,decision:head.result.output},
      code_r02:{state:'FAILED',artifact_digest:a.artifact_digest,head_sha:a.head_sha,tree_sha:a.tree_sha,result_hash:r02.result_hash,cache_ref:cache2.response_ref,
        original_public_exit:a.tests[0].program_receipt.exit_code,public_syntax_error:/SyntaxError/.test(a.tests[0].program_receipt.stderr),cold:rerun},
      code_r03:{state:'CANCELLED_AFTER_REJECTION',reason:'CODING_NO_CHANGE',response_ref:cache3.response_ref,proposal_digest:digest(proposal3),native_attempt:a03.attempt_id,worktree_created:false,new_commit:false},
      product_gate:{state:product.state,product_accepted:false},new_native_usage:s.attempts.map(a=>({task:a.task_id,id:a.attempt_id,usage:a.usage,cost:a.actual_cost,reserved:a.reserved,state:a.state})),
      scoped_process_recovery:{supervisor_pid:sup.supervisor_pid,children:exits.map(e=>({pid:e.pid,exit:e.exit_code,stage:e.known_injected_fault})),
        failure_points_exercised:2,task_result_proposed_once:true,one_confirmed_r02_wire:true,operator_phase_commands_before_stop:0,operator_post_stop_finalization:1,
        observation:'Two automatic child restarts after controlled exits; component did not pass'},
      editor_candidate_changes:0,known_original_source_pins_verified:config.source_pins.length,model_calls_by_verifier:0,new_paid_calls:0,external_effects:0,
      overall_component_pass:false,full_G2:'NOT_PROVEN',dynamic_agents:'NOT_TESTED',owner_accepted:false};
    const evidence='E1/qa-repair/evidence/STOPPED-'+run+'.json',dest=path.join(root,evidence);
    fs.mkdirSync(path.dirname(dest),{recursive:true});
    let preserved=false;
    try {fs.writeFileSync(dest,JSON.stringify(status,null,2)+'\n',{flag:'wx'});}
    catch(error){if(error.code!=='EEXIST')throw error;preserved=true;}
    const storedBytes=fs.readFileSync(dest);
    if(preserved){
      const before=JSON.parse(storedBytes);
      // An independent replay has its own process, nonce, clock and diagnostic-only sentinel tree.
      // Compare the durable run plus per-probe conclusions, keeping the first actual witness.
      for(const key of ['schema','status','source_digest','run_id','project_id','mission_id','native_mission_state','outer_phase','outer_revision','remaining','aggregate','original_g1','head','code_r03','product_gate','new_native_usage','scoped_process_recovery','overall_component_pass','owner_accepted']){
        assert.deepEqual(before[key],status[key],'existing witness: '+key);
      }
      const {cold:firstCold,...firstRound}=before.code_r02,{cold:replayCold,...replayRound}=status.code_r02;
      assert.deepEqual(firstRound,replayRound);
      assert.equal(firstCold.oracle_commitment,replayCold.oracle_commitment);
      assert.equal(firstCold.verdict,replayCold.verdict);
      const conclusions=cold=>cold.probes.map(({label,passed,matched,expected_to_match,tree_type,entrypoint,profile_digest,exit_code})=>({label,passed,matched,expected_to_match,tree_type,entrypoint,profile_digest,exit_code}));
      assert.deepEqual(conclusions(firstCold),conclusions(replayCold));
    }
    return {status:status.status,task02:r02.state,task03:r03.state,remaining:counts.remaining,native_model_wires:counts.total_wires,
      fault_restarts:2,live_leases:s.leases.length,new_model_calls:0,evidence,evidence_sha256:sha256(storedBytes),
      first_witness_preserved:preserved,full_read_only_replay:true,published_failure_exports_verified:exportsVerified};
  }finally{await db.close();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{assert.equal(process.argv.length,4);assert.equal(process.argv[2],run);console.log(JSON.stringify(await inspectStopped(process.argv[3])));}
  catch(e){console.error(JSON.stringify({status:'STOPPED_RECONCILIATION_INCOMPLETE',code:e.code??'QA_VERIFY_REJECT',check:e.stack?.match(/([a-z-]+\.mjs):(\d+):\d+/)?.slice(1).join(':')??'unknown'}));process.exitCode=1;}
}
