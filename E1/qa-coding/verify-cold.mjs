// Explicit operator command only; open the isolated E1 descriptor as QA, then replay in a fresh process.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createPsqlSession,createCoordinator} from '../coordinator/index.mjs';
import {verifyColdReader} from './cold-readback.mjs';
import {digest} from '../contracts/index.mjs';
import {sha256} from './tree-proof.mjs';

const root = fileURLToPath(new URL('../../',import.meta.url));
const json = filename => JSON.parse(fs.readFileSync(filename,'utf8'));
export async function runColdCommand(runId, resourceFile) {
  assert.match(runId,/^[a-z][a-z0-9_]{0,39}$/);
  const reportFile = path.join(root,'E1','coding','evidence',runId+'.json');
  const bytes = fs.readFileSync(reportFile), report=JSON.parse(bytes);
  assert.equal(report.run_id,runId);
  assert.equal(report.status,'PASS_LIVE_MULTI_FILE_G1');
  assert.equal(report.qa.qa.verdict,'PASS');
  assert.equal(report.outcome.decision,'DRAFT_PR_INTENT');
  assert.equal(report.outcome.intent_digest,digest(report.outcome.intent));
  assert.match(report.outcome.worktree_id,/^wt_[a-f0-9]{32}$/);
  const resourcePath=path.resolve(resourceFile);
  assert.equal(resourcePath,path.join(root,'.private','e1-resource.json'));
  const resource=json(resourcePath);
  const runRoot=path.join(root,'.private','coding-'+runId);
  const persisted=json(path.join(runRoot,'intents',report.outcome.intent_digest.slice(7)+'.json'));
  assert.equal(persisted.external_mutations,0);
  assert.equal(persisted.status,'DRAFT_PR_INTENT');
  assert.equal(digest(persisted.intent),report.outcome.intent_digest);
  assert.equal(digest(persisted.qa),report.outcome.intent.qa_digest);
  const db=await createPsqlSession(resource,{role:'qa'});
  try {
    const client=createCoordinator({db,project_id:report.fixture.spec.project_id});
    const {mission_id,task_id,plan_digest,result_hash}=report.qa.receipt;
    const review=await verifyColdReader(client,{binding:{mission_id,task_id,plan_digest,result_hash},
      git:{repository_root:path.join(runRoot,'repository'),worktree_root:path.join(runRoot,'worktrees',report.outcome.worktree_id)},
      previous_qa_pid:report.qa.pid, receipt:report.qa.receipt, local_intent:persisted.intent});
    const dest=path.join(root,'E1','qa-coding','evidence','COLD-'+runId+'.json');
    const data={...review,run_id:runId,role:'awe_e1_qa',observed_at:new Date().toISOString(),runtime_report_sha256:sha256(bytes)};
    fs.mkdirSync(path.dirname(dest),{recursive:true});
    fs.writeFileSync(dest,JSON.stringify(data,null,2)+'\n',{flag:'wx'});
    return {status:review.status,scope:review.scope,run_id:runId,head_sha:review.head_sha,tree_sha:review.tree_sha,probes:review.replay.probes.length,new_model_calls:0,external_effects:0};
  } finally {await db.close();}
}
if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {
    assert.equal(process.argv.length,4);
    console.log(JSON.stringify(await runColdCommand(process.argv[2], process.argv[3])));
  } catch(error) {
    console.error(JSON.stringify({status:'COLD_BLOCKED',code:error.code?.startsWith('A2_')?error.code:'QA_COLD_REJECTED',check:error.stack?.match(/([a-z-]+\.mjs):(\d+):\d+/)?.slice(1).join(':') ?? 'unknown'}));
    process.exitCode=1;
  }
}
