import assert from 'node:assert/strict';
import {createAuthorityClient} from '../coordinator/authority-server.mjs';
import {digest} from '../contracts/index.mjs';
import {runProgram} from '../host/program-runner/runner.mjs';
import {PROGRAM_PROFILE_DIGEST} from '../host/program-runner/profiles.mjs';
import {evaluateComponent} from './oracle.mjs';
import {inspectCommittedTrees} from './git-readback.mjs';
import {verifyTrees} from './tree-proof.mjs';
import {inspectNative} from './native-review.mjs';

// Invoke from a new QA process with a fresh QA-scoped reader. This function never submits a verdict.
export async function coldReadback(options) {
  return verifyColdReader(createAuthorityClient({url:options.url,token:options.token}),options);
}

export async function verifyColdReader(client,{binding,git,previous_qa_pid,receipt,local_intent}) {
  assert.ok(Number.isSafeInteger(previous_qa_pid) && previous_qa_pid !== process.pid);
  const snapshot = await client.snapshot(), events = await client.events({});
  const {artifact, proposal, attempt} = inspectNative(snapshot,binding,'ACCEPTED');
  const mission = snapshot.missions.find(row => row.mission_id === binding.mission_id);
  assert.equal(mission.state,'COMPLETE');
  assert.equal(receipt.verdict,'PASS');
  assert.equal(receipt.result_hash,binding.result_hash);
  assert.equal(receipt.plan_digest,binding.plan_digest);
  assert.equal(receipt.native_attempt_id,attempt.attempt_id);
  assert.equal(receipt.tree_sha,artifact.tree_sha);
  const qaEvents = events.filter(event => event.mission_id === binding.mission_id && event.task_id === binding.task_id && event.kind === 'QA_PASS');
  assert.equal(qaEvents.length,1);
  assert.equal(qaEvents[0].body.result_hash,binding.result_hash);
  assert.equal(qaEvents[0].body.evaluator_id,'e1_qa');
  assert.notEqual(qaEvents[0].body.evaluator_id,artifact.producer_id);
  // This is a local preparatory intent. Its existence is verified through a separate host journal read.
  assert.equal(local_intent.intent_kind,'DRAFT_PR');
  assert.equal(local_intent.artifact_digest,artifact.artifact_digest);
  assert.equal(local_intent.head_sha,artifact.head_sha);
  assert.equal(local_intent.base_sha,artifact.base_sha);
  assert.equal(local_intent.branch,artifact.branch);
  assert.equal(local_intent.draft,true);
  assert.equal(local_intent.automatic_merge,false);
  assert.equal(local_intent.production_release,false);
  const trees = inspectCommittedTrees({...git,branch:artifact.branch,base_sha:artifact.base_sha,head_sha:artifact.head_sha});
  assert.equal(trees.final.tree_sha, artifact.tree_sha);
  verifyTrees(trees,proposal,artifact);
  const replay = await evaluateComponent({trees,runProgram,profileDigest:PROGRAM_PROFILE_DIGEST});
  assert.equal(replay.verdict,'PASS');
  for (const probe of replay.probes.filter(probe => probe.label !== 'cli_calls_library')) {
    const previous = receipt.probes.find(row => row.label === probe.label);
    assert.ok(previous?.passed);
    for (const field of ['tested_head_sha','tested_tree_sha','entrypoint','input_digest','expected_digest','matched']) {
      assert.equal(probe[field],previous[field]);
    }
    assert.notEqual(probe.invocation_id,previous.invocation_id);
  }
  return {schema:'awe.g1.independent-cold-coding-review/1',status:'PASS',scope:'ONE_SHOT_LOCAL_TWO_FILE_COMPONENT',
    ...binding, inspector_pid:process.pid, prior_qa_pid:previous_qa_pid, head_sha:artifact.head_sha, tree_sha:artifact.tree_sha,
    base_sha:artifact.base_sha, source_digests:trees.final.files.map(({path,blob_sha,digest})=>({path,blob_sha,digest})),
    actual_model:{route:attempt.route_id,usage:attempt.usage,actual_cost:attempt.actual_cost,attempt_id:attempt.attempt_id},
    native_qa_event_result:qaEvents[0].body.result_hash, pending_local_intent_digest:digest(local_intent),
    observed_git:'READ_ONLY_RAW_COMMIT_TREE_BLOB_REFS', replay, cloud_calls:0, new_model_calls:0,
    external_effects:0, owner_accepted:false, adaptive_repair:'NOT_TESTED', dynamic_agents:'NOT_TESTED'};
}
