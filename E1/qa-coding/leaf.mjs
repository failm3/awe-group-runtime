import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
import {createAuthorityClient} from '../coordinator/authority-server.mjs';
import {runProgram} from '../host/program-runner/runner.mjs';
import {PROGRAM_PROFILE_DIGEST} from '../host/program-runner/profiles.mjs';
import {evaluateComponent} from './oracle.mjs';
import {inspectNative} from './native-review.mjs';
import {inspectCommittedTrees} from './git-readback.mjs';
import {verifyTrees} from './tree-proof.mjs';

export async function evaluateWaitingTask({url, token, binding, git}) {
  const client = createAuthorityClient({url, token});
  const {artifact, proposal, attempt} = inspectNative(await client.snapshot(), binding, 'WAIT_QA');
  const trees = inspectCommittedTrees({...git, ...{branch:artifact.branch,base_sha:artifact.base_sha,head_sha:artifact.head_sha}});
  assert.equal(trees.final.tree_sha,artifact.tree_sha);
  verifyTrees(trees, proposal, artifact);
  const tested = await evaluateComponent({trees,runProgram,profileDigest:PROGRAM_PROFILE_DIGEST});
  const checks = ['schema','sources','scope'].map(check_id => ({check_id, passed: check_id === 'sources' ? tested.verdict === 'PASS' : true}));
  const qa = {verdict:tested.verdict, checks, artifact_digest:artifact.artifact_digest, rubric_digest:artifact.rubric_digest,
    producer_id:artifact.producer_id, evaluator_id:'e1_qa', accepted:false};
  const value = await client.qaEvaluate({...binding, verdict:qa.verdict, checks});
  assert.equal(value.status, qa.verdict === 'PASS' ? 'ACCEPTED' : 'FAILED');
  return {type:'EVALUATED', pid:process.pid, qa, evaluation:{...tested,checks}, value,
    receipt:{schema:'awe.g1.independent-component-qa/1', ...binding, base_sha:artifact.base_sha, head_sha:artifact.head_sha,
      tree_sha:artifact.tree_sha, native_attempt_id:attempt.attempt_id, oracle_commitment:tested.oracle_commitment,
      probes:tested.probes, verdict:qa.verdict, accepted:false, adaptive_repair:'NOT_TESTED', external_effects:0}};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.once('message', async message => {
    try { process.send?.(await evaluateWaitingTask(message)); }
    catch (error) {
      process.send?.({type:'ERROR',pid:process.pid,code:'QA_CODING_BINDING_OR_RUNNER_FAILED',
        check: error.stack?.split('\n').find(line => line.includes('/qa-coding/') || line.includes('\\qa-coding\\'))?.match(/([a-z-]+\.mjs):(\d+):\d+/)?.slice(1).join(':') ?? 'unknown'});
    }
  });
  process.on('disconnect', () => process.exit(0));
  process.send?.({type:'QA_READY',pid:process.pid});
}
