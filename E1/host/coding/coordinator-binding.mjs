import {digest, immutable, need, validateBoundValue} from '../../contracts/index.mjs';
import {PATCH_PROPOSAL_SCHEMA, PATCH_PROPOSAL_SCHEMA_DIGEST} from '../../executors/coding/contracts.mjs';

export function rawPatchProposal(patch) {
  const raw = {base_sha: patch.base_sha, summary: patch.summary, changes: patch.changes.map(({path, before_digest, after_text}) => ({path, before_digest, after_text}))};
  return validateBoundValue(PATCH_PROPOSAL_SCHEMA, raw);
}

/** Native completion is separate from semantic acceptance. A valid failed-test
 * artifact may enter WAIT_QA as truthful evidence, never as product success. */
export async function completeCodingResult(client, scope, {proposal, artifact, model_receipt, product_status = 'PENDING_INDEPENDENT_QA'}) {
  need(client && typeof client.complete === 'function', 'CODING_NATIVE_COMPLETION_REQUIRED');
  const output = validateBoundValue(PATCH_PROPOSAL_SCHEMA, proposal ?? rawPatchProposal(artifact.patch));
  need(artifact && artifact.patch && digest(output) === digest(rawPatchProposal(artifact.patch)), 'CODING_NATIVE_PATCH_BINDING');
  const result = immutable({output_schema_digest: PATCH_PROPOSAL_SCHEMA_DIGEST, output, artifact_digest: digest(output),
    evidence: {coding_artifact: artifact, model_receipt, product_status}});
  const result_hash = digest(result);
  const value = await client.complete({...scope, result, result_hash});
  need(value?.status === 'WAIT_QA', 'CODING_NATIVE_WAIT_QA_REQUIRED');
  return immutable({result, result_hash, value});
}

export function createCodingCoordinatorBinding({client, scope, verifyNativeTask}) {
  need(typeof verifyNativeTask === 'function', 'CODING_NATIVE_TASK_READER_REQUIRED');
  let completed = null;
  return Object.freeze({
    get completion() { return completed; },
    async complete({proposal, artifact, model_receipt, product_status}) {
      if (completed) { need(completed.result.evidence.coding_artifact.artifact_digest === artifact.artifact_digest, 'CODING_NATIVE_RESULT_CHANGED'); return completed; }
      completed = await completeCodingResult(client, scope, {proposal, artifact, model_receipt, product_status});
      const task = await verifyNativeTask(scope);
      need(task?.state === 'WAIT_QA' && task.result_hash === completed.result_hash && digest(task.result) === completed.result_hash, 'CODING_NATIVE_RESULT_READBACK');
      return completed;
    }
  });
}
