import {digest, inspectBoundSchema, need, validateBoundValue} from '../../contracts/index.mjs';

// A bounded repair-plan draft, not an unrestricted software planner. A1 remains
// responsible for turning this draft into an admitted exact-capability DAG.
export const REPAIR_HEAD_SCHEMA = inspectBoundSchema({type: 'object', properties: {
  decision: {type: 'string', minLength: 1, maxLength: 11, enum: ['REPAIR', 'BLOCK_SCOPE']},
  reason: {type: 'string', minLength: 1, maxLength: 512},
  focus: {type: 'string', minLength: 1, maxLength: 1024},
  max_code_attempts: {type: 'integer', minimum: 1, maximum: 2}
}, required: ['decision', 'reason', 'focus', 'max_code_attempts'], additionalProperties: false});
export const REPAIR_HEAD_SCHEMA_DIGEST = digest(REPAIR_HEAD_SCHEMA);
export const REPAIR_PRODUCT_SCHEMA = inspectBoundSchema({type: 'object', properties: {
  product_pass: {type: 'boolean'},
  head_sha: {type: 'string', minLength: 40, maxLength: 40, pattern: '^[a-f0-9]{40}$'},
  tree_sha: {type: 'string', minLength: 40, maxLength: 40, pattern: '^[a-f0-9]{40}$'},
  code_result_hash: {type: 'string', minLength: 71, maxLength: 71, pattern: '^sha256:[a-f0-9]{64}$'},
  oracle_digest: {type: 'string', minLength: 71, maxLength: 71, pattern: '^sha256:[a-f0-9]{64}$'},
  prior_result_hash: {type: 'string', minLength: 71, maxLength: 71, pattern: '^sha256:[a-f0-9]{64}$'}
}, required: ['product_pass', 'head_sha', 'tree_sha', 'code_result_hash', 'oracle_digest', 'prior_result_hash'], additionalProperties: false});
export const REPAIR_PRODUCT_SCHEMA_DIGEST = digest(REPAIR_PRODUCT_SCHEMA);

export function validateRepairHead(output) {
  validateBoundValue(REPAIR_HEAD_SCHEMA, output);
  need(!/(?:https?:\/\/|\b(?:authorization|password|secret|api[_-]?key)\s*[:=]|\.private|(?:^|[ /])(?:\.git|E1|awe)\/)/i.test(output.focus), 'REPAIR_HEAD_UNTRUSTED_SCOPE');
  return output;
}
