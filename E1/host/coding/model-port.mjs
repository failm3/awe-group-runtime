import {digest, immutable, need} from '../../contracts/index.mjs';
import {MODEL_POLICY} from '../../broker/schemas.mjs';
import {PATCH_PROPOSAL_SCHEMA_DIGEST} from '../../executors/coding/contracts.mjs';
import {createRepositoryContext} from './repository-context.mjs';

/** Composition of actual A3 provenance and a separately read native D09 row.
 * The inner provider evidence remains LIVE_LOCAL_MODEL; it is never relabelled. */
export function createAccountedPatchModelPort({broker, spec, grant, capability_id = 'e1.coding.patch', verifyNativeAttempt, contextBuilder = createRepositoryContext()}) {
  need(broker && typeof broker.invoke === 'function' && typeof verifyNativeAttempt === 'function', 'CODING_NATIVE_MODEL_BINDING_REQUIRED');
  let lastReceipt = null;
  return Object.freeze({kind: 'ACCOUNTED_PATCH_MODEL_PORT', mode: 'LIVE_SCOPED_HOST', capability_id, route_id: MODEL_POLICY.route_id,
    get lastReceipt() { return lastReceipt; },
    async proposePatch({attempt_scope, issue, baseline, output_schema_digest, max_attempts, budget_cap_micros}) {
      need(output_schema_digest === PATCH_PROPOSAL_SCHEMA_DIGEST && max_attempts === 1 && budget_cap_micros === 0, 'CODING_MODEL_SCOPE');
      const context = contextBuilder.build({issue, baseline});
      const response = await broker.invoke({scope: attempt_scope, spec, grant, capability_id, input: {instruction: context.instruction}, data_label: 'CLEAN_CODE'});
      lastReceipt = immutable({response, native_attempt: null, context_digest: context.context_digest, scope: attempt_scope});
      const native = await verifyNativeAttempt({scope: attempt_scope, response});
      lastReceipt = immutable({response, native_attempt: native ?? null, context_digest: context.context_digest, scope: attempt_scope});
      if (response.accounting_status !== 'CONFIRMED' || response.decision !== 'PROPOSED') return immutable({
        decision: response.decision, reason: response.reason, accounting_status: response.accounting_status ?? 'NOT_RESERVED',
        wire_attempts: response.wire_attempts ?? 0, attempt_id: attempt_scope.attempt_id,
        logical_request_id: attempt_scope.logical_request_id, native_receipt: lastReceipt, evidence_level: 'LIVE_SCOPED_HOST'
      });
      need(response.evidence_level === 'LIVE_LOCAL_MODEL' && response.wire_attempts === 1 && response.model?.id === MODEL_POLICY.model && response.model?.digest === MODEL_POLICY.digest, 'CODING_PROVIDER_PROVENANCE');
      need(native && native.state === 'CONFIRMED' && native.attempt_id === attempt_scope.attempt_id && native.logical_request_id === attempt_scope.logical_request_id && native.mission_id === attempt_scope.mission_id && native.task_id === attempt_scope.task_id && native.worker_id === attempt_scope.worker_id && String(native.fence) === String(attempt_scope.fence) && native.route_id === MODEL_POLICY.route_id && native.request_hash === response.request_hash && Number(native.actual_cost) === 0 && digest(native.usage) === digest(response.usage), 'CODING_NATIVE_MODEL_RECEIPT');
      return immutable({proposal: response.output, accounting_status: 'CONFIRMED', wire_attempts: 1, route_id: native.route_id, attempt_id: native.attempt_id,
        actual_cost_micros: Number(native.actual_cost), usage: response.usage, model: response.model, evidence_level: 'LIVE_SCOPED_HOST',
        native_receipt: lastReceipt, host_binding_digest: digest(lastReceipt)});
    }
  });
}
