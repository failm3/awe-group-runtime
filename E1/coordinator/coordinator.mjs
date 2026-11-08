import {digest, canonicalize, validateBoundValue} from '../contracts/index.mjs';
import {check, integer} from './errors.mjs';
import {admissionPort} from './admission.mjs';
import {validateLocalModelQuiescence} from './quiescence.mjs';

/** Project-scoped view of the one D03/D09 transaction domain. Only the authority
 * owns this object/session. Leaves receive an RPC client, never this DB port.
 */
export function createCoordinator({db, admission, project_id}) {
  check(db?.kind === 'NATIVE_POSTGRESQL_PSQL_SESSION' && typeof db.command === 'function', 'A2_NATIVE_DB_REQUIRED');
  check(typeof project_id === 'string' && /^[a-z][a-z0-9_.-]{0,79}$/.test(project_id), 'A2_PROJECT_REQUIRED');
  const scope = request => { check(request && typeof request === 'object' && (!request.project_id || request.project_id === project_id), 'A2_PROJECT_SCOPE'); return {...request, project_id}; };
  const invoke = (op, request = {}) => db.command(op, scope(request));
  function attempt(request) {
    for (const key of ['mission_id','task_id','logical_request_id','attempt_id','worker_id']) check(typeof request[key] === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/.test(request[key]), 'A2_ATTEMPT_ID');
    integer(request.fence,'A2_FENCE'); check(BigInt(request.fence) > 0n, 'A2_FENCE'); return request;
  }
  async function snapshot() { return invoke('snapshot'); }
  const api = {
    kind: 'AWE_E1_DURABLE_COORDINATOR', project_id,
    async admit(request, context) { const payload = await admissionPort(admission)(request, context); check(payload.project_id === project_id,'A2_PROJECT_SCOPE'); return invoke('admit',payload); },
    claim(request) { check(Array.isArray(request.capabilities) && request.capabilities.length > 0 && request.capabilities.length <= 128, 'A2_CLAIM_CAPABILITIES'); return invoke('claim',{...request,lease_ms:request.lease_ms ?? 5000}); },
    heartbeat(request) { return invoke('heartbeat',{...request,lease_ms:request.lease_ms ?? 5000}); },
    recover() { return invoke('recover'); },
    async complete(request) {
      check(typeof request.result_hash === 'string' && request.result_hash === digest(request.result),'A2_RESULT_DIGEST');
      const state = await snapshot(), task = state.tasks.find(t => t.mission_id === request.mission_id && t.task_id === request.task_id);
      check(task && task.producer_id === request.worker_id,'A2_RESULT_SCOPE');
      // The output schema is frozen by the A1 capability ref. Authority supplies
      // that registered schema; leaves cannot substitute a permissive schema.
      check(request.result && request.result.output_schema_digest === task.document.capability.output_schema.digest,'A2_RESULT_SCHEMA_BINDING');
      validateBoundValue(task.output_schema,request.result.output);
      return invoke('complete',request);
    },
    reserve(request) { attempt(request); integer(request.reserve_micros,'A2_RESERVE_LIMIT'); integer(request.quota_units ?? 1,'A2_QUOTA_LIMIT'); check(/^sha256:[a-f0-9]{64}$/.test(request.request_hash),'A2_REQUEST_HASH'); return invoke('reserve',{...request,quota_units:request.quota_units ?? 1}); },
    markSending(request) { return invoke('mark_sending',attempt(request)); },
    settle(request) { attempt(request); integer(request.actual_cost_micros,'A2_SETTLEMENT_LIMIT'); canonicalize(request.usage); check(Buffer.byteLength(JSON.stringify(request.usage)) <= 16384 && typeof request.provider_ref === 'string' && request.provider_ref.length <= 256,'A2_USAGE_LIMIT'); return invoke('settle',request); },
    unknown(request) { return invoke('unknown',attempt(request)); },
    failBeforeSend(request) { return invoke('fail_before_send',attempt(request)); },
    quiesceLocalModel(request) { check(['admin','coordinator'].includes(db.role),'A2_QUIESCENCE_ROLE_DENIED');attempt(request);const scoped=scope(request);validateLocalModelQuiescence(scoped,project_id);return db.quiesceLocalModel(scoped); },
    markEffectSending(request) { return invoke('effect_sending',request); },
    confirmEffect(request) { return invoke('effect_confirm',request); },
    unknownEffect(request) { return invoke('effect_unknown',request); },
    cancel(request) { return invoke('cancel',request); },
    revoke(request) { return invoke('revoke',request); },
    revokeCapability(request) { return invoke('revoke_capability',request); },
    snapshot,
    events(request={}) { return invoke('events',request); },
    getCursor(consumer_id) { return invoke('get_cursor',{consumer_id}); },
    ackCursor(request) { return invoke('ack_cursor',request); },
    inbox(request) { check(request.payload_hash === digest(request.body),'A2_INBOX_HASH'); return invoke('inbox',request); },
    qaEvaluate(request) { return invoke('qa_evaluate',request); }
  };
  return Object.freeze(api);
}
