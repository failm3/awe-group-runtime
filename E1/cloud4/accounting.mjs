import {digest,immutable,need} from '../contracts/index.mjs';
import {cloud4AuthorizationReceipt} from './authority.mjs';
/** Same A2 D09 port; no JS balance, counter, retry authority or second ledger. */
export function createCloud4Accounting({coordinator,authorization}){
  need(coordinator?.kind==='AWE_E1_DURABLE_COORDINATOR'&&typeof coordinator.cloud4Authorization==='function','CLOUD4_NATIVE_ACCOUNTING_REQUIRED');
  const receipt=cloud4AuthorizationReceipt(authorization),doc=receipt.document;
  need(doc.project_ids.includes(coordinator.project_id),'CLOUD4_NATIVE_SCOPE');
  const phase=async()=>{const state=await coordinator.cloud4Authorization(doc.key_binding_id);need(state.authorization_digest===receipt.document_digest&&['CANARY','FOLLOWUP'].includes(state.state),'CLOUD4_NATIVE_PHASE_BLOCKED');return state.state;};
  return Object.freeze({kind:'CLOUD4_BOUND_NATIVE_ACCOUNTING',project_id:coordinator.project_id,key_binding_id:doc.key_binding_id,
    async reserve(request){const current=await phase();return coordinator.reserve({...immutable(request),cloud:{...immutable(request.cloud),cloud4_authorization_digest:receipt.document_digest,cloud4_phase:current}});},
    async markSending(request){await phase();return coordinator.markSending(immutable(request));},
    settle:request=>coordinator.settle(immutable(request)),unknown:request=>coordinator.unknown(immutable(request)),failBeforeSend:request=>coordinator.failBeforeSend(immutable(request)),
    async readback(){const value=await coordinator.cloud4Authorization(doc.key_binding_id);return immutable({...value,authorization_receipt_digest:digest(receipt)});}
  });
}
