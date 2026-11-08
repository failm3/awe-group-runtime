import {createPostgresPersistence} from '../persistence/postgres.mjs';
import {need} from './protocol.mjs';
// Thin existing D09 API adapter; no new ledger, retry loop, schema or SQL.
// A real pool is host-only and is never constructed by this delivery.
export function createD09AttemptPort(pool) {
 const db=createPostgresPersistence(pool);
 return Object.freeze({
  async begin(command) {
   const admitted=await db.admit(command);
   const scoped=r=>need(r.physical_decision==='DENY'&&r.dispatch_authorized===false&&r.project_id===command.project_id&&r.task_id===command.task_id&&r.attempt_id===command.attempt_id,'D09_BINDING_DENIED');
   scoped(admitted);need(admitted.status==='ADMITTED','D09_ALREADY_ATTEMPTED');
   const key={project_id:command.project_id,attempt_id:command.attempt_id};
   const claimed=await db.claim(key);scoped(claimed);const fence=Number(claimed.delivery_fence);
   need(Number.isSafeInteger(fence)&&fence>0,'D09_FENCE_INVALID');
   const sent=await db.markSent({...key,fence});scoped(sent);need(sent.status==='SENT','D09_SEND_NOT_COMMITTED');return {physical_decision:'DENY',attempt_id:command.attempt_id};
  },
  result:(command,result,evidence_hash)=>db.recordResult({project_id:command.project_id,attempt_id:command.attempt_id,result,evidence_hash}),
  cancel:command=>db.cancel({project_id:command.project_id,attempt_id:command.attempt_id}),
  inspect:command=>db.inspect({project_id:command.project_id,attempt_id:command.attempt_id})
 });
}
