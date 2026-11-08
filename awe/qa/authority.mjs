import {copy, digest, frozen, need} from './common.mjs';

// Trusted E0 fixture issuer. Opaque handles are instance-local, never wire credentials.
export function createFixtureIssuer({principals, workerId, clock}) {
  const registry = copy(principals), sessions = new WeakMap(), grants = new WeakMap();
  const worker = registry[workerId];
  need(worker?.role === 'EXECUTOR', 'WORKER_REQUIRED');
  let epoch = 0;
  function actor(session) {
    const id = sessions.get(session), p = registry[id];
    need(p?.active, 'IDENTITY_UNTRUSTED');
    return {id, ...copy(p)};
  }
  function check(session, grant, action, binding) {
    const p = actor(session), g = grants.get(grant);
    need(g && !g.revoked && g.epoch === epoch && g.expires > clock(), 'GRANT_UNTRUSTED');
    need(g.actor === p.id && g.action === action && g.binding === digest(binding), 'GRANT_SCOPE');
    need(p.id !== workerId && p.subject !== worker.subject, 'SELF_QA_DENIED');
    need((action === 'VERIFY' ? ['EXAMINER','AUDITOR'] : ['OWNER']).includes(p.role), 'ROLE_DENIED');
    need(p.scopes.some(s => s.project_id === binding.scope.project_id && s.task_id === binding.scope.task_id), 'GRANT_SCOPE');
    return frozen({id:p.id, subject:p.subject, role:p.role, issuer_epoch:epoch});
  }
  return Object.freeze({
    control:Object.freeze({
      session(id) { need(registry[id]?.active, 'IDENTITY_UNKNOWN'); const s=Object.freeze({}); sessions.set(s,id); return s; },
      grant(session, action, binding, expires) {
        const p=actor(session);
        need(['VERIFY','ACCEPT'].includes(action) && Number.isSafeInteger(expires) && expires>clock(), 'GRANT_INVALID');
        const h=Object.freeze({});
        grants.set(h,{actor:p.id,action,binding:digest(binding),expires,epoch,revoked:false});
        // Check at issuance and every use; weak fixture grants cannot silently authorize.
        check(session,h,action,binding); return h;
      },
      revoke(grant) { const g=grants.get(grant); need(g,'GRANT_UNTRUSTED'); g.revoked=true; },
      revokeActor(id) { need(registry[id],'IDENTITY_UNKNOWN'); registry[id].active=false; epoch++; },
      advanceEpoch() { epoch++; }
    }),
    check
  });
}
