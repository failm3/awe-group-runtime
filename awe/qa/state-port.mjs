import {copy, digest, need} from './common.mjs';

// Narrow CR-D08-01 adapter: D03 owns task writes; d08 sidecar shares its serial queue.
// No worker receives this port, storage, supervisor, or D03 sessions.
export function createD03QaPort({state, storage, reader, supervisor, scope, clock}) {
  const ownScope=copy(scope);
  let sequence=0;
  function projectTask(db) {
    const p=db.projects[ownScope.project_id], t=p?.tasks[ownScope.task_id];
    need(p && t && t.control_operation_id===ownScope.operation_id,'STATE_SCOPE');
    return {p,t};
  }
  function pinOf(p,t) {
    return {scope:ownScope,project_status:p.status,project_revision:p.revision,config_revision:p.config_revision,
      spec:t.spec,epochs:p.epochs,revision:t.revision,state:t.state,fence:t.fence,lease_epoch:t.lease_epoch,
      lease:t.lease,cancel_requested:t.cancel_requested,restore_pending:t.restore_pending,acceptance_stale:t.acceptance_stale,
      operations_hash:digest(Object.values(p.operations).filter(o=>o.scope.task_id===t.id))};
  }
  function read() {
    const authenticated=state.getTask(reader,ownScope);
    need(authenticated && !authenticated.then,'SYNC_STATE_REQUIRED');
    const value=storage.read(db=>{const {p,t}=projectTask(db);
      need(digest(t)===digest(authenticated),'STATE_CHANGED');
      return {pin:pinOf(p,t), operations:Object.values(p.operations).filter(o=>o.scope.task_id===t.id),
        record:db.d08?.[ownScope.project_id+'/'+ownScope.task_id]??null};});
    need(value && !value.then,'SYNC_STATE_REQUIRED'); return copy(value);
  }
  function live(pin) {
    need(pin.project_status==='READY' && ['RUNNING','QA_PENDING'].includes(pin.state)
      && !pin.cancel_requested && !pin.restore_pending && !pin.acceptance_stale,'STATE_BLOCKED');
    need(pin.lease?.holder===supervisor.identity_id && pin.lease.expires_at>clock(),'LEASE_EXPIRED');
  }
  return Object.freeze({
    read, live,
    async enterPending(expected) {
      const {pin}=read(); live(pin); need(digest(pin)===digest(expected),'STALE_REVISION');
      if(pin.state==='QA_PENDING') return pin;
      const dto={schema_version:'1.0.0',contract:'state-transition',request_id:'req_d08',correlation_id:'corr_d08',
        causation_id:null,actor:supervisor,scope:ownScope,epochs:pin.epochs,spec:pin.spec,created_at:clock(),
        expected_revision:pin.revision,event_id:'evt_d08_pending_'+(++sequence),from_state:pin.state,to_state:'QA_PENDING',
        lease_epoch:pin.lease_epoch,fence:pin.fence,resume_state:null,reason:'D08 E0 independent verification pending',
        guard_refs:[],owner_action_id:null,subscription_id:null};
      await state.transition(supervisor,dto);
      return read().pin;
    },
    transact(expected, reducer) {
      // Authenticate before queuing; the reducer rechecks live D03 pins at commit.
      read();
      return storage.transaction(db=>{
        const {p,t}=projectTask(db), pin=pinOf(p,t); live(pin);
        need(digest(pin)===digest(expected),'STALE_REVISION');
        db.d08??={}; const k=ownScope.project_id+'/'+ownScope.task_id;
        const result=reducer(copy(db.d08[k]??null),copy(pin));
        need(result && !result.then && result.record,'SYNC_QA_TRANSACTION_REQUIRED');
        db.d08[k]=copy(result.record); return copy(result.value);
      });
    }
  });
}
