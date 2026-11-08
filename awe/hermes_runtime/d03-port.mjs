// Read-only projection of the unchanged D03 service. This does not make native
// MemoryStorage durable; INT03's durable host must provide its own reviewed view.
export function createD03ReadPort({service,reader}) {
 return Object.freeze({read(scope){const p=service.getProject(reader,scope.project_id),t=service.getTask(reader,scope);
  return {project_status:p.status,state:t.state,cancelled:t.cancel_requested,restore_pending:t.restore_pending,
   acceptance_stale:t.acceptance_stale,epochs:p.epochs,spec:t.spec,revision:t.revision,
   runtime_pin:{config_revision:t.config_revision,fence:t.fence,lease_epoch:t.lease_epoch},lease_actor:t.lease?.holder,lease_expires_at:t.lease?.expires_at};}});
}
