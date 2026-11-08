import {digest} from '../../contracts/canonical.mjs';
import {copy, requireState} from '../state/errors.mjs';

export function newProject(input, epochs) {
  const hash = digest(input.config);
  return {
    id: input.project_id, name: input.name, config_owner: input.config_owner,
    status: 'PROVISIONING', revision: 0, epochs: copy(epochs),
    config_revision: 1, configs: {'1': {hash, content: copy(input.config)}},
    provision: {operation_id: `op_provision_${digest(input).slice(7, 39)}`, phase: 'INTENT', recovery_required: false},
    resources: [], qa02: null, stream_id: `stream_${input.project_id.slice(4)}`, sequence: 0,
    specs: {}, tasks: {}, operations: {}, idempotency: {}, transitions: [], events: [], payloads: {},
    inbox: {}, outbox: {}, subscriptions: {}, owner_actions: {}, checkpoints: {}, receipts: {}
  };
}

export function provisionCanary(project) {
  requireState(project.status === 'PROVISIONING', 'PROJECT_NOT_PROVISIONING');
  if (project.provision.phase === 'INTENT') {
    project.resources.push({id: `canary:${project.id}`, project_id: project.id,
      owner: project.config_owner, operation_id: project.provision.operation_id});
    project.provision.phase = 'RESOURCES_CREATED';
  }
  project.provision.recovery_required = false;
  return project;
}

export function compensateCanary(project) {
  requireState(project.status === 'PROVISIONING' || project.status === 'ERROR', 'COMPENSATION_NOT_ALLOWED');
  project.resources = project.resources.filter(resource => !(resource.project_id === project.id
    && resource.owner === project.config_owner && resource.operation_id === project.provision.operation_id));
  project.provision.phase = 'COMPENSATED';
  project.status = 'ERROR';
}

export function validateDag(tasks) {
  const visiting = new Set(), visited = new Set();
  const visit = id => {
    requireState(tasks[id], 'DEPENDENCY_MISSING');
    requireState(!visiting.has(id), 'DAG_CYCLE');
    if (visited.has(id)) return;
    visiting.add(id);
    for (const dep of tasks[id].dependencies) visit(dep);
    visiting.delete(id);
    visited.add(id);
  };
  Object.keys(tasks).forEach(visit);
}
