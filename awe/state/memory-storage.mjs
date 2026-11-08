import {createHash} from 'node:crypto';
import {canonicalize, digest} from '../../contracts/canonical.mjs';
import {validateShape} from '../../contracts/schema-validator.mjs';
import {validateDag} from '../project_factory/factory.mjs';
import {copy, increment, requireState} from './errors.mjs';

const checksum = data => createHash('sha256').update(JSON.stringify(data)).digest('hex');
const empty = () => ({format: 'awe-e0-state-v1', commit: 0, projects: {}});

// Trusted storage port: serializable transaction(sync reducer), read(sync query), snapshot().
// No worker receives this port. Memory commits survive service recreation, NOT power loss.
export class MemoryStorage {
  #data;
  #tail = Promise.resolve();
  #fault;
  constructor({snapshot, fault = () => {}} = {}) {
    this.#fault = fault;
    this.#data = snapshot === undefined ? empty() : restore(snapshot);
  }
  read(query) { return copy(query(copy(this.#data))); }
  transaction(reducer) {
    const run = this.#tail.then(() => {
      const draft = copy(this.#data);
      const result = reducer(draft);
      requireState(!result || typeof result.then !== 'function', 'ASYNC_TRANSACTION_FORBIDDEN');
      const detached = copy(result);
      draft.commit = increment(draft.commit);
      this.#fault('before_commit');
      // Detach even internal reducer aliases from committed storage.
      this.#data = copy(draft);
      this.#fault('after_commit'); // lost ACK: commit exists, caller may see failure
      return detached;
    });
    this.#tail = run.catch(() => {});
    return run;
  }
  snapshot() {
    const data = copy(this.#data);
    return JSON.stringify({snapshot_version: 1, checksum: checksum(data), data});
  }
}

function restore(snapshot) {
  requireState(typeof snapshot === 'string' && Buffer.byteLength(snapshot) <= 8 * 1024 * 1024, 'SNAPSHOT_SIZE');
  let record;
  try { record = JSON.parse(snapshot); } catch { requireState(false, 'SNAPSHOT_JSON'); }
  requireState(record.snapshot_version === 1 && record.checksum === checksum(record.data), 'SNAPSHOT_CHECKSUM');
  const data = record.data;
  requireState(data?.format === 'awe-e0-state-v1' && Number.isSafeInteger(data.commit) && data.commit >= 0, 'SNAPSHOT_VERSION');
  requireState(data.projects && Object.getPrototypeOf(data.projects) === Object.prototype, 'SNAPSHOT_STRUCTURE');
  const jsonDomain = (value, depth = 0) => {
    requireState(depth < 64, 'SNAPSHOT_DEPTH');
    if (typeof value === 'number') requireState(Number.isSafeInteger(value) && !Object.is(value, -0), 'SNAPSHOT_NUMBER');
    if (typeof value === 'string') requireState(value.isWellFormed(), 'SNAPSHOT_UNICODE');
    if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) {
      requireState(!['__proto__', 'constructor', 'prototype'].includes(key), 'SNAPSHOT_UNSAFE_KEY');
      jsonDomain(child, depth + 1);
    }
  };
  jsonDomain(data);
  for (const [id, project] of Object.entries(data.projects)) {
    requireState(/^prj_[a-z0-9][a-z0-9_-]{0,63}$/.test(id) && project.id === id, 'SNAPSHOT_SCOPE');
    canonicalize(project.epochs);
    requireState(validateShape('epochs', {schema_version: '1.0.0', contract: 'epochs', epochs: project.epochs}).length === 0, 'SNAPSHOT_EPOCHS');
    requireState(Number.isSafeInteger(project.sequence) && project.sequence === project.events.length, 'SNAPSHOT_SEQUENCE');
    for (const [index, event] of project.events.entries()) {
      requireState(validateShape('event-envelope', event).length === 0, 'SNAPSHOT_EVENT');
      requireState(event.scope.project_id === id && event.sequence === index + 1, 'SNAPSHOT_SEQUENCE');
      requireState(project.payloads[event.payload_ref.content_hash] !== undefined, 'SNAPSHOT_PAYLOAD');
      requireState(digest(project.payloads[event.payload_ref.content_hash]) === event.payload_ref.content_hash, 'SNAPSHOT_PAYLOAD');
    }
    for (const item of Object.values(project.specs)) requireState(digest(item.content) === item.dto.spec.content_hash
      && validateShape('spec-revision', item.dto).length === 0, 'SNAPSHOT_SPEC');
    for (const transition of project.transitions) requireState(transition.scope.project_id === id
      && project.tasks[transition.scope.task_id] && validateShape('state-transition', transition).length === 0, 'SNAPSHOT_TRANSITION');
    for (const item of Object.values(project.configs)) requireState(digest(item.content) === item.hash, 'SNAPSHOT_CONFIG');
    for (const [taskId, task] of Object.entries(project.tasks)) {
      requireState(/^task_[a-z0-9][a-z0-9_-]{0,63}$/.test(taskId) && task.id === taskId && task.project_id === id
        && Number.isSafeInteger(task.revision) && task.revision >= 0
        && Number.isSafeInteger(task.fence) && task.fence >= 0
        && Number.isSafeInteger(task.lease_epoch) && task.lease_epoch >= 0, 'SNAPSHOT_TASK');
      requireState(['DRAFT','READY','RUNNING','QA_PENDING','REWORK','PERSISTING','RECONCILING','WAITING_FOR_EVENT',
        'WAITING_FOR_OWNER','BLOCKED','COMPLETE','CANCELLING','CANCELLED','FAILED'].includes(task.state), 'SNAPSHOT_TASK_STATE');
      requireState(!task.cancel_requested || ['CANCELLING','CANCELLED','RECONCILING'].includes(task.state), 'SNAPSHOT_CANCEL');
      if (task.lease) requireState(task.lease.fence === task.fence && task.lease.lease_epoch === task.lease_epoch, 'SNAPSHOT_FENCE');
      requireState(task.dependencies.every(dep => project.tasks[dep]), 'SNAPSHOT_DAG');
      requireState(project.specs[`${task.spec.spec_id}:${task.spec.revision}`]?.dto.spec.content_hash === task.spec.content_hash, 'SNAPSHOT_SPEC');
    }
    validateDag(project.tasks);
    for (const [opId, operation] of Object.entries(project.operations)) {
      requireState(opId === operation.scope.operation_id && project.tasks[operation.scope.task_id] && operation.scope.project_id === id, 'SNAPSHOT_OPERATION');
      requireState(validateShape('scope-ids', {schema_version: '1.0.0', contract: 'scope-ids', scope: operation.scope}).length === 0, 'SNAPSHOT_OPERATION');
    }
    for (const [ref, checkpoint] of Object.entries(project.checkpoints)) requireState(digest(checkpoint) === ref, 'SNAPSHOT_CHECKPOINT');
  }
  // The checksum detects damage, not a malicious administrator. Authenticated backup
  // manifests/ACL reconciliation/anti-rollback belong to the D-02/D-09 integration gate.
  for (const project of Object.values(data.projects)) for (const task of Object.values(project.tasks)) {
    if (!['COMPLETE','CANCELLED','FAILED'].includes(task.state)) task.restore_pending = true;
  }
  return copy(data);
}
