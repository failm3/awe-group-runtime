import {canonicalize, digest} from '../../contracts/canonical.mjs';
import {validateShape} from '../../contracts/schema-validator.mjs';
import {increment, requireState} from '../state/errors.mjs';

export const bodyHash = event => {
  const body = {...event};
  delete body.producer_receipt_hash;
  return digest(body);
};

export function appendEvent(project, {scope, actor, spec, revision, type, payload, now, eventId, causation = null}) {
  const hash = digest(payload);
  project.payloads[hash] = payload;
  const sequence = increment(project.sequence);
  const event = {
    schema_version: '1.0.0', contract: 'event-envelope',
    request_id: `req_local_${sequence}`, correlation_id: `corr_local_${sequence}`,
    causation_id: causation, actor, scope, epochs: project.epochs, spec,
    created_at: now, expected_revision: revision, event_id: eventId ?? `evt_local_${sequence}`,
    event_type: type, source_version: '1.0.0', sequence,
    received_at: now, expires_at: new Date(Date.parse(now) + 86400000).toISOString(),
    payload_ref: {project_id: project.id, artifact_id: `art_event_${sequence}`,
      content_hash: hash, bytes: Buffer.byteLength(canonicalize(payload)), media_type: 'application/json', aggregate_hash: hash},
    producer_receipt_hash: digest({profile: 'E0_LOCAL_RECEIPT', project_id: project.id, sequence, hash})
  };
  requireState(validateShape('event-envelope', event).length === 0, 'LOCAL_EVENT_INVALID');
  requireState(!project.events.some(item => item.event_id === event.event_id), 'EVENT_ID_CONFLICT');
  project.sequence = sequence;
  project.events.push(structuredClone(event));
  enqueue(project, `event:${sequence}`, {kind: 'event', event});
  return event;
}

export function enqueue(project, key, body) {
  const existing = project.outbox[key];
  if (existing) {
    requireState(digest(existing.body) === digest(body), 'OUTBOX_KEY_CONFLICT');
    return existing;
  }
  return project.outbox[key] = {key, body, status: 'PENDING', delivery_fence: 0, lease: null, attempts: 0};
}

// Binding extensions live in storage, not in D-01 DTOs (D-01 owns schema changes).
export function matchSubscription(project, subscription, now) {
  if (subscription.status !== 'ACTIVE' || subscription.dto.deadline <= now) return null;
  const {dto, owner_action_id} = subscription;
  return project.events.find(event => {
    if (event.sequence <= dto.cursor.last_sequence || event.event_type !== dto.event_type || event.expires_at <= now) return false;
    if (event.scope.project_id !== dto.scope.project_id || event.scope.task_id !== dto.scope.task_id || event.scope.operation_id !== dto.scope.operation_id) return false;
    if (digest(event.epochs) !== digest(dto.epochs) || digest(event.spec) !== digest(dto.spec)) return false;
    const payload = project.payloads[event.payload_ref.content_hash];
    if (dto.event_type === 'owner-action.updated') return payload.owner_action_id === owner_action_id && payload.status === 'VERIFIED';
    return ['CONFIRMED', 'RECONCILED'].includes(payload.status);
  }) ?? null;
}
