import {createHash} from 'node:crypto';
import {harness, scope} from './harness.mjs';
const h = harness();
await h.running(); await h.action(); const sub = await h.subscribe(); await h.verifyAction();
await h.wake(sub);
const intent = await h.intent(); await h.dispatch(intent.scope);
await h.service.recordToolReceipt(h.state, h.receipt(intent.scope, 'OUTCOME_UNKNOWN'));
const unknown = h.service.getOperation(h.owner, intent.scope);
await h.reconcile(intent.scope, 'APPLIED');
let task = h.service.getTask(h.supervisor, scope());
await h.service.resume(h.supervisor, scope(), task.revision, task.lease);
await h.go('QA_PENDING'); await h.go('PERSISTING');
task = h.service.getTask(h.supervisor, scope());
const checkpoint = await h.service.checkpoint(h.supervisor, scope(), task.revision, task.lease);
task = await h.go('COMPLETE');
console.log(JSON.stringify({mode: 'E0_SYNTHETIC_ONLY', task: {state: task.state, revision: task.revision},
  stable_operation_id: intent.scope.operation_id, operation_attempts: unknown.attempts,
  unknown_retained_reservation: unknown.retained_reservation, unsafe_replays: 0, actual_external_dispatches: 0,
  subscriptions: h.service.getSubscriptions(h.owner, 'prj_alpha').map(item => item.status),
  checkpoint_ref: checkpoint.checkpoint_ref,
  final_reports: h.service.peekOutbox(h.state, 'prj_alpha').filter(item => item.body.kind === 'final-report').length,
  snapshot_sha256: createHash('sha256').update(h.storage.snapshot()).digest('hex')}, null, 2));
