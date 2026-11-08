import test from 'node:test';
import assert from 'node:assert/strict';
import {MemoryLedger} from '../../awe/budget/memory-ledger.mjs';
import {world, request, approve, assertCaps, success, route, readback, shape} from './fixtures.mjs';

for (const status of ['TIMEOUT', 'PARTIAL_STREAM', 'LOST_RESPONSE', 'SPLIT_COMMIT']) test('F01 uncertain ' + status + ' blocks fallback and new IDs', async () => {
  const w = world({routes: [route(), route('r2', 'OpenRouter')], scripts: [[{status}], [success()]]});
  const r = request('one', {allowedRoutes: ['r1', 'r2']}), a = approve(w, r);
  assert.equal((await w.broker.execute(r, a.approval.id)).status, 'OUTCOME_UNKNOWN');
  assert.equal(w.ledger.inspect().totals.global.uncertainMicros, '40');
  assert.equal((await w.broker.execute(r, a.approval.id)).status, 'OUTCOME_UNKNOWN');
  const sameIntent = {...r, operationId: 'op-new', logicalRequestId: 'logical-new', correlationId: 'corr-new'}, b = approve(w, sameIntent);
  assert.equal((await w.broker.execute(sameIntent, b.approval.id)).code, 'INTENT_ID_REUSE_BLOCKED');
  const sibling = request('two'), c = approve(w, sibling);
  assert.equal((await w.broker.execute(sibling, c.approval.id)).code, 'SCOPE_QUARANTINED');
  assert.equal(w.controls.r1.calls().length, 1); assert.equal(w.controls.r2.calls().length, 0); assertCaps(w);
});
const invalidReplies = [
  ['missing usage', success({usage: null})],
  ['over-bound output', success({usage: {uncachedInput: 4, cacheRead: 0, cacheWrite: 0, output: 6, toolCalls: 0}})],
  ['unexpected reasoning bucket', success({usage: {uncachedInput: 4, cacheRead: 0, cacheWrite: 0, output: 2, toolCalls: 0, reasoning: 1}})],
  ['model substitution', success({modelId: 'synthetic-other'})],
  ['wrong correlation', success({correlationId: 'corr-wrong'})],
  ['wrong attempt', success({attemptId: 'attempt-wrong'})],
  ['incomplete response', success({complete: false})],
  ['tool without request', success({output: {text: '', tools: [{id: 't1', name: 'unsafe', arguments: {}}]}})],
  ['unproven transient', {status: 'TRANSIENT_NOT_SENT'}],
  ['auth after acceptance', {status: 'AUTH_ERROR', accepted: true}],
  ['partial stream falsely marked NOT_SENT', {status: 'TRANSIENT_NOT_SENT', accepted: false, billable: false, emittedBytes: 0, stream: [{type: 'text'}]}]
];
for (const [name, reply] of invalidReplies) test('F02 validate ' + name + ' conservatively', async () => {
  const w = world({scripts: [[reply]]}), r = request(), a = approve(w, r);
  assert.equal((await w.broker.execute(r, a.approval.id)).status, 'OUTCOME_UNKNOWN');
  assert.equal(w.ledger.inspect().totals.global.uncertainMicros, '40'); assert.equal(w.ledger.inspect().totals.global.spentMicros, '0'); assertCaps(w);
});
test('F03 stream + JSON + tools validated; tool output is data only', async () => {
  const toolSchema = {required: ['query'], properties: {query: 'string'}, additionalProperties: false};
  const w = world({scripts: [[success({usage: {uncachedInput: 4, cacheRead: 0, cacheWrite: 0, output: 2, toolCalls: 1},
    output: {text: 'fixture', json: {answer: 'fixture'}, tools: [{id: 'tool-1', name: 'search', arguments: {query: 'fixture'}}]},
    stream: [{seq: 0, type: 'text', data: 'fixture'}, {seq: 1, type: 'done'}]})]]});
  const r = request('one', {features: {tools: true, stream: true, json: true}, jsonSchema: shape, jsonExample: {answer: 'fixture'},
    toolSchemas: {search: {schema: toolSchema, example: {query: 'fixture'}}}, bounds: {...request().bounds, toolCalls: 1}}), a = approve(w, r);
  const result = await w.broker.execute(r, a.approval.id); assert.equal(result.status, 'SUCCEEDED'); assert.equal(result.costMicros, '11');
  assert.equal(w.controls.r1.calls().length, 1); assertCaps(w);
});
for (const [name, patch] of [
  ['missing terminal stream', {stream: [{seq: 0, type: 'text', data: 'partial'}]}],
  ['out-of-order stream', {stream: [{seq: 1, type: 'done'}]}],
  ['invalid JSON type', {output: {text: '', tools: [], json: {answer: 7}}}],
  ['extra JSON key', {output: {text: '', tools: [], json: {answer: 'fixture', extra: true}}}]
]) test('F04 stream/JSON failure ' + name + ' retains liability', async () => {
  const w = world({scripts: [[success({output: {text: '', tools: [], json: {answer: 'fixture'}}, stream: [{seq: 0, type: 'done'}], ...patch})]]});
  const r = request('one', {features: {tools: false, stream: true, json: true}, jsonSchema: shape, jsonExample: {answer: 'fixture'}}), a = approve(w, r);
  assert.equal((await w.broker.execute(r, a.approval.id)).status, 'OUTCOME_UNKNOWN'); assertCaps(w);
});
test('F05 before-COMMIT fault rolls back approval and reservation together', async () => {
  const w = world(), r = request(), a = approve(w, r); w.ledger.injectFault('BEFORE_COMMIT');
  assert.equal((await w.broker.execute(r, a.approval.id)).code, 'COMMIT_NOT_APPLIED');
  assert.equal(w.ledger.inspect().approvals[a.approval.id].uses, 0); assert.equal(w.ledger.inspect().totals.global.exposureMicros, '0');
  assert.equal(w.controls.r1.calls().length, 0);
  assert.equal((await w.broker.execute(r, a.approval.id)).status, 'SUCCEEDED'); assertCaps(w);
});
test('F06 lost admission ACK holds consumed approval; never dispatches', async () => {
  const w = world(), r = request(), a = approve(w, r); w.ledger.injectFault('AFTER_COMMIT_ACK_LOST');
  assert.equal((await w.broker.execute(r, a.approval.id)).status, 'OUTCOME_UNKNOWN');
  assert.equal(w.controls.r1.calls().length, 0); assert.equal(w.ledger.inspect().approvals[a.approval.id].uses, 1);
  assert.equal(w.ledger.inspect().totals.global.uncertainMicros, '40');
  assert.equal(w.ledger.operation(r.operationId).status, 'QUARANTINED'); assertCaps(w);
});
test('F07 lost begin ACK consumes attempt slot and quarantines without invoking mock', () => {
  const w = world(), r = request(), a = approve(w, r); w.ledger.admit(a.prepared.plan, a.approval.id);
  w.ledger.injectFault('AFTER_COMMIT_ACK_LOST'); assert.throws(() => w.ledger.begin(r.operationId, 'r1'), /COMMIT_OUTCOME_UNKNOWN/);
  assert.equal(w.ledger.operation(r.operationId).attempts.length, 1); assert.equal(w.controls.r1.calls().length, 0); assertCaps(w);
});
test('F08 lost settle ACK never double-charges or retries', async () => {
  const w = world({deferred: true}), r = request(), a = approve(w, r), pending = w.broker.execute(r, a.approval.id);
  w.ledger.injectFault('AFTER_COMMIT_ACK_LOST'); w.controls.r1.completeNext();
  assert.equal((await pending).status, 'OUTCOME_UNKNOWN');
  assert.equal(w.ledger.inspect().totals.global.spentMicros, '8'); assert.equal(w.ledger.inspect().totals.global.uncertainMicros, '32');
  assert.equal((await w.broker.execute(r, a.approval.id)).status, 'OUTCOME_UNKNOWN'); assert.equal(w.controls.r1.calls().length, 1); assertCaps(w);
});
for (const action of ['cancel', 'revoke', 'changeAuthority']) test('F09 ' + action + ' during in-flight mock retains liability', async () => {
  const w = world({deferred: true}), r = request(), a = approve(w, r), pending = w.broker.execute(r, a.approval.id);
  if (action === 'cancel') w.ledger.cancel(r.operationId);
  else if (action === 'revoke') w.ledger.revoke(a.approval.id);
  else w.ledger.changeAuthority({policyVersion: 'synthetic-v2', epoch: 2});
  w.controls.r1.completeNext(); assert.equal((await pending).status, 'OUTCOME_UNKNOWN');
  assert.equal(w.ledger.inspect().totals.global.uncertainMicros, '40'); assertCaps(w);
});
test('F10 unavailable ledger fails closed; post-invoke failure keeps reserve', async () => {
  const w = world(), r = request(), a = approve(w, r); w.ledger.setAvailable(false);
  assert.equal((await w.broker.execute(r, a.approval.id)).code, 'LEDGER_UNAVAILABLE'); assert.equal(w.controls.r1.calls().length, 0);
  const w2 = world({deferred: true}), b = approve(w2, r), pending = w2.broker.execute(r, b.approval.id);
  w2.ledger.setAvailable(false); w2.controls.r1.completeNext(); assert.equal((await pending).status, 'OUTCOME_UNKNOWN');
  assert.equal(w2.ledger.inspect().totals.global.reservedMicros, '40');
  assert.equal((await w2.broker.execute(r, b.approval.id)).code, 'LEDGER_UNAVAILABLE');
  w2.ledger.setAvailable(true);
  // Outstanding IN_FLIGHT is an execution barrier even when the store returns.
  assert.equal((await w2.broker.execute(r, b.approval.id)).status, 'IN_PROGRESS'); assert.equal(w2.controls.r1.calls().length, 1); assertCaps(w2);
});
test('F11 independent synthetic reconciliation settles once and retains historical identity', async () => {
  const w = world({scripts: [[{status: 'TIMEOUT'}]]}), r = request(), a = approve(w, r); await w.broker.execute(r, a.approval.id);
  const evidence = readback(w); assert.throws(() => w.ledger.reconcile(r.operationId, {...evidence, attempts: []}), /RECONCILIATION_INCOMPLETE/);
  assert.throws(() => w.ledger.reconcile(r.operationId, {...evidence, planHash: 'wrong'}), /RECONCILIATION_EVIDENCE/);
  assert.equal(w.ledger.reconcile(r.operationId, evidence).status, 'RECONCILED');
  assert.equal(w.ledger.inspect().totals.global.spentMicros, '8'); assert.equal(w.ledger.inspect().totals.global.uncertainMicros, '0');
  assert.equal((await w.broker.execute(r, a.approval.id)).status, 'RECONCILED'); assert.equal(w.controls.r1.calls().length, 1); assertCaps(w);
});
test('F12 synthetic restore preserves uncertain liabilities and consumed IDs', async () => {
  const w = world({scripts: [[{status: 'TIMEOUT'}]]}), r = request(), a = approve(w, r); await w.broker.execute(r, a.approval.id);
  const checkpoint = w.ledger.checkpoint(), restored = new MemoryLedger({checkpoint, now: 1100, authority: {policyVersion: 'synthetic-v2', epoch: 2}});
  assert.equal(restored.inspect().totals.global.uncertainMicros, '40'); assert.equal(restored.inspect().approvals[a.approval.id].uses, 1);
  assert(restored.inspect().approvals[a.approval.id].revoked); assert.throws(() => restored.finishMockRecovery(), /UNRESOLVED_OPERATIONS/);
  const w2 = {ledger: restored}; restored.reconcile(r.operationId, readback(w2)); restored.finishMockRecovery();
  assert.equal(restored.operation(r.operationId).status, 'RECONCILED'); assert.equal(restored.inspect().totals.global.spentMicros, '8'); assertCaps(w2);
  checkpoint.state.revision++; assert.throws(() => new MemoryLedger({checkpoint}), /CHECKPOINT_CHECKSUM/);
});
test('F13 settlement beyond declared bound quarantines, never erases exposure', async () => {
  const w = world({scripts: [[{status: 'TIMEOUT'}]]}), r = request(), a = approve(w, r); await w.broker.execute(r, a.approval.id);
  assert.throws(() => w.ledger.reconcile(r.operationId, readback(w, r.operationId, '21')), /PROVIDER_BOUND_BREACH/);
  assert.equal(w.ledger.inspect().totals.global.uncertainMicros, '40'); assertCaps(w);
});
for (const d03Marker of ['INTENT', 'ABORTED']) test('F14 CR-05 separate D-03 ' + d03Marker + ' cannot negate recorded canary', async () => {
  const observations = {d02: 'CANARY_RECORDED', d03: d03Marker, source: 'SYNTHETIC_INDEPENDENT_OBSERVATIONS'};
  const w = world(), r = request(), a = approve(w, r); w.ledger.admit(a.prepared.plan, a.approval.id);
  const attempt = w.ledger.begin(r.operationId, 'r1');
  assert.equal(observations.d02, 'CANARY_RECORDED');
  w.ledger.quarantine(r.operationId, 'CR05_SPLIT_COMMIT_' + observations.d03);
  w.ledger.cancel(r.operationId);
  assert.equal(w.ledger.inspect().totals.global.uncertainMicros, '40'); assert.equal(w.ledger.operation(r.operationId).attempts[0].id, attempt.id);
  const sibling = request('two'), b = approve(w, sibling);
  assert.equal((await w.broker.execute(sibling, b.approval.id)).code, 'SCOPE_QUARANTINED'); assertCaps(w);
});
for (const [name, tools] of [
  ['duplicate tool IDs', [{id: 'tool-1', name: 'search', arguments: {query: 'fixture'}}, {id: 'tool-1', name: 'search', arguments: {query: 'fixture'}}]],
  ['invalid arguments', [{id: 'tool-1', name: 'search', arguments: {query: 7}}]],
  ['unapproved tool name', [{id: 'tool-1', name: 'other', arguments: {query: 'fixture'}}]]
]) test('F15 requested tools ' + name + ' quarantine without executing tools', async () => {
  const schema = {required: ['query'], properties: {query: 'string'}, additionalProperties: false};
  const w = world({scripts: [[success({usage: {...success().usage, toolCalls: 2}, output: {text: '', tools}})]]});
  const r = request('one', {features: {tools: true, stream: false, json: false}, bounds: {...request().bounds, toolCalls: 2}, toolSchemas: {search: {schema, example: {query: 'fixture'}}}}), a = approve(w, r);
  assert.equal((await w.broker.execute(r, a.approval.id)).status, 'OUTCOME_UNKNOWN'); assert.equal(w.controls.r1.calls().length, 1); assertCaps(w);
});
test('F16 provider receipt cannot settle two different attempts', async () => {
  const w = world({scripts: [[success({providerRequestId: 'synthetic-reused-receipt'}), success({providerRequestId: 'synthetic-reused-receipt'})]]});
  for (const suffix of ['one', 'two']) {
    const r = request(suffix), a = approve(w, r), result = await w.broker.execute(r, a.approval.id);
    assert.equal(result.status, suffix === 'one' ? 'SUCCEEDED' : 'OUTCOME_UNKNOWN');
  }
  assert.equal(w.ledger.inspect().totals.global.spentMicros, '8'); assert.equal(w.ledger.inspect().totals.global.uncertainMicros, '40'); assertCaps(w);
});
