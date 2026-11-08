import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture, pending} from './harness.mjs';
import {copy, digest, scopeKey} from '../../awe/context/common.mjs';
import {createContextStore, createArtifactStore, boundToolOutput} from '../../awe/context/store.mjs';
import {createContextEngine} from '../../awe/context/engine.mjs';

test('bounded contexts retain active+previous, evict oldest inactive and reject CAS conflicts', () => {
  const store = createContextStore({max_entries: 2, max_bytes: 1000});
  const a = store.commit('one', null, {version: 1}), b = store.commit('one', a, {version: 2});
  const c = store.commit('one', b, {version: 3});
  assert.throws(() => store.read(a), /MANIFEST_INVALID/); assert.equal(store.read(b).version, 2);
  assert.equal(store.current('one').ref, c); assert.equal(store.inspect().entries, 2);
  assert.throws(() => store.commit('one', b, {version: 4}), /CONTEXT_CONFLICT/);
  assert.equal(store.current('one').ref, c);
});
test('bounded store cannot evict active pointers to admit another context', () => {
  const store = createContextStore({max_entries: 2, max_bytes: 1000});
  const a = store.commit('a', null, {v: 'a'}), b = store.commit('b', null, {v: 'b'});
  assert.throws(() => store.commit('c', null, {v: 'c'}), /STORE_CAPACITY/);
  assert.equal(store.current('a').ref, a); assert.equal(store.current('b').ref, b); assert.equal(store.inspect().entries, 2);
});
test('store byte limit rejects atomically, not just entry count', () => {
  const store = createContextStore({max_entries: 20, max_bytes: 100});
  const ref = store.commit('a', null, {text: 'a'});
  assert.throws(() => store.commit('a', ref, {text: 'x'.repeat(200)}), /STORE_CAPACITY/);
  assert.equal(store.current('a').ref, ref); assert(store.inspect().bytes <= 100);
});
test('artifact eviction accounts bytes; old ACL/task bindings never retrieve an object', () => {
  const store = createArtifactStore({max_entries: 5, max_bytes: 10, max_object_bytes: 10}), binding = {project_id: 'p', task_id: 't', auth_epoch: 1};
  const a = store.put(binding, Buffer.from('123456')), b = store.put(binding, Buffer.from('abcdef'));
  assert.throws(() => store.get(binding, a.artifact_ref), /ARTIFACT_UNAVAILABLE/);
  assert.throws(() => store.get({...binding, auth_epoch: 2}, b.artifact_ref), /ARTIFACT_UNAVAILABLE/);
  assert.throws(() => store.get({...binding, task_id: 'other'}, b.artifact_ref), /ARTIFACT_UNAVAILABLE/);
  assert.equal(store.get(binding, b.artifact_ref).toString(), 'abcdef'); assert(store.inspect().bytes <= 10);
  assert.throws(() => boundToolOutput(store, binding, 'x', {inline_bytes: 5000}), /OUTPUT_INVALID/);
});
test('initial overflow can compact only noncritical history with recoverable raw input and fresh budget', () => {
  const f = fixture(); f.profile().caps.input = 4500;
  f.input.history.push({id: 'msg_overflow', kind: 'assistant', text: 'x'.repeat(7000), critical: false});
  const failed = f.build(); assert.equal(failed.code, 'CONTEXT_TOO_LARGE'); assert.equal(f.store.current(f.key()), null);
  const compacted = f.engine.compactInput(f.session, f.input); assert.equal(compacted.decision, 'READY_OFFLINE', JSON.stringify(compacted));
  assert(compacted.manifest.counted.upper_bound <= 4500);
  const record = f.store.read(compacted.ref); assert.deepEqual(record.compaction_input, f.input);
  assert.equal(record.compaction_receipt.input_build_request_hash, digest(f.input));
  assert.deepEqual(record.payload.requirements, f.state.requirements);
  const bad = copy(f.input.history); bad[0].text = 'Публиковать.';
  assert.equal(f.engine.compactInput(f.session, f.input, bad).code, 'COMPACTION_INVALID');
});
test('compaction of oversized mandatory input never invents fit', () => {
  const f = fixture(); f.profile().caps.input = 100;
  assert.equal(f.engine.compactInput(f.session, f.input).code, 'PIN_SET_TOO_LARGE'); assert.equal(f.store.current(f.key()), null);
});
test('signed requirement mutation without trusted successor hash fails closed', () => {
  const f = fixture(), original = f.build(); f.state.requirements[0].text = 'Публиковать.';
  assert.equal(f.build().code, 'SIGNED_PIN_INVALID'); assert.equal(f.engine.preflight(f.session, original.ref).code, 'SIGNED_PIN_INVALID');
});
test('fresh authority required for every revision/epoch and restore boundary', () => {
  for (const key of ['spec_revision', 'policy_epoch', 'config_revision', 'state_revision', 'auth_epoch']) {
    const f = fixture(), result = f.build(); f.state[key]++;
    assert.equal(f.engine.preflight(f.session, result.ref).code, 'PERMISSION_REVOKED');
    assert.equal(f.engine.recover(f.session, result.ref).code, 'PERMISSION_REVOKED');
  }
  const f = fixture(), result = f.build(); f.state.restore_pending = true;
  assert.equal(f.engine.recover(f.session, result.ref).code, 'PERMISSION_REVOKED');
});
test('JSON copies of sessions and manifests cannot authenticate or authorize effects', () => {
  const f = fixture(), result = f.build();
  assert.equal(f.engine.build({}, f.input).code, 'AUTHENTICATION_REQUIRED');
  assert.equal(f.engine.preflight(JSON.parse(JSON.stringify(f.session)), result.ref).code, 'AUTHENTICATION_REQUIRED');
  assert.equal(f.engine.requestPhysicalEffect({manifest: result.manifest, decision: 'ALLOW'}).decision, 'DENY');
});
test('source ACL denial happens before body access', () => {
  const f = fixture({denied_sources: ['src_public']}); assert.equal(f.build().code, 'SOURCE_DENIED');
  assert.equal(f.log.filter(e => e.kind === 'READ').length, 0);
});
test('source corruption and version races never activate a partially validated context', () => {
  const f = fixture(); f.records.get('src_public').hash = 'sha256:' + '0'.repeat(64);
  assert.equal(f.build().code, 'SOURCE_CORRUPT'); assert.equal(f.store.current(f.key()), null);
  const g = fixture(); g.onRead(() => g.updateSource('src_public', 'replacement'));
  assert.equal(g.build().code, 'SOURCE_CORRUPT'); assert.equal(g.store.current(g.key()), null);
});
test('permission revocation during final preflight counter is rechecked', () => {
  const f = fixture(), result = f.build(), tokenizer = f.tokenizers.get('synthetic-utf8'); let revoked = false;
  f.tokenizers.set('synthetic-utf8', {...tokenizer, count(text) {
    if (!revoked) { revoked = true; f.revoke(); } return tokenizer.count(text);
  }});
  assert.equal(f.engine.preflight(f.session, result.ref).code, 'PERMISSION_REVOKED');
});
test('unapproved tool schemas and unsupported tools cannot be repacked into a model', () => {
  const f = fixture(); f.input.tools.push({id: 'unapproved'}); assert.equal(f.build().code, 'TOOL_SCHEMA_UNAPPROVED');
  const g = fixture(); pending(g); g.profile().tools = false; assert.equal(g.build().code, 'MODEL_SWITCH_UNSUPPORTED');
});
test('result hash must match authoritative operation receipt; cannot fabricate completed output', () => {
  const f = fixture(), binding = {project_id: 'prj_alpha', task_id: 'task_context', auth_epoch: 1};
  const output = boundToolOutput(f.artifacts, binding, 'real synthetic receipt'); pending(f, 'COMPLETE', output);
  assert.equal(f.build().decision, 'READY_OFFLINE');
  const fake = boundToolOutput(f.artifacts, binding, 'fabricated receipt'); f.input.history.at(-1).output = fake;
  assert.equal(f.build().code, 'TOOL_RESULT_UNVERIFIED');
});
test('duplicate/out-of-order results and changed tool arguments are rejected', () => {
  const f = fixture(), binding = {project_id: 'prj_alpha', task_id: 'task_context', auth_epoch: 1};
  pending(f, 'COMPLETE', boundToolOutput(f.artifacts, binding, 'ok'));
  const duplicate = copy(f.input); duplicate.history.push({...duplicate.history.at(-1), id: 'duplicate'});
  assert.equal(f.build(duplicate).code, 'PROTOCOL_INVALID');
  const reversed = copy(f.input); const last = reversed.history.pop(); reversed.history.unshift(last);
  assert.equal(f.build(reversed).code, 'PROTOCOL_INVALID');
  f.input.history.find(m => m.kind === 'call').arguments.value = 'different'; assert.equal(f.build().code, 'PROTOCOL_INVALID');
});
test('tool-turn reserve is explicit and not automatically counted again for an existing result', () => {
  const f = fixture(); f.input.reserves.next_tool = 20; assert.equal(f.build().code, 'TOOL_RESERVE_INVALID');
  f.input.planned_next_tool_turn = true; const planned = f.build(); assert.equal(planned.decision, 'READY_OFFLINE');
  assert.equal(planned.manifest.budget.planned_total, planned.manifest.counted.upper_bound + 100 + 50 + 10 + 20);
});
test('non-additive tokenizer components do not replace full-request measurement', () => {
  const f = fixture(); f.tokenizers.set('synthetic-utf8', {id: 'synthetic-utf8', version: '1', count(text) {
    const n = Math.ceil(Buffer.byteLength(text) / 7); return {tokens: n, upper_bound: n + 3, method: 'synthetic-utf8', version: '1', uncertainty_tokens: 3};
  }});
  const result = f.build(); assert.equal(result.decision, 'READY_OFFLINE');
  assert.equal(result.manifest.counted.component_sum_is_authoritative, false);
  assert.equal(result.manifest.counted.upper_bound, result.manifest.counted.tokens + 3);
});
test('deadline and ledger remain authoritative after new engine instance or replayed ticket', () => {
  const f = fixture(), result = f.build(), retry = f.engine.recover(f.session, result.ref, {failure_code: '429'});
  const restarted = createContextEngine(f.ports);
  assert.equal(restarted.recover(f.session, result.ref).code, 'RETRY_REQUIRED');
  assert.equal(f.build().code, 'RETRY_REQUIRED'); assert.equal(restarted.preflight(f.session, result.ref).code, 'RETRY_REQUIRED');
  const same = restarted.recover(f.session, result.ref, {failure_code: '429'}); assert.equal(same.retry_ticket, retry.retry_ticket);
  assert.equal(f.ledger.inspect().repairs.length, 1);
  f.time(90001); assert.equal(restarted.recover(f.session, result.ref, {retry_ticket: retry.retry_ticket}).code, 'PERMISSION_REVOKED');
});
test('summary lineage survives model switch and recovery', () => {
  const f = fixture(); let r = f.build(); r = f.engine.compact(f.session, r.ref); const lineage = r.manifest.lineage;
  r = f.engine.recover(f.session, r.ref); assert.deepEqual(r.manifest.lineage, lineage);
  r = f.engine.switchModel(f.session, r.ref, f.input.profile_id, f.input.route); assert.deepEqual(r.manifest.lineage, lineage);
});
test('public trace is bounded and revoked epochs cannot read historical trace entries', () => {
  const f = fixture({cap: 60}); for (let i = 0; i < 45; i++) assert.equal(f.build().decision, 'READY_OFFLINE');
  assert.equal(f.engine.reconnect(f.session).evidence.length, 32); assert(f.store.inspect().entries <= 16);
  f.revoke(); const status = f.engine.reconnect(f.session); assert.equal(status.evidence.length, 0);
});
test('async trusted ports are rejected; there is no implicit await across a final barrier', () => {
  const f = fixture(); const engine = createContextEngine({...f.ports, authority: {read: () => Promise.resolve(f.state)}});
  assert.equal(engine.build(f.session, f.input).decision, 'DENY'); assert.equal(f.store.current(f.key()), null);
});
test('failure messages never expose dependency exceptions, raw prompts or secret values', () => {
  const f = fixture(); const memory = {...f.ports.memory, list() { throw Error('SECRET_BODY_CANARY'); }};
  const result = createContextEngine({...f.ports, memory}).build(f.session, f.input);
  assert.equal(result.decision, 'WAIT'); assert(!JSON.stringify(result).includes('SECRET_BODY_CANARY'));
});
test('blind Examiner input allowlist rejects worker narrative and attachment feedback channels', () => {
  const f = fixture(), examiner = f.issue({actor_id: 'act_examiner', role: 'EXAMINER', purpose: 'BLIND_QA'});
  assert.equal(f.engine.build(examiner, f.input).code, 'BLIND_INPUT_DENIED');
  const input = {...copy(f.input), history: [], attachments: [{kind: 'SYNTHETIC_INLINE', bytes: 1, data_base64: 'eA=='}]};
  assert.equal(f.engine.build(examiner, input).code, 'BLIND_INPUT_DENIED');
  const source = f.records.get('src_public'); source.classification = 'WORKER_EXPLANATION';
  assert.equal(f.engine.build(examiner, {...input, attachments: []}).code, 'SOURCE_DENIED');
  assert.equal(f.log.filter(e => e.kind === 'READ').length, 0);
});
