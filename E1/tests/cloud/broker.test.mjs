import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../../contracts/index.mjs';
import {createCloudModelBroker, createOfflineCloudModelBrokerForTests} from '../../cloud/broker.mjs';
import {cloudFixture, syntheticAck, jsonResponse, LATER} from './fixtures.mjs';

const methods = f => f.calls.map(x => x.method);
test('cloud public boundary rejects fake transport and forged live policy; offline requires an explicit verifier and label', () => {
  const f = cloudFixture();
  assert.throws(() => createCloudModelBroker({...f.options, catalog: undefined, transport: f.testBinding.transport, policy: f.policy}));
  assert.throws(() => createCloudModelBroker({accounting: f.options.accounting, registry: f.registry, transport: {send() {}, verifyInputBound() { return true; }}, policy: f.policy}), {code: 'CLOUD_HOST_TRANSPORT_REQUIRED'});
  assert.throws(() => createOfflineCloudModelBrokerForTests(f.options, {...f.testBinding, label: 'LIVE'}), {code: 'CLOUD_TEST_DOUBLE_LABEL_REQUIRED'});
  assert.throws(() => createOfflineCloudModelBrokerForTests(f.options, {transport: f.testBinding.transport, label: 'OFFLINE_TEST_DOUBLE'}), {code: 'CLOUD_TEST_DOUBLE_LABEL_REQUIRED'});
});
test('one fixed HTTPS attempt is ordered through A2 and settles exact rational actual charge including cache', async () => {
  const f = cloudFixture(), result = await f.broker.invoke(f.request);
  assert.equal(result.decision, 'PROPOSED'); assert.equal(result.evidence_level, 'OFFLINE_TEST_DOUBLE'); assert.equal(result.accepted, false);
  assert.deepEqual(methods(f), ['reserve', 'markSending', 'settle']); assert.equal(f.wires.length, 1);
  assert.equal(f.wires[0].url, 'https://router.cheap/v1/chat/completions'); assert.equal(f.wires[0].redirect, 'error'); assert.equal(f.wires[0].body.stream, false);
  assert.equal(f.wires[0].body.max_tokens, 16); assert.equal(f.wires[0].body.response_format.json_schema.strict, true);
  assert.deepEqual(f.bounds[0].body, f.wires[0].body); assert.ok(f.bounds[0].body.response_format.json_schema.schema);
  assert.equal(f.calls[0].request.reserve_micros, 2313); assert.equal(f.calls[0].request.cloud.request_charge_cap_micros, '2313');
  const settle = f.calls[2].request; assert.equal(settle.actual_cost_micros, 16); assert.equal(settle.cloud.base_cost_micros, '10');
  assert.equal(settle.usage.cached_input_tokens, 3); assert.equal(result.usage.actual_charge_micros, '16');
  assert.deepEqual(result.output, {text: 'Synthetic code review.'});
});
test('full-body input proof denial prevents reservation and sending', async () => {
  const f = cloudFixture({inputTokenBound: () => false}), result = await f.broker.invoke(f.request);
  assert.equal(result.reason, 'CLOUD_INPUT_BOUND_UNKNOWN'); assert.deepEqual(methods(f), []); assert.equal(f.wires.length, 0);
  assert.ok(f.bounds[0].body.response_format.json_schema.schema);
});
test('catalogue, privacy, permission, scope, USD budget and forged policy failures have zero wire', async () => {
  const changes = [
    f => { f.request.data_label = 'PERSONAL'; },
    f => { f.request.input.instruction = 'Send to person@example.invalid'; },
    f => { f.request.route_id = 'router.cheap.chat.unknown'; },
    f => { f.request.scope.worker_id = 'foreign_worker'; },
    f => { f.policy.catalog_digest = digest({foreign: true}); },
    f => { f.policy.hard_cap.kind = 'PROVIDER_ACTUAL_CHARGE_HARD_LIMIT'; },
    f => { f.policy.per_attempt_cap_micros = '1'; },
    f => { f.grant.permissions = []; f.policy.mission_grant_digest = digest(f.grant); },
    f => { f.spec.budget.currency = 'NONE'; f.spec.budget.amount_micros = '0'; f.grant.budget_cap = f.spec.budget; f.grant.spec_digest = digest(f.spec); f.policy.spec_digest = digest(f.spec); f.policy.mission_grant_digest = digest(f.grant); },
    f => { delete f.catalog.routes[0].sources[0].cached_input_micros_per_token; }
  ];
  for (const change of changes) { const f = cloudFixture(); change(f); const result = await f.broker.invoke(f.request); assert.equal(result.decision, 'BLOCK'); assert.equal(f.wires.length, 0); assert.equal(f.calls.length, 0); }
});
test('expiry or capability revocation after reserve releases the same reservation once with proven no send', async () => {
  for (const mutation of ['time', 'capability']) {
    const f = cloudFixture({onReserve: ({registry, setNow}) => { if (mutation === 'time') setNow(LATER); else registry.entries.find(x => x.descriptor.ref.capability_id === 'e1.code.review').installed = false; }});
    const result = await f.broker.invoke(f.request); assert.equal(result.decision, 'BLOCK'); assert.equal(result.reservation_released, true);
    assert.deepEqual(methods(f), ['reserve', 'failBeforeSend']); assert.equal(f.wires.length, 0);
  }
});
test('policy expiry after SENDING holds reserve with zero wire and never invokes failBeforeSend', async () => {
  const f = cloudFixture({onSending: ({setNow}) => setNow(LATER)}), result = await f.broker.invoke(f.request);
  assert.equal(result.decision, 'HOLD'); assert.equal(result.wire_attempts, 0); assert.equal(result.accounting_status, 'UNKNOWN');
  assert.deepEqual(methods(f), ['reserve', 'markSending', 'unknown']); assert.equal(f.wires.length, 0);
});
test('uncertain reserve or SENDING acknowledgement holds without sending or releasing', async () => {
  for (const method of ['reserve', 'markSending']) {
    const f = cloudFixture({overrides: {[method]: () => { throw new Error('synthetic transport uncertainty'); }}}), result = await f.broker.invoke(f.request);
    assert.equal(result.decision, 'HOLD'); assert.equal(f.wires.length, 0); assert.equal(methods(f).at(-1), 'unknown'); assert.ok(!methods(f).includes('failBeforeSend'));
  }
});
test('length and malformed output settle real-shaped known charge before requesting repair with no retry', async () => {
  for (const mutation of ['length', 'malformed', 'schema', 'missing_content']) {
    const answer = syntheticAck();
    if (mutation === 'length') answer.choices[0].finish_reason = 'length';
    if (mutation === 'malformed') answer.choices[0].message.content = '{';
    if (mutation === 'schema') answer.choices[0].message.content = '{"text":"ok","accepted":true}';
    if (mutation === 'missing_content') delete answer.choices[0].message.content;
    const f = cloudFixture({answer}), result = await f.broker.invoke(f.request);
    assert.equal(result.decision, 'REPAIR'); assert.equal(result.accounting_status, 'CONFIRMED'); assert.equal(result.usage.actual_charge_micros, '16');
    assert.deepEqual(methods(f), ['reserve', 'markSending', 'settle']); assert.equal(f.wires.length, 1);
  }
});
test('missing or mismatched model/source/request identity, usage or actual billed charge hold without invented settlement', async () => {
  const changes = [
    a => { delete a.id; }, a => { a.model = 'different_model'; }, a => { a.source_id = 'foreign_source'; },
    a => { delete a.usage; }, a => { delete a.usage.prompt_tokens_details.cached_tokens; }, a => { a.usage.prompt_tokens = 4097; },
    a => { a.usage.prompt_tokens_details.cached_tokens = 13; }, a => { delete a.actual_charge; }, a => { a.actual_charge.amount_micros = '0'; },
    a => { a.actual_charge.amount_micros = '16.0'; }, a => { a.actual_charge.evidence_label = 'ASSUMED'; }, a => { delete a.actual_charge.evidence_digest; }
  ];
  for (const change of changes) {
    const answer = syntheticAck(); change(answer); const f = cloudFixture({answer}), result = await f.broker.invoke(f.request);
    assert.equal(result.decision, 'HOLD'); assert.equal(result.accounting_status, 'UNKNOWN'); assert.equal(result.usage, null); assert.deepEqual(methods(f), ['reserve', 'markSending', 'unknown']); assert.equal(f.wires.length, 1);
  }
});
test('redirect, HTTP failure, truncated body, thrown transport and timeout hold once and do not leak upstream diagnostics', async () => {
  const providers = [
    async () => ({ok: true, status: 200, redirected: true}),
    async () => new Response('untrusted diagnostic', {status: 500}),
    async () => new Response('{', {status: 200, headers: {'content-type': 'application/json'}}),
    async () => { throw Object.assign(new Error('private provider diagnostic'), {code: 'PRIVATE_UPSTREAM_DIAGNOSTIC'}); },
    async () => new Promise(() => {})
  ];
  for (const transport of providers) {
    const f = cloudFixture({transport, timeoutMs: 20}), result = await f.broker.invoke(f.request);
    assert.equal(result.decision, 'HOLD'); assert.equal(f.wires.length, 1); assert.deepEqual(methods(f), ['reserve', 'markSending', 'unknown']);
    assert.ok(!JSON.stringify(result).includes('diagnostic'));
  }
});
test('uncertain settlement acknowledgement retains known usage in HOLD and never sends twice', async () => {
  const f = cloudFixture({overrides: {settle: () => { throw new Error('lost settlement acknowledgement'); }}}), result = await f.broker.invoke(f.request);
  assert.equal(result.decision, 'HOLD'); assert.equal(result.usage.actual_charge_micros, '16'); assert.deepEqual(methods(f), ['reserve', 'markSending', 'settle', 'unknown']); assert.equal(f.wires.length, 1);
});
test('logical-request reuse across separate broker instances cannot consume another reserve or wire', async () => {
  const f = cloudFixture(), second = createOfflineCloudModelBrokerForTests(f.options, f.testBinding);
  const [one, two] = await Promise.all([f.broker.invoke(f.request), second.invoke(f.request)]);
  assert.deepEqual([one.decision, two.decision].sort(), ['BLOCK', 'PROPOSED']); assert.equal(f.wires.length, 1); assert.equal(methods(f).filter(x => x === 'reserve').length, 1);
  const again = await second.invoke({...f.request, scope: {...f.request.scope, attempt_id: 'new_attempt_same_logical'}});
  assert.equal(again.reason, 'CLOUD_ATTEMPT_REUSED'); assert.equal(f.wires.length, 1);
});
test('worker mutation after request entry cannot change the immutable provider request', async () => {
  let release; const barrier = new Promise(resolve => { release = resolve; });
  const f = cloudFixture({inputTokenBound: async () => { await barrier; return true; }}), pending = f.broker.invoke(f.request);
  f.request.input.instruction = 'MUTATED_AFTER_ENTRY'; f.request.scope.worker_id = 'foreign_worker'; release();
  const result = await pending; assert.equal(result.decision, 'PROPOSED'); assert.ok(!JSON.stringify(f.wires).includes('MUTATED_AFTER_ENTRY'));
});
