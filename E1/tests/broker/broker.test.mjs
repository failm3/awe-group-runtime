import test from 'node:test';
import assert from 'node:assert/strict';
import {digest, validatePlanRevision, validateBoundValue} from '../../contracts/index.mjs';
import {createMaintenanceMission, createBrokerRegistry, selectExecutor, runPinnedScript, materializeHeadDraft, createLocalModelBroker, HEAD_DRAFT_SCHEMA, MODEL_POLICY} from '../../broker/index.mjs';
import {createOfflineModelBrokerForTests} from '../../broker/model.mjs';

const copy = value => structuredClone(value);
function draft() { return {reason: 'Numeric comparison is needed; preserve the array and request independent review.', tasks: [{task_id: 'inspect', title: 'Inspect supplied JSON', capability_id: 'e1.code.parse', instruction: 'Inspect supplied synthetic code and cases.', depends_on: [], criterion_ids: ['correctness']}, {task_id: 'review', title: 'Review numeric comparator and input preservation', capability_id: 'e1.code.review', instruction: 'Explain the lexicographic-sort defect and numerical comparator; check input preservation and independent QA.', depends_on: ['inspect'], criterion_ids: ['review']}]}; }
function ack(response = JSON.stringify(draft())) { return {model: MODEL_POLICY.model, created_at: '2026-11-08T00:00:00.000Z', response, done: true, done_reason: 'stop', prompt_eval_count: 123, eval_count: 55, total_duration: 1000000, eval_duration: 500000, load_duration: 1000, prompt_eval_duration: 499000}; }
const jsonResponse = value => new Response(JSON.stringify(value), {status: 200, headers: {'content-type': 'application/json'}});
function setup({answer = ack(), overrides = {}, transport: suppliedTransport, timeoutMs, clock} = {}) {
  const f = createMaintenanceMission(), calls = [], wires = [];
  // EXPLICIT OFFLINE TEST DOUBLE: a call recorder, never durable/native evidence.
  const accounting = Object.fromEntries(['reserve', 'markSending', 'settle', 'unknown', 'failBeforeSend'].map(method => [method, async request => { calls.push({method, request}); if (overrides[method]) return overrides[method](request); return {status: {reserve: 'RESERVED', markSending: 'SENDING', settle: 'CONFIRMED', unknown: 'UNKNOWN', failBeforeSend: 'FAILED'}[method]}; }]));
  const transport = async (url, options) => { wires.push({url, options}); if (suppliedTransport) return suppliedTransport(url, options); return jsonResponse(url.endsWith('/api/tags') ? {models: [{name: MODEL_POLICY.model, digest: MODEL_POLICY.digest, details: {parameter_size: '4.0B', quantization_level: 'Q4_K_M'}}]} : answer); };
  const broker = createOfflineModelBrokerForTests({accounting, registry: f.registry, ...(clock ? {clock} : {}), ...(timeoutMs ? {timeoutMs} : {})}, {transport, label: 'OFFLINE_TEST_DOUBLE'});
  const scope = {mission_id: f.spec.mission_id, task_id: 'head_control', logical_request_id: 'head_request', attempt_id: 'head_attempt', worker_id: 'e1_worker', fence: 1};
  const request = {scope, spec: f.spec, grant: f.grant, capability_id: 'e1.head.plan', input: {instruction: 'Review synthetic numerical-sort source.'}, data_label: 'SYNTHETIC'};
  const bridge = {spec: f.spec, grant: f.grant, capabilities: f.registry.descriptors, domainManifest: f.domainManifest, authority: f.authority, headContext: f.contexts.head, source: f.source, now: f.spec.facts_refs[0].created_at, plan_id: f.bootstrapPlan.plan_id, revision: 2, previous_digest: digest(f.bootstrapPlan)};
  return {f, calls, wires, accounting, broker, scope, request, bridge};
}

test('synthetic staging mission uses frozen A1 and selects two executor kinds with exclusion reasons', () => {
  const {f} = setup(); assert.equal(f.validation.decision, 'VALIDATED');
  for (const [kind, expected] of [['deterministic', 'script'], ['semantic', 'llm']]) {
    const selection = selectExecutor({registry: f.registry, task: {kind, data_label: 'SYNTHETIC'}, spec: f.spec, grant: f.grant});
    assert.equal(selection.decision, 'SELECTED'); assert.equal(selection.selected.descriptor.executor_kind, expected); assert.ok(selection.rejected.length >= 2); assert.equal(selection.accepted, false);
  }
  const parsed = runPinnedScript({registry: f.registry, spec: f.spec, grant: f.grant, input: f.bootstrapPlan.tasks[0].input});
  assert.equal(JSON.parse(parsed.output.text).synthetic, true); assert.equal(parsed.effects, 0);
});
test('model draft actually controls task text and dependency edges, while code owns all protected metadata', () => {
  const {bridge} = setup(), first = materializeHeadDraft(draft(), bridge), changed = draft();
  changed.tasks[1].task_id = 'semantic_check'; changed.tasks[1].title = 'Check numbers independently';
  const second = materializeHeadDraft(changed, bridge); assert.notEqual(digest(first.plan), digest(second.plan));
  assert.equal(second.plan.tasks[1].task_id, 'semantic_check'); assert.deepEqual(second.plan.tasks[1].depends_on, ['inspect']);
  assert.equal(first.plan.grant_digest, digest(bridge.grant)); assert.equal(first.plan.tasks[0].effect.effect_class, 'NONE'); assert.equal(first.accepted, false);
  assert.equal(validatePlanRevision(first.plan, {...bridge, domainManifest: bridge.domainManifest}).decision, 'VALIDATED');
});
test('protected additions, absent tools, cycles and invented criteria cannot materialize', () => {
  const {bridge} = setup();
  for (const change of [x => { x.accepted = true; }, x => { x.grant = {permissions: ['shell']}; }, x => { x.budget = {amount_micros: '99'}; }, x => { x.tasks[0].capability_id = 'shell.execute'; }, x => { x.tasks[0].depends_on = ['review']; }, x => { x.tasks[0].criterion_ids = ['invented']; }]) {
    const value = draft(); change(value); assert.throws(() => materializeHeadDraft(value, bridge));
  }
  const alteredSource = {...copy(bridge.source), filename: 'foreign.mjs'}; assert.throws(() => materializeHeadDraft(draft(), {...bridge, source: alteredSource}), error => error.code === 'A3_SOURCE_BINDING');
});
test('live factory has mandatory trusted accounting and rejects endpoint/test-transport overrides', () => {
  const {accounting, f} = setup();
  assert.throws(() => createLocalModelBroker({registry: f.registry}), error => error.code === 'A3_ACCOUNTING_REQUIRED');
  assert.throws(() => createLocalModelBroker({accounting, registry: f.registry, endpoint: 'https://cloud.invalid'}), error => error.code === 'A3_ENDPOINT_DENIED');
  assert.throws(() => createLocalModelBroker({accounting, registry: f.registry, fetchImpl: async () => {}}), error => error.code === 'A3_TEST_TRANSPORT_DENIED');
});
test('one structured wire attempt records backend usage after durable reserve and SENDING', async () => {
  const s = setup(), result = await s.broker.invoke(s.request);
  assert.equal(result.decision, 'PROPOSED'); assert.equal(result.evidence_level, 'OFFLINE_TEST_DOUBLE');
  assert.deepEqual(s.calls.map(x => x.method), ['reserve', 'markSending', 'settle']); assert.equal(s.wires.filter(x => x.options.method === 'POST').length, 1);
  assert.equal(s.calls[0].request.capability_id, 'e1.head.plan'); assert.equal(s.calls[0].request.reserve_micros, 0); assert.equal(s.calls[0].request.quota_units, 1);
  const body = JSON.parse(s.wires[1].options.body); assert.equal(body.stream, false); assert.deepEqual(body.format, HEAD_DRAFT_SCHEMA); assert.equal(body.options.num_ctx, 4096); assert.equal(body.options.num_predict, 1024); assert.equal(body.model, MODEL_POLICY.model);
  assert.equal(result.usage.input_tokens, 123); assert.equal(result.usage.output_tokens, 55); assert.equal(result.usage.digest, MODEL_POLICY.digest); assert.ok(Number.isFinite(result.usage.latency_ms));
});
test('normal Head bridge creates a model-controlled next revision without acceptance', async () => {
  const s = setup(); const result = await s.broker.generateHeadProposal({...s.bridge, scope: s.scope});
  assert.equal(result.decision, 'PROPOSED'); assert.equal(result.plan.revision, 2); assert.equal(result.plan.tasks[1].task_id, 'review'); assert.equal(result.accepted, false);
});
test('forged Head context is blocked before all wire operations', async () => {
  const s = setup(), result = await s.broker.generateHeadProposal({...s.bridge, headContext: {principal_id: 'e1_head', project_id: s.f.spec.project_id}, scope: s.scope});
  assert.equal(result.decision, 'BLOCK'); assert.equal(s.wires.length, 0); assert.equal(s.calls.length, 0);
});
test('privacy, permission, missing tool, unknown lineage and expired grant deny before metadata/inference', async () => {
  for (const edit of [
    request => { request.input.instruction = 'Personal contact alice@example.invalid'; },
    request => { request.data_label = 'PERSONAL'; },
    request => { request.grant.permissions = request.grant.permissions.filter(x => x !== 'artifact.read'); },
    request => { request.capability_id = 'absent.tool'; },
    request => { request.grant.expires_at = request.grant.issued_at; },
    request => { request.spec.data_classes = ['PERSONAL']; request.grant.allowed_data_classes = ['PERSONAL']; request.grant.spec_digest = digest(request.spec); },
    request => { request.spec.allowed_origins = ['EXTERNAL']; request.grant.allowed_origins = ['EXTERNAL']; request.grant.spec_digest = digest(request.spec); }
  ]) {
    const s = setup(), request = copy(s.request); edit(request); const result = await s.broker.invoke(request); assert.ok(['BLOCK', 'WAIT'].includes(result.decision)); assert.equal(result.wire_attempts, 0); assert.equal(s.wires.length, 0); assert.equal(s.calls.length, 0);
  }
});
test('backend digest mismatch prevents reservation and inference', async () => {
  const s = setup({transport: () => jsonResponse({models: [{name: MODEL_POLICY.model, digest: 'bad'}]})}), result = await s.broker.invoke(s.request);
  assert.equal(result.reason, 'A3_MODEL_PIN_MISMATCH'); assert.equal(s.calls.length, 0); assert.equal(s.wires.length, 1);
});
test('reservation and markSending failures never send generation', async () => {
  for (const method of ['reserve', 'markSending']) {
    const s = setup({overrides: {[method]: () => { throw Object.assign(new Error('deny'), {code: 'A2_DENIED'}); }}}), result = await s.broker.invoke(s.request);
    assert.equal(result.decision, 'WAIT'); assert.equal(s.wires.filter(x => x.options.method === 'POST').length, 0); assert.equal(result.wire_attempts, 0);
    if (method === 'markSending') assert.equal(s.calls.at(-1).request.reason, 'A3_MARK_SENDING_UNCERTAIN');
  }
});
test('grant expiry immediately after durable reserve proves no wire and releases the SAME A2 reservation/quota', async () => {
  let current = new Date().toISOString(), quota = 0;
  const s = setup({clock: () => current, overrides: {reserve: () => { quota++; current = '2099-01-01T00:00:00.000Z'; return {status: 'RESERVED'}; }, failBeforeSend: () => { quota--; return {status: 'FAILED'}; }}});
  const result = await s.broker.invoke(s.request);
  assert.equal(result.decision, 'BLOCK'); assert.equal(result.accounting_status, 'FAILED'); assert.equal(result.reservation_released, true); assert.equal(result.wire_attempts, 0); assert.equal(quota, 0);
  assert.deepEqual(s.calls.map(x => x.method), ['reserve', 'failBeforeSend']); assert.equal(s.wires.filter(x => x.options.method === 'POST').length, 0);
});
test('uncertain reserve commit never releases blindly and retains UNKNOWN without model wire', async () => {
  const s = setup({overrides: {reserve: () => { throw new Error('Synthetic response loss after commit'); }}}), result = await s.broker.invoke(s.request);
  assert.equal(result.decision, 'WAIT'); assert.equal(result.reason, 'A3_RESERVATION_UNCERTAIN'); assert.equal(result.accounting_status, 'UNKNOWN');
  assert.deepEqual(s.calls.map(x => x.method), ['reserve', 'unknown']); assert.equal(result.wire_attempts, 0);
});
test('malformed JSON, tool misuse and budget escalation settle actual consumed usage then request REPAIR', async () => {
  for (const response of ['not-json', JSON.stringify({...draft(), accepted: true}), JSON.stringify({tool_calls: [{name: 'shell'}]}), JSON.stringify({...draft(), budget: 100})]) {
    const s = setup({answer: ack(response)}), result = await s.broker.invoke(s.request);
    assert.equal(result.decision, 'REPAIR'); assert.equal(result.accounting_status, 'CONFIRMED'); assert.equal(s.calls.filter(x => x.method === 'settle').length, 1); assert.equal(result.wire_attempts, 1); assert.equal(result.effects, 0);
  }
});
test('possible-send timeout goes UNKNOWN/HOLD once without hidden retry or fallback', async () => {
  const s = setup({timeoutMs: 25, transport: (url, options) => url.endsWith('/api/tags') ? jsonResponse({models: [{name: MODEL_POLICY.model, digest: MODEL_POLICY.digest}]}) : new Promise((resolve, reject) => options.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), {name: 'AbortError'})), {once: true}))});
  const result = await s.broker.invoke(s.request); assert.equal(result.decision, 'WAIT'); assert.equal(result.accounting_status, 'UNKNOWN'); assert.equal(result.wire_attempts, 1);
  assert.deepEqual(s.calls.map(x => x.method), ['reserve', 'markSending', 'unknown']); assert.equal(s.wires.filter(x => x.options.method === 'POST').length, 1);
});
test('missing backend usage and settlement failure cannot report success', async () => {
  const missing = ack(); delete missing.eval_count;
  for (const options of [{answer: missing}, {overrides: {settle: () => { throw new Error('DB lost'); }}}]) {
    const s = setup(options), result = await s.broker.invoke(s.request); assert.equal(result.decision, 'WAIT'); assert.equal(result.accounting_status, 'UNKNOWN'); assert.ok(s.calls.some(x => x.method === 'unknown'));
  }
});
test('module-wide semaphore permits only one concurrent inference across broker instances', async () => {
  let release, started; const didStart = new Promise(resolve => { started = resolve; });
  const s = setup({transport: (url) => url.endsWith('/api/tags') ? jsonResponse({models: [{name: MODEL_POLICY.model, digest: MODEL_POLICY.digest}]}) : new Promise(resolve => { release = () => resolve(jsonResponse(ack())); started(); })});
  const first = s.broker.invoke(s.request); await didStart;
  const other = setup(), second = await other.broker.invoke(other.request); assert.equal(second.reason, 'A3_MODEL_BUSY'); assert.equal(other.wires.length, 0);
  release(); assert.equal((await first).decision, 'PROPOSED');
});
test('raw JSON schema rejects model-provided acceptance and arbitrary object fields', () => {
  assert.throws(() => validateBoundValue(HEAD_DRAFT_SCHEMA, {...draft(), accepted: true}));
});
test('concise owner mission changes only goal/criteria and fully rebinds new spec, grant and bootstrap', () => {
  const now = new Date().toISOString(), registry = createBrokerRegistry({now});
  const ordinary = createMaintenanceMission({now, registry, suffix: 'ordinary'}), short = createMaintenanceMission({now, registry, suffix: 'concise', concise: true});
  assert.match(short.spec.goal, /exactly two/); assert.match(short.spec.goal, /250 tokens/);
  for (const denied of ['No code execution', 'shell', 'network tools', 'publication', 'new product ideas']) assert.ok(short.spec.goal.includes(denied));
  assert.notEqual(short.spec.mission_id, ordinary.spec.mission_id); assert.notEqual(digest(short.spec), digest(ordinary.spec));
  assert.equal(short.grant.spec_digest, digest(short.spec)); assert.equal(short.bootstrapPlan.spec_digest, digest(short.spec)); assert.equal(short.bootstrapPlan.grant_digest, digest(short.grant));
  for (const key of ['permissions', 'allowed_capabilities', 'allowed_data_classes', 'allowed_origins', 'allowed_effect_classes', 'destinations', 'max_tasks', 'max_actions', 'max_replans', 'budget_cap']) assert.deepEqual(short.grant[key], ordinary.grant[key]);
  assert.deepEqual(short.registry.descriptors, ordinary.registry.descriptors); assert.deepEqual(short.source, ordinary.source); assert.equal(short.validation.decision, 'VALIDATED');
  assert.equal(validatePlanRevision(short.bootstrapPlan, {spec: short.spec, grant: short.grant, capabilities: registry.descriptors, domainManifest: short.domainManifest, now}).decision, 'VALIDATED');
  assert.throws(() => createMaintenanceMission({now, registry, concise: 1}), error => error.code === 'A3_FIXTURE_CONCISE');
});

for (const [label, response] of [['valid JSON', JSON.stringify(draft())], ['truncated JSON', '{"reason":"Truncated draft","tasks":[']]) test('completed length ACK with ' + label + ' settles usage once and never proposes a plan', async () => {
  let quotaUsed = 0, spentMicros = 0;
  const answer = {...ack(response), done_reason: 'length'};
  const s = setup({answer, overrides: {
    reserve: request => { quotaUsed += request.quota_units; return {status: 'RESERVED'}; },
    settle: request => { spentMicros += request.actual_cost_micros; return {status: 'CONFIRMED'}; }
  }});
  const result = await s.broker.invoke(s.request);
  assert.equal(result.decision, 'REPAIR'); assert.equal(result.reason, 'A3_OUTPUT_TRUNCATED'); assert.equal(result.accounting_status, 'CONFIRMED');
  assert.equal(result.wire_attempts, 1); assert.equal(result.usage.input_tokens, answer.prompt_eval_count); assert.equal(result.usage.output_tokens, answer.eval_count); assert.equal(result.response_digest, digest({response}));
  assert.equal(Object.hasOwn(result, 'output'), false); assert.equal(Object.hasOwn(result, 'plan'), false); assert.equal(Object.hasOwn(result, 'draft'), false); assert.equal(result.effects, 0); assert.equal(result.accepted, false);
  assert.deepEqual(s.calls.map(call => call.method), ['reserve', 'markSending', 'settle']); assert.equal(s.wires.filter(wire => wire.options.method === 'POST').length, 1);
  assert.equal(quotaUsed, 1); assert.equal(spentMicros, 0); assert.equal(s.calls.some(call => call.method === 'unknown' || call.method === 'failBeforeSend'), false);
});
test('unrecognized done reason remains UNKNOWN without usage settlement or proposal', async () => {
  const s = setup({answer: {...ack(), done_reason: 'unsupported_reason'}}), result = await s.broker.invoke(s.request);
  assert.equal(result.decision, 'WAIT'); assert.equal(result.reason, 'A3_OUTCOME_UNKNOWN'); assert.equal(result.accounting_status, 'UNKNOWN'); assert.equal(result.wire_attempts, 1);
  assert.deepEqual(s.calls.map(call => call.method), ['reserve', 'markSending', 'unknown']); assert.equal(Object.hasOwn(result, 'output'), false);
});
