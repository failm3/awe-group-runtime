import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../../contracts/canonical.mjs';
import {validateShape} from '../../contracts/schema-validator.mjs';
import {createOfflineSecurity} from '../../awe/policy/security.mjs';
import {parseIntent} from '../../awe/policy/json.mjs';
import {createRecordingSink} from '../../awe/sandbox/recording-sink.mjs';
import {setup, world, hash, text} from './helpers.mjs';
import {negatives, runNegative} from './fixture-results.mjs';

const deny = (h, reason, context = h.auth, intent = h.intent) => {
  const before = h.control.inspect();
  const result = h.worker.execute(context, text(intent));
  assert.equal(result.decision, 'DENY');
  if (reason) assert.equal(result.reason, reason);
  assert.deepEqual(h.control.inspect(), before, 'DENY before effect/quota/approval consumption');
  return result;
};
const child = (h, patch = {}) => ({...structuredClone(h.grant), run_id: 'run_child',
  parent_run_id: h.grant.run_id, depth: 1, max_children: 0, max_physical_attempts: 1, ...patch});
const addApproval = (h, patch = {}, subject = h.intent.actor.identity_id) => {
  const dto = {...structuredClone(h.approval), approval_id: 'appr_second', ...patch};
  h.control.registerApproval(h.owner, dto, subject); return dto;
};

for (const row of negatives) test(`${row.criterion}/${row.id} ${row.name}: deny before effect`, () => runNegative(row));

for (const action of ['publish', 'delete', 'charge', 'send_sensitive', 'inference', 'read'])
  test(`M02/P01 ${action}: only synthetic recording, exactly one approval/quota/attempt consumed`, () => {
    const h = setup({action});
    const before = h.control.inspect();
    assert.equal(h.worker.pdp(h.auth, text(h.intent)).decision, 'ALLOW_SIMULATION');
    assert.deepEqual(h.control.inspect(), before, 'PDP is advisory and side-effect free');
    assert.equal(h.worker.execute(h.auth, text(h.intent)).decision, 'RECORDED_SIMULATION');
    const after = h.control.inspect();
    assert.equal(after.effects.length, 1); assert.equal(after.quotas[0].remaining_micros, '90');
    assert.equal(after.approvals[0].used, true); assert.equal(after.grants[0].remaining, 4);
    deny(h, 'APPROVAL_UNUSABLE');
  });

test('M02/P02 D-01 v1 DTOs are consumed without schema extensions', () => {
  const h = setup({action: 'inference'});
  for (const [name, dto] of [['approval', h.approval], ['tool-capability', h.capability],
    ['run-grant', h.grant], ['provider-price', h.quote]]) assert.deepEqual(validateShape(name, dto), []);
});
test('M02/A01 forged AuthContext, JSON context and foreign-instance context are refused', () => {
  const h = setup(), other = setup();
  for (const c of [{}, structuredClone(h.auth), other.auth]) deny(h, 'AUTH_CONTEXT_INVALID', c);
});
test('M02/A02 synthetic sessions cannot be invented, serialized or reused across issuers', () => {
  const h = setup(), other = setup();
  for (const session of [{identity_id: 'act_owner'}, {}, other.control.issueSession('act_executor')])
    assert.throws(() => h.worker.authenticate(session, h.intent.scope), /SESSION_INVALID/);
  assert.throws(() => h.control.issueSession('act_unknown'), /PRINCIPAL_UNKNOWN/);
});
test('M02/A03 AuthContext is immutable and cannot widen scope', () => {
  const h = setup(); assert(Object.isFrozen(h.auth)); assert(Object.isFrozen(h.auth.actor));
  assert.throws(() => { h.auth.actor.role = 'OWNER'; }, TypeError);
  assert.throws(() => h.worker.authenticate(h.control.issueSession('act_executor'),
    {...h.intent.scope, task_id: 'task_other'}), /SCOPE_DENIED/);
});
test('M02/A04 registry rejects unknown role alias', () => {
  const seed = world(); seed.principals[2].actor.role = 'runner';
  assert.throws(() => createOfflineSecurity(seed), /INVALID_ACTOR-REF/);
});
test('M02/A05 registry never aliases producer, Examiner and Auditor subjects', () => {
  for (const pair of [[2, 4], [2, 5], [4, 5]]) {
    const seed = world(); seed.principals[pair[1]].subject = seed.principals[pair[0]].subject;
    assert.throws(() => createOfflineSecurity(seed), /QA_SUBJECT_CONFLICT/);
  }
});
test('M02/A06 worker has no issuer, approval writer, registry or raw journal', () => {
  const h = setup();
  assert.deepEqual(Object.keys(h.worker).sort(), ['authenticate', 'directDispatch', 'execute', 'pdp']);
  assert.equal(h.worker.issueSession, undefined); assert.equal(h.worker.control, undefined);
});
for (const key of ['policy', 'auth', 'stop', 'owner'])
  test(`M02/R01-${key} revoke epoch after PDP/enqueue: execution rechecks`, () => {
    const h = setup(); assert.equal(h.worker.pdp(h.auth, text(h.intent)).decision, 'ALLOW_SIMULATION');
    h.control.advanceEpoch('prj_site_zhiv', key); deny(h, 'AUTH_EPOCH_REVOKED');
  });
for (const id of ['act_executor', 'act_owner', 'act_supervisor'])
  test(`M02/R02-${id} identity revocation is checked at execution`, () => {
    const h = setup(); assert.equal(h.worker.pdp(h.auth, text(h.intent)).decision, 'ALLOW_SIMULATION');
    h.control.revokeIdentity(id); deny(h, id === 'act_executor' ? 'AUTH_CONTEXT_INVALID' :
      id === 'act_owner' ? 'APPROVER_REVOKED' : 'TOOL_ISSUER_REVOKED');
  });
for (const [method, id, reason] of [['revokeApproval', 'appr_once', 'APPROVAL_UNUSABLE'],
  ['revokeGrant', 'run_parent', 'GRANT_REVOKED_OR_UNKNOWN'], ['revokeTool', 'tool_recorder', 'TOOL_UNKNOWN']])
  test(`M02/R03-${method} revocation after PDP`, () => {
    const h = setup(); h.worker.pdp(h.auth, text(h.intent)); h.control[method](id); deny(h, reason);
  });
test('M02/R04 cancelled queued action cannot execute, even with refreshed context', () => {
  const h = setup(); h.control.cancel('prj_site_zhiv'); deny(h, 'AUTH_EPOCH_REVOKED');
  const fresh = h.ctx('act_executor'); deny(h, 'STOP_OR_CANCEL', fresh);
});
for (const state of ['COMPLETE', 'CANCELLED', 'FAILED', 'CANCELLING'])
  test(`M02/R05-${state} terminal/cancelling state denies effect`, () => {
    const h = setup(); h.control.setTaskState(h.intent.scope, state, 4); deny(h, 'STOP_OR_CANCEL');
    assert.throws(() => h.control.setTaskState(h.intent.scope, 'RUNNING', 5), /TERMINAL_IMMUTABLE/);
  });
test('M02/R06 unknown policy and policy mutation fail closed', () => {
  const seed = world(); seed.projects[0].policy_id = 'unknown-policy';
  const h = setup({seed}); deny(h, 'POLICY_UNKNOWN');
});
test('M02/R07 revised task invalidates queued intent', () => {
  const h = setup(); h.control.setTaskState(h.intent.scope, 'RUNNING', 4); deny(h, 'STALE_STATE');
});
test('M02/R08 expired approval at exact boundary denies without consumption', () => {
  let time = '2026-11-05T12:00:00.000Z'; const h = setup({clock: () => time});
  addApproval(h, {expires_at: '2026-11-05T12:00:01.000Z'}); h.intent.approval_id = 'appr_second';
  time = '2026-11-05T12:00:01.000Z'; deny(h, 'APPROVAL_STALE');
});
test('M02/R09 changed payload with recomputed hash still mismatches action-bound approval', () => {
  const h = setup(); h.intent.payload.recipient = 'another-synthetic-recipient';
  h.intent.payload_hash = digest(h.intent.payload); deny(h, 'APPROVAL_BINDING_MISMATCH');
});
test('M02/R10 action, resource and execution subject are independently approval-bound', () => {
  const h = setup();
  addApproval(h, {resource: 'site:memory'}); h.intent.approval_id = 'appr_second'; deny(h, 'APPROVAL_BINDING_MISMATCH');
  const j = setup(); addApproval(j, {action: 'delete'}); j.intent.approval_id = 'appr_second'; deny(j, 'APPROVAL_BINDING_MISMATCH');
  const k = setup(); addApproval(k, {}, 'act_child'); k.intent.approval_id = 'appr_second'; deny(k, 'APPROVAL_BINDING_MISMATCH');
});
test('M02/R11 operation replay denied with fresh approval and changed payload', () => {
  const h = setup(); assert.equal(h.worker.execute(h.auth, text(h.intent)).decision, 'RECORDED_SIMULATION');
  h.intent.payload.content = 'changed'; h.intent.payload_hash = digest(h.intent.payload);
  addApproval(h, {payload_hash: h.intent.payload_hash}); h.intent.approval_id = 'appr_second'; deny(h, 'OPERATION_REPLAY');
});
test('M02/R12 20 simultaneous promises produce one recording, one spend', async () => {
  const h = setup(); const results = await Promise.all(Array.from({length: 20}, () =>
    Promise.resolve().then(() => h.worker.execute(h.auth, text(h.intent)))));
  assert.equal(results.filter(r => r.decision === 'RECORDED_SIMULATION').length, 1);
  assert.equal(h.control.inspect().effects.length, 1); assert.equal(h.control.inspect().quotas[0].remaining_micros, '90');
});
test('M02/R13 approval is immutable and cannot be reset after use/revoke', () => {
  const h = setup(); h.worker.execute(h.auth, text(h.intent));
  assert.throws(() => h.control.registerApproval(h.owner, h.approval, 'act_executor'), /APPROVAL_IMMUTABLE/);
});
test('M02/R14 forged, used, revoked and wrong-version approvals rejected at registration', () => {
  for (const patch of [{uses: 1}, {revoked_at: '2026-11-05T11:59:30.000Z'}, {schema_version: '1.1.0'},
    {actor: {identity_id: 'act_executor', role: 'EXECUTOR'}}, {epochs: {policy: 2, auth: 1, stop: 0, owner: 1}}]) {
    const h = setup(); assert.throws(() => addApproval(h, patch), /CONTRACT_DENIED/);
  }
});
for (const quoteStatus of ['UNKNOWN', 'QUOTED'])
  test(`M02/Q01-${quoteStatus} unknown/expired quote denies before effect`, () => {
    let time = '2026-11-05T12:00:00.000Z';
    const h = setup({action: 'inference', quoteStatus, clock: () => time});
    if (quoteStatus === 'QUOTED') time = '2026-11-05T12:01:00.000Z';
    deny(h, 'QUOTE_UNKNOWN_OR_STALE');
  });
test('M02/Q02 unregistered quote id rejected; no caller supplied quote authority', () => {
  const h = setup({action: 'charge'}); h.intent.quote_id = 'price_unknown'; deny(h, 'QUOTE_UNKNOWN');
});
test('M02/Q03 quota smaller than exact trusted tariff denies', () => {
  const seed = world(); seed.projects[0].tasks[0].quota_micros = '9';
  deny(setup({seed}), 'QUOTA_EXCEEDED');
});
test('M02/Q04 integer quota handles large micros without floating point', () => {
  const seed = world(); seed.projects[0].tasks[0].quota_micros = '999999999999999999999999999999';
  const h = setup({seed}); h.worker.execute(h.auth, text(h.intent));
  assert.equal(h.control.inspect().quotas[0].remaining_micros, '999999999999999999999999999989');
});
test('M02/Q05 revoking a registered quote after PDP denies before effect', () => {
  const h = setup({action: 'inference'});
  assert.equal(h.worker.pdp(h.auth, text(h.intent)).decision, 'ALLOW_SIMULATION');
  h.control.revokeQuote('price_synthetic'); deny(h, 'QUOTE_UNKNOWN');
});
test('M02/Q06 quote issuer revocation is independent of tool/grant issuer', () => {
  const seed = world(), secondary = structuredClone(seed.principals[1]);
  secondary.actor.identity_id = 'act_quote_issuer'; secondary.subject = 'synthetic-quote-issuer';
  seed.principals.push(secondary);
  const h = setup({seed, action: 'inference'});
  const quote = {...h.quote, price_profile_id: 'price_secondary'};
  h.control.registerQuote(h.ctx('act_quote_issuer'), quote, {scope: h.intent.scope, tool_id: h.capability.tool_id});
  h.intent.quote_id = quote.price_profile_id;
  assert.equal(h.worker.pdp(h.auth, text(h.intent)).decision, 'ALLOW_SIMULATION');
  h.control.revokeIdentity('act_quote_issuer'); deny(h, 'QUOTE_ISSUER_REVOKED');
});
test('M12/C01 narrowed child grant executes and consumes shared parent attempt/quota', () => {
  const h = setup(); const dto = child(h);
  h.control.registerGrant(h.supervisor, dto, 'act_child'); addApproval(h, {}, 'act_child');
  const intent = {...h.intent, actor: {identity_id: 'act_child', role: 'EXECUTOR'}, run_id: dto.run_id, approval_id: 'appr_second'};
  const auth = h.ctx('act_child'); assert.equal(h.worker.execute(auth, text(intent)).decision, 'RECORDED_SIMULATION');
  assert.deepEqual(h.control.inspect().grants.map(g => g.remaining), [4, 0]);
  deny(h, 'GRANT_CAPABILITY_DENIED', auth, intent);
});
for (const [name, patch] of [
  ['capabilities', {capabilities: ['tool_unregistered']}], ['attempts', {max_physical_attempts: 6}],
  ['deadline', {deadline: '2026-11-05T12:06:00.000Z'}], ['budget', {budget_ref: hash('5')}],
  ['config', {config_hash: hash('5')}], ['manifest', {manifest_hash: hash('5')}],
  ['children', {max_children: 1}], ['depth', {depth: 0}],
  ['foreign task', {scope: {project_id: 'prj_site_zhiv', task_id: 'task_other', operation_id: 'op_synthetic'}}]
]) test(`M12/C02-${name} child escalation denied`, () => {
  const h = setup(), before = h.control.inspect();
  assert.throws(() => h.control.registerGrant(h.supervisor, child(h, patch), 'act_child'));
  assert.deepEqual(h.control.inspect(), before);
});
test('M12/C03 parent revoke disables existing child; child counts capped', () => {
  const h = setup(); h.control.registerGrant(h.supervisor, child(h), 'act_child');
  h.control.registerGrant(h.supervisor, child(h, {run_id: 'run_child_two'}), 'act_child');
  assert.throws(() => h.control.registerGrant(h.supervisor, child(h, {run_id: 'run_child_three'}), 'act_child'), /CHILD_LIMIT/);
  addApproval(h, {}, 'act_child'); h.control.revokeGrant('run_parent');
  const intent = {...h.intent, actor: {identity_id: 'act_child', role: 'EXECUTOR'}, run_id: 'run_child', approval_id: 'appr_second'};
  deny(h, 'GRANT_REVOKED_OR_UNKNOWN', h.ctx('act_child'), intent);
});
test('M12/C04 grandchild and zero-attempt grants denied', () => {
  const h = setup(); h.control.registerGrant(h.supervisor, child(h), 'act_child');
  assert.throws(() => h.control.registerGrant(h.supervisor, child(h, {parent_run_id: 'run_child', run_id: 'run_grandchild'}), 'act_child'), /CHILD_LIMIT/);
  const j = setup({attempts: 0}); deny(j, 'GRANT_CAPABILITY_DENIED');
});
test('M12/C05 revoking the parent subject disables descendant grants', () => {
  const h = setup(); h.control.registerGrant(h.supervisor, child(h), 'act_child');
  addApproval(h, {}, 'act_child'); h.control.revokeIdentity('act_executor');
  const intent = {...h.intent, actor: {identity_id: 'act_child', role: 'EXECUTOR'}, run_id: 'run_child', approval_id: 'appr_second'};
  deny(h, 'GRANT_SUBJECT_REVOKED', h.ctx('act_child'), intent);
});
test('M02/R15 a previous retrieval does not authorize another read after revoke', () => {
  const h = setup({action: 'read', resource: 'site:memory'});
  assert.equal(h.worker.execute(h.auth, text(h.intent)).decision, 'RECORDED_SIMULATION');
  addApproval(h); h.intent.approval_id = 'appr_second';
  h.control.advanceEpoch('prj_site_zhiv', 'auth'); deny(h, 'AUTH_EPOCH_REVOKED');
});
test('M12/B01 direct worker bypass has no PEP ticket and no side effect', () => {
  const h = setup(), before = h.control.inspect();
  for (const ticket of [{}, {decision: 'ALLOW_SIMULATION'}, h.auth])
    assert.deepEqual(h.worker.directDispatch(ticket, text(h.intent)), {decision: 'DENY', reason: 'PEP_TICKET_REQUIRED'});
  assert.deepEqual(h.control.inspect(), before);
});
test('M12/B02 sink tickets are body/instance bound and one-use', () => {
  const a = createRecordingSink(), b = createRecordingSink(), intent = {synthetic: 'one'};
  const ticket = a.mint(intent);
  assert.equal(a.dispatch(ticket, {synthetic: 'changed'}).decision, 'DENY');
  assert.equal(b.dispatch(ticket, intent).decision, 'DENY');
  assert.equal(a.dispatch(ticket, intent).decision, 'RECORDED_SIMULATION');
  assert.equal(a.dispatch(ticket, intent).decision, 'DENY'); assert.equal(a.inspect().length, 1);
});
test('M12/B03 output size gate precedes read and all consumption', () => {
  const h = setup({action: 'read', outputLimit: 8}); deny(h, 'OUTPUT_TOO_LARGE');
});
test('M03/V01 same-project scoped memory is readable', () => {
  const h = setup({action: 'read', resource: 'site:memory'});
  assert.deepEqual(h.worker.execute(h.auth, text(h.intent)).value, {text: 'synthetic project memory'});
});
for (const role of ['EXAMINER', 'AUDITOR'])
  test(`M03/V02-${role} independent QA cannot see local verdict`, () => {
    const h = setup({role, action: 'read', resource: 'site:local-qa'});
    assert(!JSON.stringify(deny(h, 'BLIND_QA_DENIED')).includes('SYNTHETIC_LOCAL_VERDICT'));
  });
test('M03/V03 only Examiner reads hidden test inputs', () => {
  const h = setup({role: 'EXAMINER', action: 'read', resource: 'site:hidden'});
  assert.equal(h.worker.execute(h.auth, text(h.intent)).value.canary, 'SYNTHETIC_HIDDEN_QA_CANARY');
  deny(setup({role: 'AUDITOR', action: 'read', resource: 'site:hidden'}), 'HIDDEN_QA_DENIED');
});
test('M03/V04 Auditor trace is fixed metadata projection without raw or hidden data', () => {
  const h = setup({role: 'AUDITOR', action: 'read', resource: 'site:trace'});
  const result = h.worker.execute(h.auth, text(h.intent));
  assert.deepEqual(result.value, {kind: 'TRACE', operation_id: 'op_synthetic', status: 'SIMULATED'});
  assert(!text(result).includes('CANARY')); assert(!text(result).includes('hidden_context'));
});
test('M03/V05 Examiner cannot read raw trace and Executor cannot read hidden QA via alternate action', () => {
  deny(setup({role: 'EXAMINER', action: 'read', resource: 'site:trace'}), 'TRACE_DENIED');
  for (const action of ['read', 'publish', 'inference']) deny(setup({action, resource: 'site:hidden'}), 'HIDDEN_QA_DENIED');
});
test('M03/V06 no foreign canary in denied responses, even for unknown resource', () => {
  for (const resource of ['foreign:tool', 'foreign:memory', 'foreign:evidence', 'foreign:absent']) {
    const h = setup({action: 'read'}); h.intent.resource = resource;
    const result = deny(h, 'RESOURCE_SCOPE_DENIED'); assert(!text(result).includes('CANARY'));
  }
});
test('M02/J01 duplicate JSON keys, including escaped key aliases, are denied', () => {
  const h = setup();
  for (const suffix of ['"actor":{}', '"\\u0061ctor":{}']) {
    const raw = text(h.intent).slice(0, -1) + ',' + suffix + '}';
    assert.equal(h.worker.execute(h.auth, raw).reason, 'DUPLICATE_KEY');
  }
});
test('M02/J02 non-JSON objects/accessors never execute at worker effect boundary', () => {
  const h = setup(); let calls = 0;
  const value = {get actor() { calls++; throw new Error('must not run'); }};
  assert.equal(h.worker.execute(h.auth, value).reason, 'BOUNDED_JSON_TEXT_REQUIRED'); assert.equal(calls, 0);
});
test('M02/J03 malformed, unsafe, oversized or noncanonical JSON is denied', () => {
  const h = setup();
  for (const raw of ['', '{}{}', '{"a":1,}', '{"a":01}', '{"a":1.5}', '{"a":-0}',
    '{"__proto__":{}}', '{"a":"\\ud800"}', '['.repeat(34) + '0' + ']'.repeat(34), ' '.repeat(65537)])
    assert.equal(h.worker.execute(h.auth, raw).decision, 'DENY');
  assert.deepEqual(parseIntent(' { "text" : "\\\"/\\\\\\n", "n":1, "a":[true,null,false] } '),
    {text: '"/\\\n', n: 1, a: [true, null, false]});
});
test('M02/T01 invalid clock and rollback fail closed', () => {
  let time = '2026-11-05T12:00:00.000Z'; const h = setup({clock: () => time});
  time = '2026-11-05T11:59:59.000Z'; deny(h, 'CLOCK_ROLLBACK');
  time = 'invalid'; deny(h, 'CLOCK_INVALID');
});
test('M02/T02 only synthetic mode can construct this implementation', () => {
  const seed = world(); seed.mode = 'PRODUCTION'; assert.throws(() => createOfflineSecurity(seed), /SIMULATION_REQUIRED/);
});
