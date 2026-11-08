import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../../contracts/canonical.mjs';
import {validateShape} from '../../contracts/schema-validator.mjs';
import {createRuntimeAdapter} from '../../awe/runtime/adapter.mjs';
import {createFakeHermesTransport, selectModelRow} from '../../awe/runtime/fake-hermes.mjs';
import {createToolRegistry} from '../../awe/tools/registry.mjs';
import {runtimeFixture, ready} from './fixtures.mjs';

const denied = result => { assert.equal(result.decision, 'DENY', JSON.stringify(result)); assert.equal(result.physical_decision, 'DENY'); };
const noEffects = f => { assert.equal(f.inspect().effects.length, 0); assert.equal(f.operation().attempts, 0);
  assert.equal(f.inspect().actual_external_dispatches, 0); };

test('R01 bounded parent-child-tool canary through real E0 authentication/state seams, work != QA', async () => {
  const f = await ready();
  assert.equal((await f.exec()).decision, 'CANARY_RECORDED');
  const r = await f.collect();
  assert.equal(r.mode, 'SYNTHETIC_ONLY'); assert.deepEqual(validateShape('tool-receipt', r.receipt), []);
  assert.equal(r.output.payload_hash, digest(f.payload)); assert(r.output.utf8_bytes > 0);
  assert.equal((await f.finish('run_child')).status, 'WORK_COMPLETED');
  const parent = await f.finish('run_parent'); assert.equal(parent.status, 'WORK_COMPLETED');
  assert.equal(parent.independent_qa, 'NOT_RUN'); assert.equal(parent.authoritative_task_completion, false);
  assert.equal(f.task().state, 'RUNNING'); assert.equal(f.operation().status, 'CONFIRMED');
  assert.equal(f.operation().attempts, 1); assert.equal(f.inspect().effects.length, 1);
  assert.equal(f.inspect().actual_external_dispatches, 0);
  assert.equal(f.adapter.control.inspect().physical_dispatches, 0);
  denied(f.adapter.worker.requestPhysicalEffect());
});

const grantMutations = {
  version: g => { g.schema_version = '2.0.0'; }, extra_field: g => { g.transport = 'terminal'; },
  forged_actor: g => { g.actor = {identity_id: 'act_worker', role: 'SUPERVISOR'}; },
  scope: g => { g.scope = {...g.scope, project_id: 'prj_beta'}; },
  revision: g => { g.expected_revision++; }, epoch: g => { g.epochs = {...g.epochs, policy: 99}; },
  spec: g => { g.spec = {...g.spec, revision: 99}; }, config: g => { g.config_hash = digest({bad: 1}); },
  manifest: g => { g.manifest_hash = digest({bad: 1}); }, expired: g => { g.deadline = g.created_at; },
  beyond_lease: g => { g.deadline = '2026-11-05T13:00:00.000Z'; },
  negative_attempts: g => { g.max_physical_attempts = -1; }, excessive_attempts: g => { g.max_physical_attempts = 51; },
  excessive_children: g => { g.max_children = 3; }, depth: g => { g.depth = 2; },
  duplicate_capability: g => { g.capabilities.push(g.capabilities[0]); },
  unknown_tool: g => { g.capabilities = ['tool_terminal']; },
  invalid_id: g => { g.run_id = '../terminal'; }
};
for (const [name, mutate] of Object.entries(grantMutations)) test('R02 invalid grant ' + name, async () => {
  const f = await runtimeFixture(), g = f.grant('run_bad'); mutate(g);
  assert.throws(() => f.adapter.control.registerGrant(JSON.stringify(g), 'act_worker')); noEffects(f);
});

const childMutations = {
  capabilities: {capabilities: ['tool_unregistered']}, budget: {budget_ref: digest({foreign: 1})},
  deadline: {deadline: '2026-11-05T12:00:09.001Z'}, attempts: {max_physical_attempts: 2},
  grandchildren: {max_children: 1}, root_depth: {depth: 0},
  task: {scope: {project_id: 'prj_alpha', task_id: 'task_foreign', operation_id: 'op_control_one'}},
  operation: {scope: {project_id: 'prj_alpha', task_id: 'task_one', operation_id: 'op_different'}},
  config: {config_hash: digest({other: 'config'})}, manifest: {manifest_hash: digest({other: 'manifest'})}
};
for (const [name, change] of Object.entries(childMutations)) test('R03 child escalation ' + name, async () => {
  const f = await runtimeFixture(); await f.launch('run_parent');
  await assert.rejects(f.spawn(change)); assert.equal(f.transport.inspect().launches, 1); noEffects(f);
});

test('R04 lifetime child limit and aggregate attempt reservations cannot multiply', async () => {
  const f = await runtimeFixture({parent: {max_children: 2}}); await f.launch('run_parent'); await f.spawn();
  await assert.rejects(f.spawn({}, 'run_second'), /TREE_ATTEMPT_LIMIT/);
  await f.cancelRun('run_child');
  await assert.rejects(f.spawn({}, 'run_second'), /TREE_ATTEMPT_LIMIT/); noEffects(f);
});
test('R05 max_children=0 and unlaunched parent cannot spawn', async () => {
  const f = await runtimeFixture({parent: {max_children: 0}}); await assert.rejects(f.spawn());
  await f.launch('run_parent'); await assert.rejects(f.spawn(), /CHILD_LIMIT/); noEffects(f);
});
test('R06 single launch and no terminal resurrection', async () => {
  const f = await runtimeFixture(); await f.launch('run_parent'); denied(await f.launch('run_parent'));
  await f.cancelRun('run_parent'); denied(await f.launch('run_parent')); denied(await f.finish('run_parent'));
  assert.equal(f.transport.inspect().launches, 1); noEffects(f);
});
test('R07 exactly one concurrent tool attempt, duplicate receipt and registration rejected', async () => {
  const f = await ready(); assert.throws(() => f.admit(), /OPERATION_ALREADY_REGISTERED/);
  const results = await Promise.all([f.exec(), f.exec(), f.exec()]);
  assert.equal(results.filter(r => r.decision === 'CANARY_RECORDED').length, 1);
  results.filter(r => r.decision !== 'CANARY_RECORDED').forEach(denied);
  await f.collect(); denied(await f.collect());
  assert.equal(f.operation().attempts, 1); assert.equal(f.inspect().effects.length, 1);
});
test('R08 parent cannot spend child reserved attempts or access child operation', async () => {
  const f = await ready(); denied(await f.exec('run_parent')); noEffects(f);
});
test('R09 narrowed empty child capabilities cannot register tool admission', async () => {
  const f = await runtimeFixture(); await f.launch('run_parent'); await f.spawn({capabilities: [], max_physical_attempts: 0});
  assert.throws(() => f.admit(), /CAPABILITY_DENIED/); noEffects(f);
});
test('R10 foreign sessions, forged sessions, worker control-plane absence', async () => {
  const f = await ready(), w = f.adapter.worker;
  for (const session of [{identity_id: 'act_worker', role: 'EXECUTOR'}, f.ownerSession, f.bridge.control.issueSession('act_examiner')]) {
    denied(await w.executeTool(session, 'run_child', f.opScope.operation_id));
    denied(await w.complete(session, 'run_child')); denied(await w.interrupt(session, 'run_child'));
  }
  assert.equal(w.registerGrant, undefined); assert.equal(w.registerAdmission, undefined); assert.equal(w.registerTool, undefined); noEffects(f);
});

for (const [name, change] of Object.entries({identity: f => f.bridge.control.revokeIdentity('act_worker'),
  grant: f => f.bridge.control.revokeGrant(f.intent.run_id), approval: f => f.bridge.control.revokeApproval(f.intent.approval_id),
  tool: f => f.bridge.control.revokeTool(f.intent.tool_id), policy: f => f.bridge.control.setPolicy('unknown-policy'),
  epoch: f => f.bridge.control.advanceEpoch('policy'), deadline: f => f.h.tick(9000)})) {
  test('R11 current PEP/state change before execution ' + name, async () => {
    const f = await ready(); await change(f); denied(await f.exec()); noEffects(f);
  });
}
test('R12 policy changes between asynchronous review and dispatch: second PEP denies', async () => {
  // Trusted test harness wrapper injects a race; worker never receives the bridge or a callback.
  const f = await ready({bridgeTransform: original => ({worker: {...original.worker, async review(...args) {
    const result = await original.worker.review(...args); original.control.setPolicy('unknown-policy'); return result;
  }}})});
  denied(await f.exec()); noEffects(f);
});
test('R13 cancellation propagates to children, late completion cannot reverse it', async () => {
  const f = await ready(); const result = await f.cancelRun('run_parent'); assert.equal(result.status, 'CANCELLED');
  assert.equal((await f.status('run_child')).status, 'CANCELLED');
  denied(await f.exec()); denied(await f.finish('run_child')); denied(await f.launch('run_parent')); noEffects(f);
});
test('R14 pending tool attempt prevents false confirmed cancellation', async () => {
  const f = await ready(); await f.exec(); const result = await f.cancelRun('run_parent');
  assert.equal(result.status, 'UNKNOWN'); assert.equal((await f.status('run_child')).status, 'UNKNOWN');
  denied(await f.finish('run_child')); assert.equal(f.operation().retained_reservation, true);
});
for (const name of ['loseLaunchCallback', 'loseInterruptCallback']) test('R15 lost callback ' + name + ' retains unknown, never replay', async () => {
  const f = await runtimeFixture({transport: {[name]: true}}); const launched = await f.launch('run_parent');
  const result = name === 'loseLaunchCallback' ? launched : await f.cancelRun('run_parent');
  assert.equal(result.status, 'UNKNOWN'); denied(await f.launch('run_parent'));
  assert.equal(f.transport.inspect().launches, 1); noEffects(f);
});
test('R16 A-02 abandoned handle after adapter replacement becomes UNKNOWN without relaunch', async () => {
  const f = await ready(), transport = createFakeHermesTransport();
  const restarted = createRuntimeAdapter({...f.args, transport});
  const result = restarted.control.reconcile('run_child');
  assert.equal(result.status, 'UNKNOWN'); assert.equal(result.reason, 'HELPER_HANDLE_LOST');
  denied(await restarted.worker.launch(f.executorSession, 'run_child'));
  assert.equal(transport.inspect().launches, 0); assert.equal(result.delegated_attempts, 0);
});
test('R17 A-02 owner epoch mismatch reconciles to UNKNOWN and retains capacity', async () => {
  const f = await ready(); await f.bridge.control.advanceEpoch('owner');
  const result = f.adapter.control.reconcile('run_child');
  assert.equal(result.status, 'UNKNOWN'); assert.equal(result.reason, 'OWNER_EPOCH_CHANGED'); noEffects(f);
});
test('R18 D02 consumed / D03 ambiguous commit is quarantined, no retry', async () => {
  const f = await ready(); f.fault('before_commit'); const result = await f.exec();
  assert.equal(result.decision, 'OUTCOME_UNKNOWN'); assert.equal((await f.status('run_child')).status, 'UNKNOWN');
  f.fault(null); denied(await f.exec()); assert.equal(f.inspect().effects.length, 1);
});
test('R19 receipt commit ambiguity never reports work completed', async () => {
  const f = await ready(); await f.exec(); f.fault('before_commit'); denied(await f.collect()); f.fault(null);
  assert.equal((await f.status('run_child')).status, 'UNKNOWN'); denied(await f.finish('run_child'));
});
test('R20 pending children / tool work cannot be claimed complete by text', async () => {
  const f = await ready(); denied(await f.finish('run_parent')); denied(await f.finish('run_child'));
  assert.equal(f.task().state, 'RUNNING'); noEffects(f);
});

test('R21 A-01 switching from A to B rebinds exact reviewed B row', () => {
  const rows = ['a', 'b'].map(id => ({id, enabled: true, reviewed: true, fingerprint: digest({id}),
    tested_fingerprint: digest({id}), expires_at: '2026-11-06T00:00:00.000Z'}));
  const result = selectModelRow(JSON.stringify(rows), 'b', '2026-11-05T12:00:00.000Z');
  assert.equal(result.id, 'b'); assert.equal(result.fingerprint, rows[1].fingerprint);
});
for (const [name, change] of Object.entries({unreviewed: r => { r.reviewed = false; }, disabled: r => { r.enabled = false; },
  mismatch: r => { r.tested_fingerprint = digest({a: 1}); }, expired: r => { r.expires_at = '2026-01-01T00:00:00.000Z'; }})) {
  test('R22 A-01 rejects selected B ' + name + ' even if A is valid', () => {
    const rows = ['a', 'b'].map(id => ({id, enabled: true, reviewed: true, fingerprint: digest({id}),
      tested_fingerprint: digest({id}), expires_at: '2026-11-06T00:00:00.000Z'})); change(rows[1]);
    assert.throws(() => selectModelRow(JSON.stringify(rows), 'b', '2026-11-05T12:00:00.000Z'));
  });
}
test('R23 A-01 duplicate/missing model and duplicate JSON keys fail closed', () => {
  assert.throws(() => selectModelRow('[{"id":"a"},{"id":"a"}]', 'a', '2026-11-05T12:00:00.000Z'));
  assert.throws(() => selectModelRow('[]', 'missing', '2026-11-05T12:00:00.000Z'));
  assert.throws(() => selectModelRow('[{"id":"a","id":"b"}]', 'b', '2026-11-05T12:00:00.000Z'));
});
test('R24 tool pin/handler/physical registration and duplicate replacement rejected', async () => {
  const f = await runtimeFixture(), registry = createToolRegistry(); registry.register(JSON.stringify(f.descriptor));
  assert.throws(() => registry.register(JSON.stringify(f.descriptor)), /TOOL_ALREADY_REGISTERED/);
  for (const change of [{mode: 'PHYSICAL'}, {id: 'tool_other', digest: 'unknown'}, {handler: 'terminal'}])
    assert.throws(() => registry.register(JSON.stringify({...f.descriptor, ...change})));
  denied(registry.dispatch());
});
test('R25 foreign runtime transport / forged registry cannot enter E0 assembly', async () => {
  const f = await runtimeFixture();
  assert.throws(() => createRuntimeAdapter({...f.args, transport: {launch: () => { throw Error('MUST_NOT_RUN'); }}}), /SYNTHETIC_TRANSPORT_REQUIRED/);
  assert.throws(() => createRuntimeAdapter({...f.args, registry: {}}), /REGISTRY_UNTRUSTED/);
});

const admissionMutations = {
  project: i => { i.scope.project_id = 'prj_beta'; }, task: i => { i.scope.task_id = 'task_foreign'; },
  control_operation: (i, f) => { i.scope.operation_id = f.taskScope.operation_id; },
  executor: i => { i.actor.identity_id = 'act_other'; }, tool: i => { i.tool_id = 'tool_foreign'; },
  digest: i => { i.tool_digest = digest({other: 1}); }, payload: i => { i.payload = {changed: true}; },
  schema: i => { i.input_schema_hash = digest({other: 1}); }, action: i => { i.action = 'terminal'; },
  resource: i => { i.resource = 'host:filesystem'; }
};
for (const [name, mutate] of Object.entries(admissionMutations)) test('R26 mismatched tool admission ' + name, async () => {
  const f = await runtimeFixture(); await f.launch('run_parent'); await f.spawn();
  const intent = structuredClone(f.intent); mutate(intent, f);
  assert.throws(() => f.admit('run_child', {intent, handle: f.handle})); noEffects(f);
});
test('R27 forged opaque bridge admission cannot consume a synthetic attempt', async () => {
  const f = await runtimeFixture(); await f.launch('run_parent'); await f.spawn();
  f.admit('run_child', {intent: f.intent, handle: {}}); denied(await f.exec()); noEffects(f);
});
test('R28 actual task cancel denies pending tool and late receipt', async () => {
  const f = await ready(); await f.exec();
  await f.h.service.cancel(f.h.owner, f.taskScope, f.task().revision, 'cancel-runtime');
  denied(await f.collect()); denied(await f.finish('run_child'));
  assert.equal(f.task().cancel_requested, true); assert.equal(f.operation().attempts, 1);
});
test('R29 cancel arriving after review cannot admit tool at final state barrier', async () => {
  let f;
  f = await ready({bridgeTransform: original => ({worker: {...original.worker, async review(...args) {
    const result = await original.worker.review(...args);
    await f.h.service.cancel(f.h.owner, f.taskScope, f.task().revision, 'race-cancel'); return result;
  }}})});
  denied(await f.exec()); assert.equal(f.task().cancel_requested, true); noEffects(f);
});
test('R30 lost bridge callback after canary write retains UNKNOWN without retry', async () => {
  const f = await ready({bridgeTransform: original => ({worker: {...original.worker, async dispatchCanary(...args) {
    await original.worker.dispatchCanary(...args); throw new Error('CALLBACK_LOST');
  }}})});
  const result = await f.exec(); assert.equal(result.decision, 'OUTCOME_UNKNOWN');
  denied(await f.exec()); assert.equal((await f.status('run_child')).status, 'UNKNOWN');
  assert.equal(f.operation().attempts, 1); assert.equal(f.inspect().effects.length, 1);
});
test('R31 lost receipt ACK after actual synthetic commit stays UNKNOWN, no duplicate write', async () => {
  const f = await ready(); await f.exec(); f.fault('after_commit'); denied(await f.collect()); f.fault(null);
  assert.equal(f.operation().status, 'CONFIRMED'); denied(await f.collect());
  assert.equal((await f.status('run_child')).status, 'UNKNOWN'); denied(await f.finish('run_parent'));
});
test('R32 confirmed terminal work stays terminal after interrupt and reconcile', async () => {
  const f = await ready(); await f.exec(); await f.collect(); await f.finish('run_child'); await f.finish('run_parent');
  assert.equal((await f.cancelRun('run_parent')).status, 'WORK_COMPLETED');
  assert.equal(f.adapter.control.reconcile('run_parent').status, 'WORK_COMPLETED'); denied(await f.exec());
  assert.equal(f.operation().attempts, 1);
});
test('R33 zero attempt grant cannot request tool; actual lifetime child bound persists after cancel', async () => {
  const f = await runtimeFixture({parent: {max_children: 1, max_physical_attempts: 0}});
  await f.launch('run_parent'); await f.spawn({max_physical_attempts: 0}); f.admit(); denied(await f.exec());
  await f.cancelRun('run_child'); await assert.rejects(f.spawn({max_physical_attempts: 0}, 'run_next'), /CHILD_LIMIT/); noEffects(f);
});
test('R34 no two grandchildren or foreign run/tool queries', async () => {
  const f = await ready();
  await assert.rejects(f.spawn({parent_run_id: 'run_child'}, 'run_grandchild'));
  denied(await f.adapter.worker.executeTool(f.executorSession, 'run_child', 'op_foreign'));
  denied(await f.status('run_foreign')); noEffects(f);
});
test('R35 opaque fake transport handle cannot be forged or reused in another transport', () => {
  const a = createFakeHermesTransport(), b = createFakeHermesTransport(), h = a.launch({run_id: 'run_test'});
  assert.throws(() => a.status({}), /HELPER_HANDLE_LOST/); assert.throws(() => b.status(h), /HELPER_HANDLE_LOST/);
});
test('R36 exact tool identifiers and pins reject a trailing newline', async () => {
  const f = await runtimeFixture();
  for (const key of ['id', 'digest', 'input_schema_hash', 'output_schema_hash']) {
    const registry = createToolRegistry();
    assert.throws(() => registry.register(JSON.stringify({...f.descriptor, [key]: f.descriptor[key] + '\n'})));
  }
  const rows = [{id: 'b', enabled: true, reviewed: true, fingerprint: digest({b: 1}) + '\n',
    tested_fingerprint: digest({b: 1}) + '\n', expires_at: '2026-11-06T00:00:00.000Z'}];
  assert.throws(() => selectModelRow(JSON.stringify(rows), 'b', '2026-11-05T12:00:00.000Z'));
});
test('R37 worker reconcile binds authoritative owner epoch; reads cannot revive orphan', async () => {
  const f = await ready();
  assert.equal((await f.adapter.worker.reconcile(f.executorSession, 'run_child', 1)).status, 'RUNNING');
  await f.bridge.control.advanceEpoch('owner');
  denied(await f.adapter.worker.reconcile(f.executorSession, 'run_child', 1));
  assert.equal((await f.adapter.worker.reconcile(f.executorSession, 'run_child', 2)).status, 'UNKNOWN');
  denied(await f.launch('run_child')); noEffects(f);
});
