import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionFixture} from '../examples/fixtures.mjs';
import {createMissionIngress, createE1Composition, digest, canonicalize, capabilityManifestDigest, validateContract, sealContract, createOfflineAuthority} from '../index.mjs';
import {independentConfig} from './helpers.mjs';

function fixture(kind = 'A') {
  const f = createMissionFixture(kind);
  f.ingress = newIngress(f);
  return f;
}
function newIngress(f) { return createMissionIngress({authority: f.authority, capabilities: f.capabilities, domainManifests: [f.domain_manifest], clock: f.clock, projectId: f.spec.project_id}); }
function bind(f) {
  f.grant.spec_digest = digest(f.spec);
  f.plan.spec_digest = digest(f.spec);
  f.plan.grant_digest = digest(f.grant);
  f.plan.grant_version = f.grant.grant_version;
  return f;
}
function open(f) { return f.ingress.mission.create({spec: f.spec, grant: f.grant}, f.contexts.owner); }
function propose(f, plan = f.plan) { return f.ingress.plan.propose({plan}, f.contexts.head); }
function validate(f, proposal) { return f.ingress.plan.validate({mission_id: f.spec.mission_id, plan_digest: proposal.plan.digest}, f.contexts.coordinator); }
function publish(f, proposal, validation) { return f.ingress.plan.publish({mission_id: f.spec.mission_id, plan_digest: proposal.plan.digest, validation_digest: validation.validation.digest}, f.contexts.coordinator); }
function e1Rejected(fn, code) { assert.throws(fn, error => error?.code?.startsWith('E1_') && (!code || error.code === code)); }
function noEffects(f) {
  const snapshot = f.ingress.snapshot(f.contexts.owner);
  assert.equal(snapshot.accepted, false);
  assert.equal(snapshot.effects, 0);
  assert.equal(snapshot.execution_authorized, false);
  return snapshot;
}
function money(f, cap = '0') {
  for (const budget of [f.spec.budget, f.grant.budget_cap, f.plan.budget, ...f.plan.tasks.map(t => t.budget)]) budget.currency = 'USD';
  f.spec.budget.amount_micros = cap; f.grant.budget_cap.amount_micros = cap;
  return bind(f);
}
function rewriteCapability(f, index, mutate) {
  const cap = f.capabilities[index];
  const key = cap.ref.capability_id + '@' + cap.ref.version;
  mutate(cap);
  cap.ref.manifest_digest = capabilityManifestDigest(cap);
  const matches = value => value.capability_id + '@' + value.version === key;
  f.spec.requested_capabilities = f.spec.requested_capabilities.map(ref => matches(ref) ? structuredClone(cap.ref) : ref);
  f.grant.allowed_capabilities = f.grant.allowed_capabilities.map(ref => matches(ref) ? structuredClone(cap.ref) : ref);
  f.domain_manifest.capabilities = f.domain_manifest.capabilities.map(ref => matches(ref) ? structuredClone(cap.ref) : ref);
  f.spec.domain_manifest.digest = digest(f.domain_manifest);
  for (const task of f.plan.tasks) if (matches(task.capability)) task.capability = structuredClone(cap.ref);
  bind(f);
  f.ingress = newIngress(f);
}

test('QA A/B data manifests pass the same public composition with no execution or acceptance', () => {
  const results = [];
  for (const kind of ['A', 'B']) {
    const f = fixture(kind), config = independentConfig();
    config.project_id = f.spec.project_id;
    f.ingress = createE1Composition({config, authority: f.authority, capabilities: f.capabilities, domainManifests: [f.domain_manifest], clock: f.clock});
    open(f);
    const proposed = propose(f), checked = validate(f, proposed), result = publish(f, proposed, checked);
    assert.equal(result.decision, 'PUBLISHED_PREFLIGHT_ONLY');
    assert.equal(result.accepted, false);
    assert.equal(result.effects, 0);
    assert.equal(result.execution_authorized, false);
    assert.equal(f.ingress.health().ready, false);
    assert.equal(f.ingress.health().state, 'WAIT');
    noEffects(f);
    results.push({release: f.ingress.release, build: f.ingress.manifest.build_digest, project: f.spec.project_id, domain: f.spec.domain_manifest.digest});
  }
  assert.equal(results[0].release, results[1].release);
  assert.equal(results[0].build, results[1].build);
  assert.notEqual(results[0].project, results[1].project);
  assert.notEqual(results[0].domain, results[1].domain);
});

test('QA composition cannot admit a mission for a different configured project', () => {
  const f = fixture(), config = independentConfig();
  config.project_id = 'project_other';
  e1Rejected(() => {
    f.ingress = createE1Composition({config, authority: f.authority, capabilities: f.capabilities, domainManifests: [f.domain_manifest], clock: f.clock});
    open(f);
  });
});

for (const [label, mutate] of [
  ['mission accepted flag', f => { f.spec.accepted = true; }],
  ['grant owner forged', f => { f.grant.owner_id = 'head_e1'; }],
  ['grant self-issued by head', f => { f.grant.issued_by = 'head_e1'; }],
  ['expired grant at exclusive edge', f => { f.grant.expires_at = f.clock(); f.spec.deadline = f.clock(); }],
  ['future grant', f => { f.grant.issued_at = '2026-11-08T09:01:00.000Z'; }],
  ['revoked grant', f => { f.grant.revoked_at = f.clock(); f.grant.revocation_reason = 'seeded revoke'; }],
  ['mission above owner budget', f => { f.spec.budget.amount_micros = '1'; }],
  ['mission above grant action count', f => { f.spec.max_actions = 1; }],
  ['mission widened data class', f => { f.spec.data_classes.push('PERSONAL'); }],
  ['mission inferred origin', f => { f.spec.allowed_origins.push('INFERRED'); f.grant.allowed_origins.push('INFERRED'); }],
  ['future artifact', f => { f.spec.facts_refs[0].created_at = '2026-11-08T09:00:01.000Z'; }],
  ['foreign artifact project', f => { f.spec.facts_refs[0].project_id = 'project_other'; }],
  ['foreign artifact mission', f => { f.spec.facts_refs[0].mission_id = 'mission_other'; }],
  ['unregistered domain manifest digest', f => { f.spec.domain_manifest.digest = 'sha256:' + '0'.repeat(64); }],
  ['forged JSON context actor', f => { f.contexts.owner = {...f.contexts.owner}; }],
  ['wrong trusted role', f => { f.contexts.owner = f.contexts.head; }],
]) test('QA create rejects: ' + label, () => {
  const f = fixture(); mutate(f); bind(f);
  e1Rejected(() => open(f));
});

for (const [label, mutate] of [
  ['schema binding digest mismatch', f => { f.plan.tasks[0].capability.input_schema.digest = 'sha256:' + '0'.repeat(64); }],
  ['unknown input property', f => { f.plan.tasks[0].input.side_effect = true; f.plan.tasks[0].effect.payload_digest = digest(f.plan.tasks[0].input); }],
  ['dependency output schema mismatch', f => { f.plan.tasks[2].dependency_bindings[0].output_schema.digest = 'sha256:' + '1'.repeat(64); }],
  ['unregistered QA rubric', f => { f.plan.tasks[0].qa.rubric_digest = 'sha256:' + '2'.repeat(64); }],
  ['cycle', f => { f.plan.tasks[0].depends_on = [f.plan.tasks.at(-1).task_id]; f.plan.tasks[0].dependency_bindings = [{task_id: f.plan.tasks.at(-1).task_id, output_schema: f.plan.tasks.at(-1).capability.output_schema}]; }],
  ['missing dependency', f => { f.plan.tasks[0].depends_on = ['missing']; f.plan.tasks[0].dependency_bindings = [{task_id: 'missing', output_schema: f.plan.tasks[0].capability.output_schema}]; }],
  ['uncovered criterion', f => { f.plan.tasks.at(-1).criterion_ids = ['primary']; }],
  ['private task data', f => { f.plan.tasks[0].data_classes = ['PERSONAL']; }],
  ['unknown origin', f => { f.plan.tasks[0].origin.kind = 'UNKNOWN'; }],
  ['invented source digest', f => { f.plan.tasks[0].origin.source_digests = ['sha256:' + 'a'.repeat(64)]; }],
  ['task budget exceeds cap', f => { f.plan.tasks[0].budget.amount_micros = '1'; f.plan.budget.amount_micros = '1'; }],
  ['plan declared budget wrong', f => { f.plan.budget.amount_micros = '1'; }],
  ['unsafe unknown retry', f => { f.plan.tasks[0].retry.on_unknown = 'RETRY'; }],
  ['foreign effect payload', f => { f.plan.tasks[0].effect.payload_digest = 'sha256:' + 'b'.repeat(64); }],
  ['unknown outcome already in flight', f => { f.plan.tasks[0].effect.outcome = 'OUTCOME_UNKNOWN'; }],
  ['external effect absent mandate', f => { f.plan.tasks[0].effect.effect_class = 'EXTERNAL_WRITE'; }],
  ['too many retry attempts', f => { f.plan.tasks[0].retry.max_attempts = 3; }],
  ['critical path misses deadline', f => { f.plan.tasks.forEach(t => { t.deadline = '2026-11-08T09:00:00.200Z'; }); f.plan.deadline = '2026-11-08T09:00:00.200Z'; }],
]) test('QA plan rejects before any execution: ' + label, () => {
  const f = fixture();
  if (label.includes('budget')) money(f);
  open(f); mutate(f);
  e1Rejected(() => { const proposal = propose(f); validate(f, proposal); });
  noEffects(f);
});

for (const [label, change] of [
  ['missing capability', f => { f.capabilities = f.capabilities.filter(c => c.ref.capability_id !== 'common.transform'); }],
  ['revoked capability', f => rewriteCapability(f, 0, c => { c.state = 'REVOKED'; })],
  ['expired capability health', f => rewriteCapability(f, 0, c => { c.health_until = f.clock(); })],
]) test('QA current registry rejects: ' + label, () => {
  const f = fixture(); change(f);
  f.ingress = newIngress(f);
  open(f); const proposed = propose(f);
  e1Rejected(() => validate(f, proposed));
  noEffects(f);
});

test('QA plan certificate cannot be guessed or replayed after a new proposal', () => {
  const f = fixture(); open(f); const p1 = propose(f), v1 = validate(f, p1);
  e1Rejected(() => publish(f, p1, {validation: {digest: 'sha256:' + '0'.repeat(64)}}));
  const next = structuredClone(f.plan);
  next.revision = 2; next.previous_digest = p1.plan.digest; next.reason = 'Seeded bounded replan';
  const p2 = propose(f, next);
  e1Rejected(() => publish(f, p1, v1));
  e1Rejected(() => publish(f, p2, v1));
  const v2 = validate(f, p2);
  assert.equal(publish(f, p2, v2).accepted, false);
});

test('QA revoke invalidates validated plan and keeps owner stop available after grant expiry', () => {
  const f = fixture(); const created = open(f), p = propose(f), v = validate(f, p);
  f.setTime(f.grant.expires_at);
  e1Rejected(() => publish(f, p, v));
  const revoked = f.ingress.mission.revoke({mission_id: f.spec.mission_id, expected_spec_digest: created.spec.digest, expected_grant_digest: created.grant.digest, reason: 'seeded expired stop'}, f.contexts.owner);
  assert.equal(revoked.status, 'REVOKED');
  e1Rejected(() => publish(f, p, v));
  noEffects(f);
});

test('QA principal revocation invalidates an already issued trusted context', () => {
  const f = fixture(); open(f); const p = propose(f), v = validate(f, p);
  f.authority.revokePrincipal(f.contexts.coordinator.principal_id);
  e1Rejected(() => publish(f, p, v));
  noEffects(f);
});

test('QA successful spec revision invalidates the old validated plan without rewriting its history', () => {
  const f = fixture(), created = open(f), proposal = propose(f), checked = validate(f, proposal);
  const before = f.ingress.history(f.spec.mission_id, f.contexts.owner);
  const spec = structuredClone(f.spec), grant = structuredClone(f.grant);
  spec.revision++; spec.goal += ' Revised within the same bounded scope.'; grant.grant_version++; grant.spec_digest = digest(spec);
  const revised = f.ingress.mission.revise({spec, grant, expected_spec_digest: created.spec.digest, expected_grant_digest: created.grant.digest, reason: 'seeded bounded correction'}, f.contexts.owner);
  assert.equal(revised.spec_history[0].digest, created.spec.digest);
  assert.equal(revised.published_digest, null);
  e1Rejected(() => publish(f, proposal, checked));
  assert.deepEqual(f.ingress.history(f.spec.mission_id, f.contexts.owner).slice(0, before.length), before);
});

test('QA plan proposer identity and publish permission are checked independently of valid digests', () => {
  const f = fixture();
  f.grant.permissions = f.grant.permissions.filter(p => p !== 'plan.publish'); bind(f);
  open(f);
  const badActor = structuredClone(f.plan); badActor.proposed_by = f.contexts.owner.principal_id;
  e1Rejected(() => propose(f, badActor), 'E1_PLAN_ACTOR');
  const proposal = propose(f), checked = validate(f, proposal);
  e1Rejected(() => publish(f, proposal, checked), 'E1_PERMISSION');
  noEffects(f);
});

test('QA ingress clock rollback rejects a previously validated certificate', () => {
  const f = fixture(); open(f); const proposal = propose(f), checked = validate(f, proposal);
  f.setTime('2026-11-08T08:59:59.999Z');
  e1Rejected(() => publish(f, proposal, checked), 'E1_CLOCK_ROLLBACK');
  noEffects(f);
});

test('QA mission revision cannot self-increase grant or mission budget', () => {
  const f = fixture(); money(f, '10');
  const created = open(f), spec = structuredClone(f.spec), grant = structuredClone(f.grant);
  spec.revision++; spec.budget.amount_micros = '11'; grant.grant_version++; grant.budget_cap.amount_micros = '11'; grant.spec_digest = digest(spec);
  e1Rejected(() => f.ingress.mission.revise({spec, grant, expected_spec_digest: created.spec.digest, expected_grant_digest: created.grant.digest, reason: 'seeded unauthorized expansion'}, f.contexts.owner));
  assert.equal(noEffects(f).missions[0].spec.digest, created.spec.digest);
});

test('QA bounded replan retains immutable chain and refuses a fourth plan', () => {
  const f = fixture(); open(f); let previous = null;
  for (let revision = 1; revision <= 3; revision++) {
    const plan = structuredClone(f.plan); plan.revision = revision; plan.previous_digest = previous; plan.reason = 'Seeded revision ' + revision;
    const proposed = propose(f, plan); previous = proposed.plan.digest;
  }
  const before = noEffects(f);
  const fourth = structuredClone(f.plan); fourth.revision = 4; fourth.previous_digest = previous; fourth.reason = 'One too many';
  e1Rejected(() => propose(f, fourth));
  assert.deepEqual(noEffects(f), before);
  const history = f.ingress.history(f.spec.mission_id, f.contexts.owner);
  assert.equal(history.length, 4);
  for (let i = 0; i < history.length; i++) {
    assert.equal(digest(history[i].value), history[i].digest);
    assert.equal(history[i].value.previous_event_digest, i ? history[i - 1].digest : null);
    assert.ok(Object.isFrozen(history[i].value));
  }
});

test('QA proposal/spec snapshots cannot be altered through caller-owned nested arrays', () => {
  const f = fixture(), created = open(f), proposed = propose(f);
  f.spec.goal = 'INJECTED_AFTER_CREATE'; f.spec.facts_refs[0].digest = 'sha256:' + 'c'.repeat(64);
  f.plan.tasks[0].input.instruction = 'INJECTED_AFTER_PROPOSE';
  assert.equal(noEffects(f).missions[0].spec.digest, created.spec.digest);
  assert.equal(noEffects(f).missions[0].plans[0].contract.digest, proposed.plan.digest);
  assert.equal(validate(f, proposed).decision, 'VALIDATED');
  assert.ok(Object.isFrozen(proposed.plan.value.tasks[0].input));
});

test('QA raw JSON boundary rejects array descriptors, hidden properties and prototype objects', () => {
  for (const mutate of [
    s => { Object.defineProperty(s.criteria, '0', {get() { throw new Error('GETTER_MUST_NOT_RUN'); }, enumerable: true}); },
    s => { s.criteria[Symbol('hidden')] = 'HIDDEN'; },
    s => { Object.defineProperty(s.criteria, 'hidden', {value: 'HIDDEN', enumerable: false}); },
    s => { Object.setPrototypeOf(s, {accepted: true}); },
  ]) {
    const f = fixture(); mutate(f.spec);
    e1Rejected(() => validateContract('MissionSpec', f.spec));
  }
});

test('QA acceptance is a fixed false contract value, not an input-controlled shortcut', () => {
  const f = fixture();
  e1Rejected(() => sealContract('MissionSpec', {...f.spec, accepted: true}));
  const qa = {contract_version: f.spec.contract_version, release: f.spec.release, qa_id: 'qa_test', mission_id: f.spec.mission_id,
    project_id: f.spec.project_id, task_id: f.plan.tasks[0].task_id, artifact_digest: f.spec.facts_refs[0].digest,
    plan_digest: digest(f.plan), rubric_digest: f.plan.tasks[0].qa.rubric_digest, evaluator_id: 'qa_e1', producer_id: 'head_e1',
    evaluated_at: f.clock(), verdict: 'PASS', checks: [{check_id: 'schema', passed: true, evidence_refs: [f.spec.facts_refs[0]]}], accepted: true};
  e1Rejected(() => validateContract('QAResult', qa));
  qa.accepted = false; qa.evaluator_id = qa.producer_id;
  e1Rejected(() => validateContract('QAResult', qa));
  assert.throws(() => createOfflineAuthority([{principal_id: 'qa_one', subject_id: 'same', role: 'QA', projects: ['qa_project']}, {principal_id: 'worker_one', subject_id: 'same', role: 'EXECUTOR', projects: ['qa_project']}]), error => error.code === 'E1_QA_SUBJECT_CONFLICT');
});

test('QA large history stays reviewable and revision-limit rejection is atomic', () => {
  const f = fixture(); open(f); let rejected = false;
  for (let revision = 2; revision <= 20; revision++) {
    const before = noEffects(f), current = before.missions[0], spec = structuredClone(current.spec.value), grant = structuredClone(current.grant.value);
    spec.revision = revision; spec.goal = String(revision) + 'x'.repeat(4000); grant.grant_version++; grant.spec_digest = digest(spec);
    try {
      f.ingress.mission.revise({spec, grant, expected_spec_digest: current.spec.digest, expected_grant_digest: current.grant.digest, reason: 'r'.repeat(2000)}, f.contexts.owner);
    } catch (error) {
      assert.ok(error.code?.startsWith('E1_'));
      assert.deepEqual(noEffects(f), before);
      rejected = true; break;
    }
  }
  assert.equal(rejected, true, 'a bounded immutable mission history must reject excess revisions');
});

test('QA plan budget counts every retry and refuses a task-sum beyond the grant', () => {
  const f = fixture(); money(f, '100');
  for (const task of f.plan.tasks) { task.budget.amount_micros = '11'; task.retry.max_attempts = 2; }
  f.plan.budget.amount_micros = '110';
  open(f); const proposal = propose(f);
  e1Rejected(() => validate(f, proposal), 'E1_PLAN_BUDGET');
  noEffects(f);
});

test('QA capability schema cannot introduce a remote reference into the validator', () => {
  const f = fixture();
  f.capabilities[0].input_schema = {type: 'object', $ref: 'https://qa.awe-e1.invalid/remote.schema.json', properties: {}, required: [], additionalProperties: false};
  f.capabilities[0].ref.input_schema.digest = digest(f.capabilities[0].input_schema);
  f.capabilities[0].ref.manifest_digest = capabilityManifestDigest(f.capabilities[0]);
  e1Rejected(() => newIngress(f));
});

test('QA stale/cross-authority JSON context cannot read mission history', () => {
  const f = fixture(); open(f);
  e1Rejected(() => f.ingress.history(f.spec.mission_id, {...f.contexts.owner}));
  const other = fixture('B');
  e1Rejected(() => f.ingress.history(f.spec.mission_id, other.contexts.owner));
  e1Rejected(() => f.ingress.snapshot(JSON.parse(canonicalize(f.contexts.owner))));
});
