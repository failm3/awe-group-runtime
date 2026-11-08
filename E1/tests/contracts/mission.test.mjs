import test from 'node:test';
import assert from 'node:assert/strict';
import {canonicalize, digest, CONTRACT_TYPES, CONTRACT_VERSION, RELEASE, SCHEMA_DOCUMENT, schemaDigest, sealContract, validateContract, validatePlanRevision, inspectBoundSchema, validateCapabilityDescriptor, capabilityManifestDigest} from '../../contracts/index.mjs';
import {createMissionIngress, createOfflineAuthority, MAX_MISSION_REVISIONS} from '../../mission/ingress.mjs';
import {createMissionFixture, runFixture, fixtureSummary, FIXTURE_NOW} from '../../examples/fixtures.mjs';

const clone = structuredClone;
function expectCode(fn, code, disposition) { assert.throws(fn, error => error.code === code && (!disposition || error.disposition === disposition), code); }
function create(f = createMissionFixture('A'), overrides = {}) {
  const ingress = createMissionIngress({clock: f.clock, authority: f.authority, capabilities: f.capabilities, domainManifests: [f.domain_manifest], projectId: f.spec.project_id, ...overrides});
  ingress.mission.create({spec: f.spec, grant: f.grant}, f.contexts.owner); return {...f, ingress};
}
function propose(f, plan = f.plan) { return f.ingress.plan.propose({plan}, f.contexts.head); }
function validate(f, proposed = propose(f)) { return f.ingress.plan.validate({mission_id: f.spec.mission_id, plan_digest: proposed.plan.digest}, f.contexts.coordinator); }
function publish(f, proposed, validated) { return f.ingress.plan.publish({mission_id: f.spec.mission_id, plan_digest: proposed.plan.digest, validation_digest: validated.validation.digest}, f.contexts.coordinator); }
function rebind(f) { f.grant.spec_digest = digest(f.spec); f.plan.spec_digest = digest(f.spec); f.plan.grant_digest = digest(f.grant); f.plan.grant_version = f.grant.grant_version; return f; }
function nextPlan(f, previous, revision = previous.plan.value.revision + 1) { return {...clone(previous.plan.value), revision, previous_digest: previous.plan.digest, reason: 'Repair within unchanged grant: revision ' + revision}; }
const snapshot = f => JSON.stringify(f.ingress.snapshot(f.contexts.owner));

test('one ingress validates distinct A/B manifests and branching DAGs on one release', () => {
  const a = runFixture('A'), b = runFixture('B');
  for (const result of [a, b]) { assert.equal(result.published.decision, 'PUBLISHED_PREFLIGHT_ONLY'); assert.equal(result.published.release, RELEASE); assert.equal(result.published.accepted, false); assert.equal(result.published.effects, 0); assert.equal(result.published.execution_authorized, false); assert.ok(result.fixture.plan.tasks.some(t => t.depends_on.length === 2)); }
  assert.notEqual(a.fixture.spec.project_id, b.fixture.spec.project_id); assert.notEqual(digest(a.fixture.domain_manifest), digest(b.fixture.domain_manifest));
  assert.equal(a.snapshot.registry_digest, b.snapshot.registry_digest); assert.equal(a.created.spec.schema_digest, b.created.spec.schema_digest);
  assert.equal(fixtureSummary('A').release, fixtureSummary('B').release);
});

test('all versioned schemas are immutable and hash stable under JSON key reorder', () => {
  const f = createMissionFixture(); const qa = {contract_version: CONTRACT_VERSION, release: RELEASE, qa_id: 'qa_record', project_id: f.spec.project_id, mission_id: f.spec.mission_id, task_id: 'review', artifact_digest: f.spec.facts_refs[0].digest, plan_digest: digest(f.plan), rubric_digest: f.domain_manifest.qa_rubric.digest, evaluator_id: 'id_e1_qa', producer_id: 'id_e1_head', evaluated_at: FIXTURE_NOW, verdict: 'PASS', checks: [{check_id: 'schema', passed: true, evidence_refs: f.spec.facts_refs}], accepted: false};
  const values = {MissionSpec: f.spec, MissionGrant: f.grant, PlanRevision: f.plan, TaskSpec: f.plan.tasks[0], CapabilityRef: f.capabilities[0].ref, ArtifactRef: f.spec.facts_refs[0], EffectIntent: f.plan.tasks[0].effect, QAResult: qa, DomainManifest: f.domain_manifest};
  for (const type of CONTRACT_TYPES) { const sealed = sealContract(type, values[type]); assert.equal(sealed.digest, digest(Object.fromEntries(Object.entries(values[type]).reverse()))); assert.equal(sealed.schema_digest, schemaDigest(type)); assert.ok(Object.isFrozen(sealed.value)); assert.equal(validateContract(type, values[type]).release, RELEASE); }
  assert.ok(Object.isFrozen(SCHEMA_DOCUMENT.$defs.TaskSpec.properties));
});

for (const [name, edit, code, disposition] of [
  ['wrong input schema digest', p => { p.tasks[0].capability.input_schema.digest = 'sha256:' + 'a'.repeat(64); }, 'E1_CAPABILITY_BINDING'],
  ['wrong output schema digest', p => { p.tasks[0].capability.output_schema.digest = 'sha256:' + 'a'.repeat(64); }, 'E1_CAPABILITY_BINDING'],
  ['wrong implementation digest', p => { p.tasks[0].capability.manifest_digest = 'sha256:' + 'a'.repeat(64); }, 'E1_CAPABILITY_BINDING'],
  ['DAG cycle', p => { p.tasks[0].depends_on = ['review']; p.tasks[0].dependency_bindings = [{task_id: 'review', output_schema: p.tasks.at(-1).capability.output_schema}]; }, 'E1_DAG_CYCLE'],
  ['missing DAG dependency', p => { p.tasks[0].depends_on = ['constructor']; }, 'E1_DEPENDENCY_MISSING'],
  ['dependency output substitution', p => { p.tasks[2].dependency_bindings[0].output_schema.digest = 'sha256:' + 'a'.repeat(64); }, 'E1_DEPENDENCY_SCHEMA'],
  ['unbound QA rubric', p => { p.tasks[0].qa.rubric_digest = 'sha256:' + 'a'.repeat(64); }, 'E1_QA_RUBRIC_BINDING'],
  ['missing criterion', p => { p.tasks.at(-1).criterion_ids = ['primary']; }, 'E1_CRITERIA_COVERAGE'],
  ['wrong origin', p => { p.tasks[0].origin.kind = 'UNKNOWN'; }, 'E1_TASK_ORIGIN'],
  ['foreign source digest', p => { p.tasks[0].origin.source_digests = ['sha256:' + 'a'.repeat(64)]; }, 'E1_TASK_SOURCE'],
  ['data class escalation', p => { p.tasks[0].data_classes = ['SECRET']; }, 'E1_TASK_DATA_CLASS'],
  ['reconcile before unknown replay', p => { p.tasks[0].effect.outcome = 'OUTCOME_UNKNOWN'; }, 'E1_RECONCILIATION_REQUIRED', 'WAIT'],
  ['effect input substitution', p => { p.tasks[0].effect.payload_digest = 'sha256:' + 'a'.repeat(64); }, 'E1_EFFECT_BINDING'],
  ['effect project substitution', p => { p.tasks[0].effect.project_id = 'prj_other'; }, 'E1_EFFECT_BINDING'],
  ['effect duplicate IDs', p => { p.tasks[1].effect.effect_id = p.tasks[0].effect.effect_id; }, 'E1_DUPLICATE_EFFECT'],
  ['task deadline beyond plan', p => { p.tasks[0].deadline = '2026-11-08T11:00:00.000Z'; }, 'E1_TASK_BOUNDS'],
  ['task timeout beyond registry', p => { p.tasks[0].timeout_ms = 2000; }, 'E1_TASK_BOUNDS'],
  ['malformed capability input', p => { p.tasks[0].input.instruction = 42; p.tasks[0].effect.payload_digest = digest(p.tasks[0].input); }, 'E1_SCHEMA_TYPE'],
  ['unknown capability input property', p => { p.tasks[0].input.accepted = true; p.tasks[0].effect.payload_digest = digest(p.tasks[0].input); }, 'E1_SCHEMA_EXTRA']
]) test('preflight denies ' + name + ' without publishing or changing validation history', () => {
  const f = create(); const plan = clone(f.plan); edit(plan); const p = propose(f, plan), before = snapshot(f);
  expectCode(() => validate(f, p), code, disposition); assert.equal(snapshot(f), before); assert.equal(f.ingress.snapshot(f.contexts.owner).missions[0].published_digest, null);
});

test('missing registry capability returns WAIT', () => {
  const f = create(createMissionFixture(), {capabilities: createMissionFixture().capabilities.filter(x => x.ref.capability_id !== 'common.research')});
  expectCode(() => validate(f), 'E1_CAPABILITY_MISSING', 'WAIT');
});
test('revoked and expired registry capabilities return WAIT', () => {
  for (const edit of [cap => { cap.state = 'REVOKED'; }, cap => { cap.health_until = FIXTURE_NOW; }]) {
    const f = createMissionFixture(); edit(f.capabilities[0]); f.capabilities[0].ref.manifest_digest = capabilityManifestDigest(f.capabilities[0]);
    // Keep the requested binding matching the prior reviewed registry pin: health/state change still denies availability.
    const instance = create(f); expectCode(() => validate(instance), 'E1_CAPABILITY_UNAVAILABLE', 'WAIT');
  }
});

test('budget caps include all retry attempts and cannot self increase', () => {
  const f = createMissionFixture(); f.spec.budget = {currency: 'RUB', amount_micros: '10'}; f.grant.budget_cap = clone(f.spec.budget); f.plan.budget = {currency: 'RUB', amount_micros: '12'}; f.plan.tasks.forEach(t => { t.budget = {currency: 'RUB', amount_micros: t.task_id === 'source_left' ? '6' : '0'}; }); f.plan.tasks[0].retry.max_attempts = 2; rebind(f);
  expectCode(() => validate(create(f)), 'E1_PLAN_BUDGET');
});
test('critical path must fit the task and mission deadline', () => {
  const f = createMissionFixture(); f.plan.tasks.forEach(t => { t.deadline = '2026-11-08T09:00:00.300Z'; }); f.plan.deadline = '2026-11-08T09:00:00.300Z';
  expectCode(() => validate(create(f)), 'E1_CRITICAL_PATH_DEADLINE');
});
test('retry policy cannot retry an unknown outcome', () => {
  const f = create(); const plan = clone(f.plan); plan.tasks[0].retry.on_unknown = 'RETRY'; const before = snapshot(f); expectCode(() => propose(f, plan), 'E1_SCHEMA_CONST'); assert.equal(snapshot(f), before);
});
test('JSON actor metadata and foreign authority contexts are not credentials', () => {
  const f = createMissionFixture(); expectCode(() => f.ingress.mission.create({spec: f.spec, grant: f.grant}, {principal_id: f.spec.owner_id, project_id: f.spec.project_id}), 'E1_AUTH_CONTEXT');
  const other = createMissionFixture(); expectCode(() => f.ingress.mission.create({spec: f.spec, grant: f.grant}, other.contexts.owner), 'E1_AUTH_CONTEXT');
});
test('owner, issuer, head and coordinator roles cannot substitute each other', () => {
  const f = create(); expectCode(() => propose({...f, contexts: {...f.contexts, head: f.contexts.owner}}), 'E1_ACTOR_ROLE'); const p = propose(f); expectCode(() => f.ingress.plan.validate({mission_id: f.spec.mission_id, plan_digest: p.plan.digest}, f.contexts.head), 'E1_ACTOR_ROLE');
  const plan = nextPlan(f, p); plan.proposed_by = 'id_e1_qa'; expectCode(() => propose(f, plan), 'E1_PLAN_ACTOR');
  const invalid = createMissionFixture(); invalid.grant.issued_by = 'id_e1_head'; expectCode(() => invalid.ingress.mission.create({spec: invalid.spec, grant: invalid.grant}, invalid.contexts.owner), 'E1_GRANT_SCOPE');
});
test('bootstrap authority cannot alias the QA subject to a producer', () => {
  expectCode(() => createOfflineAuthority([{principal_id: 'producer', subject_id: 'same_subject', role: 'HEAD', projects: ['prj_test']}, {principal_id: 'qa', subject_id: 'same_subject', role: 'QA', projects: ['prj_test']}]), 'E1_QA_SUBJECT_CONFLICT');
});
test('revoked principal context cannot act or read snapshots', () => {
  const f = create(); f.authority.revokePrincipal('id_e1_head'); expectCode(() => propose(f), 'E1_ACTOR_SCOPE'); expectCode(() => f.ingress.snapshot(f.contexts.head), 'E1_ACTOR_SCOPE');
});
test('cross-project spec and configured instance cannot cross the boundary', () => {
  const f = createMissionFixture('A'), b = createMissionFixture('B'); expectCode(() => f.ingress.mission.create({spec: b.spec, grant: b.grant}, f.contexts.owner), 'E1_ACTOR_PROJECT');
  const wrong = createMissionIngress({authority: b.authority, capabilities: b.capabilities, clock: b.clock, domainManifests: [b.domain_manifest], projectId: f.spec.project_id}); expectCode(() => wrong.mission.create({spec: b.spec, grant: b.grant}, b.contexts.owner), 'E1_INSTANCE_PROJECT');
});
test('expired/revoked grants and mismatched source digests reject create', () => {
  const expired = createMissionFixture(); expired.setTime('2026-11-08T10:00:00.000Z'); expectCode(() => expired.ingress.mission.create({spec: expired.spec, grant: expired.grant}, expired.contexts.owner), 'E1_GRANT_EXPIRED');
  const revoked = createMissionFixture(); revoked.grant.revoked_at = FIXTURE_NOW; revoked.grant.revocation_reason = 'Owner stopped'; expectCode(() => revoked.ingress.mission.create({spec: revoked.spec, grant: revoked.grant}, revoked.contexts.owner), 'E1_GRANT_REVOKED');
  const stale = createMissionFixture(); stale.spec.goal = 'Changed after grant'; expectCode(() => stale.ingress.mission.create({spec: stale.spec, grant: stale.grant}, stale.contexts.owner), 'E1_GRANT_SPEC_DIGEST');
});
test('domain manifest digest/project/rubric is mandatory and immutable', () => {
  const f = createMissionFixture(); const missing = createMissionIngress({clock: f.clock, authority: f.authority, capabilities: f.capabilities}); expectCode(() => missing.mission.create({spec: f.spec, grant: f.grant}, f.contexts.owner), 'E1_DOMAIN_MANIFEST_MISSING', 'WAIT');
  const changed = clone(f.domain_manifest); changed.project_id = 'prj_wrong'; const wrong = createMissionIngress({clock: f.clock, authority: f.authority, capabilities: f.capabilities, domainManifests: [changed]}); expectCode(() => wrong.mission.create({spec: f.spec, grant: f.grant}, f.contexts.owner), 'E1_DOMAIN_MANIFEST_MISSING', 'WAIT');
});

test('nested mutation after create/propose cannot change stored digests', () => {
  const f = create(); const created = f.ingress.snapshot(f.contexts.owner).missions[0]; const originalSpecDigest = created.spec.digest; f.spec.goal = 'Tampered input'; assert.equal(f.ingress.snapshot(f.contexts.owner).missions[0].spec.digest, originalSpecDigest);
  const proposal = propose(f); const originalInput = proposal.plan.value.tasks[0].input.instruction; f.plan.tasks[0].input.instruction = 'Tampered nested input'; assert.equal(f.ingress.snapshot(f.contexts.owner).missions[0].plans[0].contract.value.tasks[0].input.instruction, originalInput);
  assert.throws(() => { proposal.plan.value.tasks[0].input.instruction = 'Frozen mutation'; }, TypeError); assert.throws(() => { created.grant.value.permissions.push('effect.external_write'); }, TypeError);
  validate(f, proposal);
});
test('bounded replan requires reason, predecessor and immutable history', () => {
  const f = create(); const p1 = propose(f), initial = f.ingress.history(f.spec.mission_id, f.contexts.owner); const p2 = propose(f, nextPlan(f, p1));
  expectCode(() => validate(f, p1), 'E1_STALE_PLAN'); const invalid = nextPlan(f, p2); invalid.reason = '   '; expectCode(() => propose(f, invalid), 'E1_SCHEMA_STRING');
  const p3 = propose(f, nextPlan(f, p2)); expectCode(() => propose(f, nextPlan(f, p3)), 'E1_REPLAN_EXHAUSTED'); assert.equal(initial.length, 2);
  const history = f.ingress.history(f.spec.mission_id, f.contexts.owner); history.forEach((event, index) => { assert.equal(event.digest, digest(event.value)); assert.equal(event.value.previous_event_digest, index ? history[index - 1].digest : null); });
  assert.throws(() => history.push({}), TypeError); assert.equal(f.ingress.snapshot(f.contexts.owner).missions[0].plans[0].contract.digest, p1.plan.digest);
});
test('publication requires validated exact digest and rechecks expiry', () => {
  const f = create(); const p = propose(f); expectCode(() => publish(f, p, {validation: {digest: 'sha256:' + 'a'.repeat(64)}}), 'E1_VALIDATION_REQUIRED'); const v = validate(f, p);
  expectCode(() => publish(f, {...p, plan: {...p.plan, digest: 'sha256:' + 'a'.repeat(64)}}, v), 'E1_STALE_PLAN'); f.setTime('2026-11-08T10:00:00.000Z'); expectCode(() => publish(f, p, v), 'E1_GRANT_EXPIRED');
});
test('repeat validation/publication is idempotent and does not grow history', () => {
  const f = create(), p = propose(f), v = validate(f, p), first = publish(f, p, v), before = snapshot(f); assert.deepEqual(validate(f, p), v); assert.deepEqual(publish(f, p, v), first); assert.equal(snapshot(f), before);
});
test('owner revise narrows scope, invalidates publication and keeps immutable spec/grant history', () => {
  const f = create(), p = propose(f), v = validate(f, p); publish(f, p, v); const old = f.ingress.snapshot(f.contexts.owner).missions[0];
  const spec = {...clone(f.spec), revision: 2, goal: 'Clarified bounded fictional goal'}, grant = {...clone(f.grant), grant_version: 2, spec_digest: digest(spec)};
  const revised = f.ingress.mission.revise({spec, grant, expected_spec_digest: old.spec.digest, expected_grant_digest: old.grant.digest, reason: 'Owner clarification within old bounds'}, f.contexts.owner);
  assert.equal(revised.spec_history.length, 2); assert.equal(revised.grant_history.length, 2); assert.equal(revised.published_digest, null); assert.equal(old.spec.value.goal, f.spec.goal); expectCode(() => publish(f, p, v), 'E1_PLAN_BINDING');
  const enlarged = {...clone(grant), grant_version: 3, max_actions: 1}; const nextSpec = {...clone(spec), revision: 3}; enlarged.spec_digest = digest(nextSpec); const before = snapshot(f); expectCode(() => f.ingress.mission.revise({spec: nextSpec, grant: enlarged, expected_spec_digest: revised.spec.digest, expected_grant_digest: revised.grant.digest, reason: 'Unauthorized elevation'}, f.contexts.owner), 'E1_GRANT_SELF_ELEVATION'); assert.equal(snapshot(f), before);
});
test('revoke keeps prior grant immutable and blocks all new plan work, including after expiry', () => {
  const f = create(), p = propose(f), v = validate(f, p), old = f.ingress.snapshot(f.contexts.owner).missions[0]; f.setTime('2026-11-08T10:00:01.000Z');
  const revoked = f.ingress.mission.revoke({mission_id: f.spec.mission_id, expected_spec_digest: old.spec.digest, expected_grant_digest: old.grant.digest, reason: 'Owner stop'}, f.contexts.owner); assert.equal(revoked.status, 'REVOKED'); assert.equal(revoked.grant_history.length, 2); assert.equal(revoked.grant_history[0].value.revoked_at, null); assert.equal(revoked.grant.value.revoked_at, f.clock()); expectCode(() => publish(f, p, v), 'E1_MISSION_REVOKED');
});

test('all nine bounded revisions remain inspectable above the per-entity 64KiB limit', () => {
  const f = createMissionFixture(); f.spec.max_replans = 8; f.grant.max_replans = 8; rebind(f); const instance = create(f); let p = propose(instance);
  for (let i = 1; i <= 9; i++) { if (i > 1) p = propose(instance, nextPlan(instance, p)); const v = validate(instance, p); publish(instance, p, v); }
  const result = instance.ingress.snapshot(instance.contexts.owner); assert.equal(result.missions[0].plans.length, 9); assert.ok(Buffer.byteLength(JSON.stringify(result)) > 65536); assert.equal(result.missions[0].history.length, 28);
});
test('mission revision history is bounded and remains immutable above 64KiB', () => {
  const f = create(); let state = f.ingress.snapshot(f.contexts.owner).missions[0];
  for (let i = 2; i <= MAX_MISSION_REVISIONS; i++) { const spec = {...clone(state.spec.value), revision: i, goal: 'Clarification ' + i}, grant = {...clone(state.grant.value), grant_version: i, spec_digest: digest(spec)}; state = f.ingress.mission.revise({spec, grant, expected_spec_digest: state.spec.digest, expected_grant_digest: state.grant.digest, reason: 'Bounded owner clarification'}, f.contexts.owner); }
  assert.equal(state.spec_history.length, MAX_MISSION_REVISIONS); assert.ok(Buffer.byteLength(JSON.stringify(state)) > 65536); const before = snapshot(f); const spec = {...clone(state.spec.value), revision: MAX_MISSION_REVISIONS + 1}, grant = {...clone(state.grant.value), grant_version: MAX_MISSION_REVISIONS + 1, spec_digest: digest(spec)}; expectCode(() => f.ingress.mission.revise({spec, grant, expected_spec_digest: state.spec.digest, expected_grant_digest: state.grant.digest, reason: 'Too many revisions'}, f.contexts.owner), 'E1_SPEC_REVISION'); assert.equal(snapshot(f), before);
});
test('oversized proposal fails atomically without consuming a revision', () => {
  const f = create(), before = snapshot(f), large = clone(f.plan); large.tasks[0].input.instruction = 'x'.repeat(70000); assert.throws(() => propose(f, large)); assert.equal(snapshot(f), before); assert.equal(propose(f).plan.value.revision, 1);
});

for (const [name, change] of [
  ['symbol array property', a => { a[Symbol('hidden')] = true; }],
  ['hidden array property', a => { Object.defineProperty(a, 'hidden', {value: true}); }],
  ['array accessor', a => { Object.defineProperty(a, '0', {get() { throw new Error('ACCESSOR_EXECUTED'); }, enumerable: true}); }],
  ['sparse array', a => { delete a[0]; }],
  ['inherited array prototype', a => { Object.setPrototypeOf(a, Object.create(Array.prototype)); }]
]) test('raw JS contract rejects ' + name + ' before getters or hashing', () => {
  const f = createMissionFixture(); change(f.spec.criteria); assert.throws(() => validateContract('MissionSpec', f.spec), error => error.code?.startsWith('E1_INVALID_JSON:'));
});
test('prototype keys, custom prototypes and accepted=true are rejected', () => {
  for (const value of [JSON.parse('{"__proto__":{}}'), Object.assign(Object.create({injected: true}), createMissionFixture().spec)]) assert.throws(() => validateContract('MissionSpec', value));
  const f = create(); for (const value of [{...clone(f.spec), accepted: true}, {...clone(f.plan), accepted: true}]) expectCode(() => validateContract(value.mission_id && value.tasks ? 'PlanRevision' : 'MissionSpec', value), 'E1_SCHEMA_EXTRA');
  expectCode(() => f.ingress.plan.propose({plan: f.plan, accepted: true}, f.contexts.head), 'E1_REQUEST_SHAPE');
});
test('bound schema vocabulary and scalar constraints fail closed', () => {
  for (const invalid of [
    {type: 'string', minLength: 1, maxLength: null}, {type: 'integer', minimum: '100', maximum: 200},
    {type: 'boolean', enum: null}, {type: 'string', maxLength: 10, required: []}, {type: 'array', items: {type: 'boolean'}, maxItems: '10'},
    {type: 'object', properties: {}, required: [], additionalProperties: true}, {type: 'string', maxLength: 10, $ref: 'https://example.invalid/schema'},
    {type: 'string', maxLength: 10, pattern: false}, {type: 'integer', minimum: 0, maximum: 10, enum: ['wrong']}
  ]) assert.throws(() => inspectBoundSchema(invalid));
  const f = createMissionFixture(), invalid = clone(f.capabilities[0]); invalid.min_cost_micros = 0; invalid.ref.manifest_digest = capabilityManifestDigest(invalid); expectCode(() => validateCapabilityDescriptor(invalid), 'E1_CAPABILITY_LIMITS');
});
test('QA result cannot self approve, accept a failed check, or set accepted=true', () => {
  const f = createMissionFixture(), base = {contract_version: CONTRACT_VERSION, release: RELEASE, qa_id: 'qa_test', project_id: f.spec.project_id, mission_id: f.spec.mission_id, task_id: 'review', artifact_digest: f.spec.facts_refs[0].digest, plan_digest: digest(f.plan), rubric_digest: f.domain_manifest.qa_rubric.digest, evaluator_id: 'id_e1_head', producer_id: 'id_e1_head', evaluated_at: FIXTURE_NOW, verdict: 'PASS', checks: [{check_id: 'schema', passed: true, evidence_refs: f.spec.facts_refs}], accepted: false};
  expectCode(() => validateContract('QAResult', base), 'E1_QA_INDEPENDENCE'); base.evaluator_id = 'id_e1_qa'; base.checks[0].passed = false; expectCode(() => validateContract('QAResult', base), 'E1_QA_FAILED_CHECK'); base.checks[0].passed = true; base.accepted = true; expectCode(() => validateContract('QAResult', base), 'E1_SCHEMA_CONST');
});
