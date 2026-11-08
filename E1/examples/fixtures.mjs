import {RELEASE, CONTRACT_VERSION, digest, immutable, capabilityManifestDigest} from '../contracts/index.mjs';
import {createMissionIngress, createOfflineAuthority} from '../mission/ingress.mjs';
export const FIXTURE_NOW = '2026-11-08T09:00:00.000Z';
const versioned = value => ({contract_version: CONTRACT_VERSION, release: RELEASE, ...value});
const stringSchema = {type: 'string', minLength: 1, maxLength: 2048};
const inputSchema = {type: 'object', properties: {instruction: stringSchema}, required: ['instruction'], additionalProperties: false};
const outputSchema = {type: 'object', properties: {text: stringSchema}, required: ['text'], additionalProperties: false};
const budget = {currency: 'NONE', amount_micros: '0'};
const future = '2026-11-08T10:00:00.000Z';
const schemaRef = (id, value) => ({schema_id: id, version: '1.0.0', digest: digest(value)});
export function fixtureCapabilities() {
  return ['research', 'transform', 'build', 'qa'].map(name => {
    const descriptor = {ref: versioned({capability_id: 'common.' + name, version: '1.0.0', manifest_digest: 'sha256:' + '0'.repeat(64), input_schema: schemaRef('e1.instruction', inputSchema), output_schema: schemaRef('e1.text', outputSchema)}), executor_kind: 'script', permissions: ['artifact.read', 'artifact.write'], data_classes: ['PUBLIC', 'PROJECT'], origins: ['OWNER', 'PROJECT'], effect_class: 'NONE', health_until: future, state: 'ACTIVE', max_attempts: 2, timeout_ms: 1000, min_cost_micros: '0', supports_reconcile: false, input_schema: structuredClone(inputSchema), output_schema: structuredClone(outputSchema)};
    descriptor.ref.manifest_digest = capabilityManifestDigest(descriptor); return descriptor;
  });
}
export function createDomainManifest(kind = 'A', capabilities = fixtureCapabilities()) {
  if (!['A', 'B'].includes(kind)) throw new TypeError('E1_FIXTURE_KIND');
  return versioned({manifest_id: kind === 'A' ? 'domain.career' : 'domain.product', version: '1.0.0', project_id: kind === 'A' ? 'prj_e1_career' : 'prj_e1_product', domain: kind === 'A' ? 'career' : 'digital_product', description: kind === 'A' ? 'Fictional offline career package; no personal facts, applications or external destinations.' : 'Independent fictional shift-handoff product brief; no deployment or running product claim.', capabilities: capabilities.map(x => x.ref), qa_rubric: {rubric_id: 'e1.fixture.rubric', digest: digest({checks: ['schema', 'sources', 'scope'], version: 1}), checks: ['schema', 'sources', 'scope']}});
}

/** Data-only A/B inputs use one release, registry, schemas and ingress.
 * Bootstrap credentials are test setup, never a JSON authentication channel.
 */
export function createMissionFixture(kind = 'A') {
  const capabilities = fixtureCapabilities(), domain_manifest = createDomainManifest(kind, capabilities), projectId = domain_manifest.project_id;
  let currentTime = FIXTURE_NOW;
  const principals = [
    {principal_id: 'id_e1_owner', subject_id: 'id_e1_owner', role: 'OWNER', projects: [projectId]},
    {principal_id: 'id_e1_head', subject_id: 'producer_e1', role: 'HEAD', projects: [projectId]},
    {principal_id: 'id_e1_coordinator', subject_id: 'id_e1_coordinator', role: 'COORDINATOR', projects: [projectId]},
    {principal_id: 'id_e1_qa', subject_id: 'independent_qa_e1', role: 'QA', projects: [projectId]}
  ];
  const authority = createOfflineAuthority(principals), contexts = Object.fromEntries(principals.map(p => [p.role.toLowerCase(), authority.issueContext(p.principal_id, projectId)]));
  const missionId = kind === 'A' ? 'mission_career_fixture' : 'mission_product_fixture';
  const facts = kind === 'A' ? {fictional: true, source: 'Local career requirements example', confirmed_claims: ['Synthetic skill alpha']} : {fictional: true, source: 'Independent product brief', confirmed_claims: ['Two fictional shift roles need an auditable handoff']};
  const factsSchema = {type: 'object', properties: {fictional: {type: 'boolean'}, source: stringSchema, confirmed_claims: {type: 'array', items: stringSchema, minItems: 1, maxItems: 8}}, required: ['fictional', 'source', 'confirmed_claims'], additionalProperties: false};
  const fact = versioned({artifact_id: 'facts_' + kind.toLowerCase(), project_id: projectId, mission_id: missionId, uri: 'artifact:fixture/' + kind.toLowerCase() + '/facts', digest: digest(facts), media_type: 'application/json', schema: schemaRef('e1.fixture.facts', factsSchema), data_class: 'PUBLIC', origin: 'OWNER', producer_id: 'id_e1_owner', created_at: FIXTURE_NOW});
  const spec = versioned({mission_id: missionId, project_id: projectId, owner_id: 'id_e1_owner', revision: 1, goal: kind === 'A' ? 'Prepare a fictional evidence-backed career package offline.' : 'Prepare an independent fictional shift-handoff digital-product plan offline.', criteria: [{criterion_id: 'primary', text: kind === 'A' ? 'Package claims cite supplied fictional facts.' : 'Product plan covers create, handoff and confirmation for fictional roles.'}, {criterion_id: 'review', text: 'Independent QA rubric and immutable bindings are present.'}], facts_refs: [fact], domain_manifest: {manifest_id: domain_manifest.manifest_id, version: domain_manifest.version, digest: digest(domain_manifest)}, requested_capabilities: capabilities.map(x => x.ref), budget: structuredClone(budget), deadline: future, data_classes: ['PUBLIC'], allowed_origins: ['OWNER'], max_replans: 2, max_actions: 0});
  const grant = versioned({grant_id: 'grant_' + kind.toLowerCase(), grant_version: 1, mission_id: missionId, project_id: projectId, owner_id: 'id_e1_owner', issued_by: 'id_e1_owner', spec_digest: digest(spec), issued_at: FIXTURE_NOW, expires_at: future, revoked_at: null, revocation_reason: null, allowed_principals: principals.map(p => p.principal_id), permissions: ['mission.create', 'mission.revise', 'mission.revoke', 'plan.propose', 'plan.validate', 'plan.publish', 'artifact.read', 'artifact.write', 'qa.evaluate'], allowed_capabilities: capabilities.map(x => x.ref), allowed_data_classes: ['PUBLIC'], allowed_origins: ['OWNER'], allowed_effect_classes: ['NONE'], destinations: [], max_tasks: 8, max_actions: 0, max_replans: 2, budget_cap: structuredClone(budget)});
  const vectors = kind === 'A'
    ? [['source_left', 'research', []], ['source_right', 'research', []], ['dedupe', 'transform', ['source_left', 'source_right']], ['package', 'build', ['dedupe']], ['review', 'qa', ['package']]]
    : [['brief', 'research', []], ['spike', 'research', []], ['design', 'transform', ['brief', 'spike']], ['build', 'build', ['design']], ['review', 'qa', ['build']]];
  const byCapability = Object.fromEntries(capabilities.map(x => [x.ref.capability_id.split('.').at(-1), x.ref]));
  const tasks = vectors.map(([taskId, name, deps]) => {
    const input = {instruction: (kind === 'A' ? 'Fictional career package: ' : 'Independent product: ') + taskId};
    return versioned({task_id: taskId, title: input.instruction, capability: byCapability[name], input, depends_on: deps, dependency_bindings: deps.map(dependency => ({task_id: dependency, output_schema: byCapability[vectors.find(v => v[0] === dependency)[1]].output_schema})), criterion_ids: taskId === 'review' ? ['review'] : ['primary'], budget: structuredClone(budget), deadline: future, timeout_ms: 100, data_classes: ['PUBLIC'], origin: {kind: 'OWNER', source_digests: [fact.digest]}, effect: versioned({effect_id: 'intent_' + taskId, mission_id: missionId, project_id: projectId, task_id: taskId, effect_class: 'NONE', permission: null, destination: null, business_key: null, payload_digest: digest(input), max_actions: 0, reconcile_capability: null, unknown_policy: 'HOLD', outcome: 'NOT_STARTED'}), retry: {max_attempts: 1, retry_on: [], on_unknown: 'HOLD'}, qa: {rubric_id: domain_manifest.qa_rubric.rubric_id, rubric_digest: domain_manifest.qa_rubric.digest, required_checks: domain_manifest.qa_rubric.checks, reviewer_role: 'QA'}});
  });
  const plan = versioned({plan_id: 'plan_' + kind.toLowerCase(), mission_id: missionId, project_id: projectId, revision: 1, spec_digest: digest(spec), grant_digest: digest(grant), grant_version: 1, previous_digest: null, proposed_by: 'id_e1_head', reason: 'Initial bounded offline proposal from domain manifest.', created_at: FIXTURE_NOW, budget: structuredClone(budget), deadline: future, tasks});
  const ingress = createMissionIngress({clock: () => currentTime, authority, capabilities, projectId, domainManifests: [domain_manifest]});
  // Simulate independent JSON documents: no shared mutable object aliases across
  // registry, spec, grant, dependency bindings or proposed task capabilities.
  const jsonCopy = value => JSON.parse(JSON.stringify(value));
  return {kind, spec: jsonCopy(spec), grant: jsonCopy(grant), plan: jsonCopy(plan), facts: jsonCopy(facts), factsSchema: jsonCopy(factsSchema), domain_manifest: jsonCopy(domain_manifest), capabilities: jsonCopy(capabilities), principals: jsonCopy(principals), authority, contexts, ingress, clock: () => currentTime, setTime(value) { currentTime = value; }};
}
export function runFixture(kind = 'A') {
  const fixture = createMissionFixture(kind), {ingress, contexts, spec, grant, plan} = fixture;
  const created = ingress.mission.create({spec, grant}, contexts.owner);
  const proposed = ingress.plan.propose({plan}, contexts.head);
  const validated = ingress.plan.validate({mission_id: spec.mission_id, plan_digest: proposed.plan.digest}, contexts.coordinator);
  const published = ingress.plan.publish({mission_id: spec.mission_id, plan_digest: proposed.plan.digest, validation_digest: validated.validation.digest}, contexts.coordinator);
  return {fixture, created, proposed, validated, published, snapshot: ingress.snapshot(contexts.owner)};
}
export function fixtureSummary(kind = 'A') { const run = runFixture(kind); return immutable({kind, release: RELEASE, project_id: run.fixture.spec.project_id, domain_manifest_digest: digest(run.fixture.domain_manifest), spec_digest: run.created.spec.digest, grant_digest: run.created.grant.digest, plan_digest: run.proposed.plan.digest, decision: run.published.decision, tasks: run.fixture.plan.tasks.map(t => ({task_id: t.task_id, depends_on: t.depends_on})), accepted: false, effects: 0, execution_authorized: false}); }
