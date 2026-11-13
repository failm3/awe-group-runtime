import {RELEASE, CONTRACT_VERSION, digest, immutable, canonicalize, need, validateBoundValue, validateMissionBinding, validatePlanRevision} from '../contracts/index.mjs';
import {createOfflineAuthority, createMissionIngress} from '../mission/ingress.mjs';
import {createBrokerRegistry, requireRegistryEntry} from './registry.mjs';

const versioned = value => ({contract_version: CONTRACT_VERSION, release: RELEASE, ...value});
export const MAINTENANCE_SOURCE = immutable({synthetic: true, language: 'javascript', filename: 'numeric-sort.mjs', source: 'export function numericSorted(values) { return [...values].sort(); }', expected: ['Sort numbers in numerical ascending order.', 'Preserve the original input array.'], cases: [{input: [10, 2, -1], output: [-1, 2, 10]}, {input: [], output: []}]});
export const MAINTENANCE_RUBRIC = immutable({version: 'e1.code-maintenance.frozen-rubric/1', checks: ['schema', 'numeric_order', 'input_preserved', 'independent_qa', 'scope'], minimum: 'All checks pass; no external effects; producer cannot accept.'});

/** Synthetic owner bootstrap for the staging entrypoint; it cannot publish or accept itself. */
export function createMaintenanceMission({now = new Date().toISOString(), registry = createBrokerRegistry({now}), suffix = 'canary', ttlMs = 3600000, concise = false} = {}) {
  need(/^[a-z0-9_-]{1,24}$/.test(suffix), 'A3_FIXTURE_SUFFIX');
  need(typeof concise === 'boolean', 'A3_FIXTURE_CONCISE');
  const projectId = 'prj_code_maintenance', missionId = 'mission_code_' + suffix;
  const deadline = new Date(Date.parse(now) + ttlMs).toISOString();
  const principals = [
    {principal_id: 'e1_owner', subject_id: 'e1_owner', role: 'OWNER', projects: [projectId]},
    {principal_id: 'e1_head', subject_id: 'e1_producer', role: 'HEAD', projects: [projectId]},
    {principal_id: 'e1_coordinator', subject_id: 'e1_coordinator', role: 'COORDINATOR', projects: [projectId]},
    {principal_id: 'e1_worker', subject_id: 'e1_producer', role: 'EXECUTOR', projects: [projectId]},
    {principal_id: 'e1_qa', subject_id: 'e1_independent_qa', role: 'QA', projects: [projectId]}
  ];
  const authority = createOfflineAuthority(principals), contexts = Object.fromEntries(principals.map(p => [p.role.toLowerCase(), authority.issueContext(p.principal_id, projectId)]));
  const domainManifest = versioned({manifest_id: 'domain.code_maintenance', version: '1.0.0', project_id: projectId, domain: 'code_maintenance', description: 'Synthetic numerical-sort maintenance canary, no live repository or external effects.', capabilities: registry.descriptors.map(x => x.ref), qa_rubric: {rubric_id: 'e1.code_maintenance.rubric', digest: digest(MAINTENANCE_RUBRIC), checks: MAINTENANCE_RUBRIC.checks}});
  const fact = versioned({artifact_id: 'facts_code_' + suffix, project_id: projectId, mission_id: missionId, uri: 'artifact:code-maintenance/' + suffix + '/source', digest: digest(MAINTENANCE_SOURCE), media_type: 'application/json', schema: {schema_id: 'e1.synthetic.source', version: '1.0.0', digest: digest({kind: 'synthetic-code-maintenance', version: 1})}, data_class: 'PUBLIC', origin: 'OWNER', producer_id: 'e1_owner', created_at: now});
  const zero = {currency: 'NONE', amount_micros: '0'};
  const goal = concise
    ? 'Plan exactly two maintenance tasks for numericSorted: numerical ascending order and input preservation. Reason <=10 words; each title <=4 words; each instruction <=10 words; total JSON <=250 tokens. Request independent QA. No code execution, shell, network tools, publication, or new product ideas.'
    : 'Produce a bounded maintenance plan for numericSorted: numerical ascending order for negative and multi-digit numbers, preserving input. Inspect deterministic source before semantic review. No code execution, shell, network tools, publication, or new product ideas.';
  const criteria = concise
    ? [{criterion_id: 'correctness', text: 'Numeric order; preserve input.'}, {criterion_id: 'review', text: 'Semantic review depends on deterministic inspection; independent QA.'}]
    : [{criterion_id: 'correctness', text: 'Plan covers numeric ascending order and input preservation using the supplied synthetic cases.'}, {criterion_id: 'review', text: 'Semantic review depends on deterministic inspection and requests independent frozen-rubric QA.'}];
  const spec = versioned({mission_id: missionId, project_id: projectId, owner_id: 'e1_owner', revision: 1, goal, criteria, facts_refs: [fact], domain_manifest: {manifest_id: domainManifest.manifest_id, version: domainManifest.version, digest: digest(domainManifest)}, requested_capabilities: registry.descriptors.map(x => x.ref), budget: zero, deadline, data_classes: ['PUBLIC'], allowed_origins: ['OWNER'], max_replans: 2, max_actions: 0});
  const grant = versioned({grant_id: 'grant_code_' + suffix, grant_version: 1, mission_id: missionId, project_id: projectId, owner_id: 'e1_owner', issued_by: 'e1_owner', spec_digest: digest(spec), issued_at: now, expires_at: deadline, revoked_at: null, revocation_reason: null, allowed_principals: principals.map(x => x.principal_id), permissions: ['mission.create', 'mission.revise', 'mission.revoke', 'plan.propose', 'plan.validate', 'plan.publish', 'artifact.read', 'artifact.write', 'qa.evaluate'], allowed_capabilities: registry.descriptors.map(x => x.ref), allowed_data_classes: ['PUBLIC'], allowed_origins: ['OWNER'], allowed_effect_classes: ['NONE'], destinations: [], max_tasks: 8, max_actions: 0, max_replans: 2, budget_cap: zero});
  const byId = new Map(registry.descriptors.map(x => [x.ref.capability_id, x]));
  const tasks = [['parse_source', 'e1.code.parse', 'correctness'], ['head_control', 'e1.head.plan', 'review']].map(([task_id, capability_id, criterion_id]) => {
    const cap = byId.get(capability_id), input = {instruction: capability_id === 'e1.code.parse' ? JSON.stringify(MAINTENANCE_SOURCE) : 'Produce a bounded typed maintenance proposal for the supplied numerical-sort helper.'};
    return versioned({task_id, title: task_id === 'head_control' ? 'Bounded Head planning control task' : 'Parse synthetic source JSON', capability: cap.ref, input, depends_on: [], dependency_bindings: [], criterion_ids: [criterion_id], budget: zero, deadline, timeout_ms: cap.timeout_ms, data_classes: ['PUBLIC'], origin: {kind: 'OWNER', source_digests: [fact.digest]}, effect: versioned({effect_id: 'intent_' + task_id, mission_id: missionId, project_id: projectId, task_id, effect_class: 'NONE', permission: null, destination: null, business_key: null, payload_digest: digest(input), max_actions: 0, reconcile_capability: null, unknown_policy: 'HOLD', outcome: 'NOT_STARTED'}), retry: {max_attempts: 1, retry_on: [], on_unknown: 'HOLD'}, qa: {rubric_id: domainManifest.qa_rubric.rubric_id, rubric_digest: domainManifest.qa_rubric.digest, required_checks: domainManifest.qa_rubric.checks, reviewer_role: 'QA'}});
  });
  const bootstrapPlan = versioned({plan_id: 'plan_code_' + suffix, mission_id: missionId, project_id: projectId, revision: 1, spec_digest: digest(spec), grant_digest: digest(grant), grant_version: 1, previous_digest: null, proposed_by: 'e1_head', reason: 'Owner-supplied deterministic bootstrap to account one bounded Head model attempt in D09.', created_at: now, budget: zero, deadline, tasks});
  const validation = validatePlanRevision(bootstrapPlan, {spec, grant, capabilities: registry.descriptors, domainManifest, now});
  const ingress = createMissionIngress({authority, capabilities: registry.descriptors, domainManifests: [domainManifest], projectId, clock: () => new Date().toISOString()});
  return {registry, source: MAINTENANCE_SOURCE, rubric: MAINTENANCE_RUBRIC, spec: immutable(spec), grant: immutable(grant), domainManifest: immutable(domainManifest), bootstrapPlan: immutable(bootstrapPlan), validation, authority, contexts, principals, ingress};
}

/** Fixed JSON parser, never eval/spawn/shell/DB/network. Its output is a frozen artifact. */
export function runPinnedScript({registry, spec, grant, input, now = new Date().toISOString()}) {
  validateMissionBinding(spec, grant, now);
  const cap = requireRegistryEntry(registry, 'e1.code.parse', now).descriptor;
  need(spec.requested_capabilities.some(x => digest(x) === digest(cap.ref)) && grant.allowed_capabilities.some(x => digest(x) === digest(cap.ref)) && cap.permissions.every(x => grant.permissions.includes(x)), 'A3_CAPABILITY_DENIED');
  validateBoundValue(cap.input_schema, input);
  const output = validateBoundValue(cap.output_schema, {text: canonicalize(JSON.parse(input.instruction))});
  return immutable({decision: 'ARTIFACT', executor_kind: 'script', output, artifact_digest: digest(output), accepted: false, effects: 0, evidence_level: 'DETERMINISTIC_LOCAL_EXECUTION'});
}

/** Freezes producer bytes; independent QA must verify this exact digest and rubric. */
export function freezeBrokerArtifact({output, producer_id, task_id, plan_digest, rubric_digest}) {
  return immutable({output, artifact_digest: digest(output), producer_id, task_id, plan_digest, rubric_digest, accepted: false});
}
