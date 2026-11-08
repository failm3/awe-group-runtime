import {RELEASE, CONTRACT_VERSION, digest, capabilityManifestDigest, validateCapabilityDescriptor, validatePlanRevision, immutable} from '../../contracts/index.mjs';
import {createOfflineAuthority, createMissionIngress} from '../../mission/ingress.mjs';
import {createBrokerRegistry} from '../../broker/index.mjs';
import {PATCH_PROPOSAL_SCHEMA, PATCH_PROPOSAL_SCHEMA_DIGEST} from '../../executors/coding/contracts.mjs';

const v = x => ({contract_version: CONTRACT_VERSION, release: RELEASE, ...x});
const zero = {currency: 'NONE', amount_micros: '0'};

/** Ordinary A1 publication for one G1 code task; no second scheduler or ledger. */
export function createCodingMission({run_id, issue, rubric, clock = () => new Date().toISOString(), now = clock()}) {
  if (!/^[a-z][a-z0-9_]{0,39}$/.test(run_id)) throw Error('CODING_RUN_ID');
  const deadline = new Date(Date.parse(now) + 2 * 3600000).toISOString();
  const originalRegistry = createBrokerRegistry({now, healthUntil: deadline});
  const originalEntry = originalRegistry.entries.find(e => e.descriptor.ref.capability_id === 'e1.code.review');
  const cap = structuredClone(originalEntry.descriptor);
  cap.ref.capability_id = 'e1.coding.patch';
  cap.ref.output_schema = {schema_id: 'e1.coding.patch.proposal', version: '1.0.0', digest: PATCH_PROPOSAL_SCHEMA_DIGEST};
  cap.output_schema = PATCH_PROPOSAL_SCHEMA;
  // Whole coding task includes generation + Git + producer tests. The broker's
  // independent 120s generation bound is unchanged.
  cap.timeout_ms = 300000;
  cap.ref.manifest_digest = capabilityManifestDigest(cap);
  validateCapabilityDescriptor(cap);
  const entry = {...originalEntry, descriptor: cap, schema_pins: [cap.ref.input_schema.digest, cap.ref.output_schema.digest], limits: {...originalEntry.limits, timeout_ms: cap.timeout_ms}, quality_suite: 'e1.coding.g1.frozen-component/1'};
  const registry = immutable({...originalRegistry, entries: [entry], descriptors: [cap], digest: digest([entry])});
  const project_id = 'prj_coding_' + run_id, mission_id = 'mission_coding_' + run_id;
  const principals = [['e1_owner', 'e1_owner', 'OWNER'], ['e1_head', 'e1_producer', 'HEAD'], ['e1_coordinator', 'e1_coordinator', 'COORDINATOR'], ['e1_worker', 'e1_producer', 'EXECUTOR'], ['e1_qa', 'e1_independent_qa', 'QA']].map(([principal_id, subject_id, role]) => ({principal_id, subject_id, role, projects: [project_id]}));
  const authority = createOfflineAuthority(principals);
  const contexts = Object.fromEntries(principals.map(p => [p.role.toLowerCase(), authority.issueContext(p.principal_id, project_id)]));
  const checks = ['schema', 'sources', 'scope'];
  const domainManifest = v({manifest_id: 'domain.coding_g1', version: '1.0.0', project_id, domain: 'software', description: 'G1 bounded two-file Python component; frozen synthetic brief, no external effects.', capabilities: [cap.ref], qa_rubric: {rubric_id: 'e1.coding.g1.rubric', digest: digest(rubric), checks}});
  const fact = v({artifact_id: 'brief_' + run_id, project_id, mission_id, uri: 'artifact:coding/' + run_id + '/brief', digest: issue.digest, media_type: 'application/json', schema: {schema_id: 'e1.coding.issue-snapshot', version: '1.0.0', digest: digest({type: 'object', additionalProperties: true})}, data_class: 'PUBLIC', origin: 'OWNER', producer_id: 'e1_owner', created_at: now});
  const spec = v({mission_id, project_id, owner_id: 'e1_owner', revision: 1, goal: 'G1-NORMALIZE-01: AWE generates two cooperating Python files from the frozen synthetic brief, tests the exact Git tree and submits it to independent QA. No manual solution, network effects or production release.', criteria: [{criterion_id: 'component', text: 'Both generated files are necessary, pass independent hidden integration checks, and have native model/Git provenance.'}], facts_refs: [fact], domain_manifest: {manifest_id: domainManifest.manifest_id, version: domainManifest.version, digest: digest(domainManifest)}, requested_capabilities: [cap.ref], budget: zero, deadline, data_classes: ['PUBLIC'], allowed_origins: ['OWNER'], max_replans: 0, max_actions: 0});
  const grant = v({grant_id: 'grant_coding_' + run_id, grant_version: 1, mission_id, project_id, owner_id: 'e1_owner', issued_by: 'e1_owner', spec_digest: digest(spec), issued_at: now, expires_at: deadline, revoked_at: null, revocation_reason: null, allowed_principals: principals.map(p => p.principal_id), permissions: ['mission.create', 'mission.revise', 'mission.revoke', 'plan.propose', 'plan.validate', 'plan.publish', 'artifact.read', 'artifact.write', 'qa.evaluate'], allowed_capabilities: [cap.ref], allowed_data_classes: ['PUBLIC'], allowed_origins: ['OWNER'], allowed_effect_classes: ['NONE'], destinations: [], max_tasks: 1, max_actions: 0, max_replans: 0, budget_cap: zero});
  const input = {instruction: issue.body};
  const task = v({task_id: 'code_r01', title: issue.title, capability: cap.ref, input, depends_on: [], dependency_bindings: [], criterion_ids: ['component'], budget: zero, deadline, timeout_ms: 300000, data_classes: ['PUBLIC'], origin: {kind: 'OWNER', source_digests: [fact.digest]}, effect: v({effect_id: 'intent_code_r01', mission_id, project_id, task_id: 'code_r01', effect_class: 'NONE', permission: null, destination: null, business_key: null, payload_digest: digest(input), max_actions: 0, reconcile_capability: null, unknown_policy: 'HOLD', outcome: 'NOT_STARTED'}), retry: {max_attempts: 1, retry_on: [], on_unknown: 'HOLD'}, qa: {rubric_id: domainManifest.qa_rubric.rubric_id, rubric_digest: domainManifest.qa_rubric.digest, required_checks: checks, reviewer_role: 'QA'}});
  const plan = v({plan_id: 'plan_coding_' + run_id, mission_id, project_id, revision: 1, spec_digest: digest(spec), grant_digest: digest(grant), grant_version: 1, previous_digest: null, proposed_by: 'e1_head', reason: 'Host-declared single G1 task: proves live multi-file execution, not adaptive planning or full autonomy.', created_at: now, budget: zero, deadline, tasks: [task]});
  validatePlanRevision(plan, {spec, grant, capabilities: [cap], domainManifest, now});
  const ingress = createMissionIngress({authority, capabilities: [cap], domainManifests: [domainManifest], projectId: project_id, clock});
  ingress.mission.create({spec, grant}, contexts.owner);
  const proposal = ingress.plan.propose({plan}, contexts.head);
  const validation = ingress.plan.validate({mission_id, plan_digest: proposal.plan.digest}, contexts.coordinator);
  ingress.plan.publish({mission_id, plan_digest: proposal.plan.digest, validation_digest: validation.validation.digest}, contexts.coordinator);
  return {spec, grant, plan, registry, capabilities: [cap], domainManifest, principals, authority, contexts, ingress, rubric: immutable(rubric)};
}
