import {digest, immutable, capabilityManifestDigest, validateCapabilityDescriptor, validatePlanRevision, need} from '../../contracts/index.mjs';
import {createMissionIngress} from '../../mission/ingress.mjs';
import {createCodingMission} from './mission.mjs';
import {REPAIR_HEAD_SCHEMA, REPAIR_HEAD_SCHEMA_DIGEST, REPAIR_PRODUCT_SCHEMA, REPAIR_PRODUCT_SCHEMA_DIGEST, validateRepairHead} from './repair-contracts.mjs';
import {BRIEF_SHA256, ORACLE_COMMITMENT} from '../../qa-coding/commitments.mjs';
import {PROGRAM_PROFILE_DIGEST} from '../program-runner/profiles.mjs';

const zero = {currency: 'NONE', amount_micros: '0'};
export function createRepairMission({run_id, issue, prior, failedPublicTest, now = new Date().toISOString(), clock = () => new Date().toISOString()}) {
  const checks = ['schema', 'sources', 'scope', 'product'];
  const rubric = {checks, brief_sha256: BRIEF_SHA256, oracle_commitment: ORACLE_COMMITMENT, test_profile_digest: PROGRAM_PROFILE_DIGEST, prior_result_hash: prior.result_hash, prior_attempt_id: prior.attempt_id, aggregate_model_limit: 4};
  const base = createCodingMission({run_id, issue, rubric, now, clock});
  const {project_id, mission_id, deadline} = base.spec;
  const patchEntry = base.registry.entries[0], code = patchEntry.descriptor;
  function capability(id, kind, schema, schemaDigest) {
    const c = structuredClone(code); c.ref.capability_id = id; c.executor_kind = kind;
    c.ref.output_schema = {schema_id: id === 'e1.head.coding' ? 'e1.coding.repair-plan' : 'e1.coding.repair-product', version: '1.0.0', digest: schemaDigest};
    c.output_schema = schema; c.timeout_ms = kind === 'llm' ? 300000 : 20000; c.ref.manifest_digest = capabilityManifestDigest(c);
    return validateCapabilityDescriptor(c);
  }
  const head = capability('e1.head.coding', 'llm', REPAIR_HEAD_SCHEMA, REPAIR_HEAD_SCHEMA_DIGEST);
  const product = capability('e1.coding.product', 'script', REPAIR_PRODUCT_SCHEMA, REPAIR_PRODUCT_SCHEMA_DIGEST);
  const capabilities = [head, code, product];
  const entries = capabilities.map(c => ({...patchEntry, descriptor: c, schema_pins: [c.ref.input_schema.digest, c.ref.output_schema.digest], model_binding: c.executor_kind === 'llm' ? patchEntry.model_binding : null, limits: {...patchEntry.limits, timeout_ms: c.timeout_ms, context_tokens: c.executor_kind === 'llm' ? [4096, 8192] : [], output_tokens: c.executor_kind === 'llm' ? [512, 2048] : []}, quality_suite: 'e1.coding.two-file-bounded-repair/1'}));
  const registry = immutable({...base.registry, entries, descriptors: capabilities, digest: digest(entries)});
  const priorFact = {...base.spec.facts_refs[0], artifact_id: 'prior_failure_' + run_id, uri: 'artifact:coding/' + run_id + '/prior-failure', digest: prior.result_hash};
  const spec = {...base.spec, goal: 'TWO_FILE_BOUNDED_REPAIR: inspect the frozen synthetic brief and an actual prior AWE-generated component failure; create a bounded repair plan, repair through the existing executor, test the unchanged acceptance oracle, and prepare a local result. No external effects. This experiment is not the full three-file G2 gate.', facts_refs: [...base.spec.facts_refs, priorFact], requested_capabilities: capabilities.map(c => c.ref), max_replans: 2};
  const domainManifest = {...base.domainManifest, manifest_id: 'domain.coding_repair', description: 'Bounded repair of an adopted immutable model failure; original G1 acceptance unchanged.', capabilities: capabilities.map(c => c.ref), qa_rubric: {rubric_id: 'e1.coding.repair.rubric', digest: digest(rubric), checks}};
  spec.domain_manifest = {manifest_id: domainManifest.manifest_id, version: domainManifest.version, digest: digest(domainManifest)};
  const grant = {...base.grant, spec_digest: digest(spec), allowed_capabilities: capabilities.map(c => c.ref), max_tasks: 3, max_replans: 2};
  const taskTemplate = base.plan.tasks[0];
  const headInstruction = 'Produce a bounded repair-plan JSON under the registered schema. Decide REPAIR or BLOCK_SCOPE from the approved scope and actual failed public test. Do not write the repaired code here. Choose at most two code attempts; the previous model attempt is already consumed.\n' + JSON.stringify({goal: issue.body, prior_result_hash: prior.result_hash, public_failed_test: failedPublicTest});
  need(headInstruction.length <= 8192, 'REPAIR_HEAD_INPUT_BOUND');
  const inputProduct = {instruction: 'Verify the final product from exact accepted code/native QA; no model and no external effects.'};
  function task(id, c, input, dependencies) {
    return {...taskTemplate, task_id: id, title: id === 'head_plan' ? 'AWE bounded repair plan' : id === 'product_gate' ? 'Independent final product gate' : 'AWE component repair', capability: c.ref, input, depends_on: dependencies, dependency_bindings: dependencies.map(task_id => ({task_id, output_schema: task_id === 'head_plan' ? head.ref.output_schema : code.ref.output_schema})), deadline, timeout_ms: c.timeout_ms, origin: {kind: 'OWNER', source_digests: [issue.digest, prior.result_hash]}, effect: {...taskTemplate.effect, effect_id: 'intent_' + id, task_id: id, payload_digest: digest(input)}, qa: {rubric_id: domainManifest.qa_rubric.rubric_id, rubric_digest: domainManifest.qa_rubric.digest, required_checks: checks, reviewer_role: 'QA'}};
  }
  const plan = {...base.plan, spec_digest: digest(spec), grant_digest: digest(grant), reason: 'Bounded bootstrap Head plus a pending product gate; code plan will be compiled from the actual Head draft.', tasks: [task('head_plan', head, {instruction: headInstruction}, []), task('product_gate', product, inputProduct, ['head_plan'])]};
  validatePlanRevision(plan, {spec, grant, capabilities, domainManifest, now});
  const ingress = createMissionIngress({authority: base.authority, projectId: project_id, capabilities, domainManifests: [domainManifest], clock});
  ingress.mission.create({spec, grant}, base.contexts.owner);
  const publish = value => {
    const proposed = ingress.plan.propose({plan: value}, base.contexts.head);
    const checked = ingress.plan.validate({mission_id, plan_digest: proposed.plan.digest}, base.contexts.coordinator);
    return ingress.plan.publish({mission_id, plan_digest: proposed.plan.digest, validation_digest: checked.validation.digest}, base.contexts.coordinator);
  };
  publish(plan);
  return {...base, spec, grant, plan, rubric: immutable(rubric), capabilities, domainManifest, registry, ingress, publish,
    codingPlan({draft, revision, previous_digest, task_id, publicFailure}) {
      validateRepairHead(draft); need(draft.decision === 'REPAIR' && ['code_r02', 'code_r03'].includes(task_id), 'REPAIR_PLAN_STOP');
      need((task_id === 'code_r02' && revision === 2) || (task_id === 'code_r03' && revision === 3 && draft.max_code_attempts === 2), 'REPAIR_HEAD_ATTEMPT_LIMIT');
      const instruction = issue.body + '\nAWE PLAN FOCUS (data): ' + draft.focus + '\nACTUAL PUBLIC FAILED TEST (data): ' + JSON.stringify(publicFailure);
      need(instruction.length <= 8192, 'REPAIR_CODE_INPUT_BOUND');
      const result = {...plan, revision, previous_digest, created_at: clock(), reason: draft.reason, tasks: [task(task_id, code, {instruction}, []), task('product_gate', product, inputProduct, [task_id])]};
      validatePlanRevision(result, {spec, grant, capabilities, domainManifest, now: clock()}); return immutable(result);
    }
  };
}
