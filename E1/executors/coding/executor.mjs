import {digest, immutable, need, exact} from '../../contracts/index.mjs';
import * as codingContracts from './contracts.mjs';
import {MODEL_POLICY} from '../../broker/schemas.mjs';
import {randomUUID} from 'node:crypto';

const {validateCodingTaskGrant, validatePatchProposal, freezeCodingArtifact, PATCH_PROPOSAL_SCHEMA_DIGEST} = codingContracts;

const answer = (decision, reason, more = {}) => immutable({decision, reason, accepted: false, self_development_verified: false, external_mutations: 0, ...more});
const portSpecs = {githubReader: ['SCOPED_GITHUB_ISSUE_READER', 'readIssue'], modelPort: ['ACCOUNTED_PATCH_MODEL_PORT', 'proposePatch'], gitPort: ['ISOLATED_GIT_WORKTREE_PORT', 'inspectBase', 'createWorktree', 'applyPatch', 'readback'], testRunner: ['FIXED_SANDBOX_TEST_RUNNER', 'run'], qaPort: ['INDEPENDENT_FROZEN_ARTIFACT_QA', 'evaluate'], publisher: ['SCOPED_DRAFT_PR_INTENT_PUBLISHER', 'prepareDraftIntent']};

function build(options, profile) {
  const {authority, githubReader, modelPort, gitPort, testRunner, qaPort, publisher, lifecycle = null, invocationIdFactory = () => randomUUID().replaceAll('-', ''), clock = () => new Date().toISOString(), hostProtectedRoots = []} = options;
  const ports = {githubReader, modelPort, gitPort, testRunner, qaPort, publisher};
  need(Array.isArray(hostProtectedRoots) && hostProtectedRoots.every(x => typeof x === 'string' && x.length > 0), 'CODING_HOST_PROTECTION');
  return Object.freeze({profile, async run({grant_ref, context, attempt_scope}) {
    let step = 0, worktree_id = null, artifact = null, model = null, version2 = false;
    const finish = async (decision, reason, more = {}) => {
      const outcome = answer(decision, reason, {profile, artifact, worktree_id, steps_used: step, model_receipt: model, ...more});
      if (version2 && lifecycle?.recordOutcome) {
        try { await lifecycle.recordOutcome(outcome); }
        catch { return answer('HOLD', 'CODING_OUTCOME_PERSISTENCE_FAILED', {...outcome, decision: 'HOLD', reason: 'CODING_OUTCOME_PERSISTENCE_FAILED', original_reason: reason}); }
      }
      return outcome;
    };
    try {
      if (!authority || authority.kind !== 'OWNER_TASK_GRANT_AUTHORITY' || typeof authority.resolve !== 'function') return answer('WAIT', 'CODING_OWNER_GRANT_AUTHORITY_MISSING', {profile});
      if (typeof grant_ref !== 'string' || !grant_ref) return answer('WAIT', 'CODING_OWNER_TASK_GRANT_MISSING', {profile});
      const resolved = await authority.resolve(grant_ref, context);
      if (!resolved) return answer('WAIT', 'CODING_OWNER_TASK_GRANT_MISSING', {profile});
      version2 = resolved.contract_version === 'awe.e1.coding-executor/2';
      const validator = version2 ? codingContracts.validateCodingTaskGrantV2 : validateCodingTaskGrant;
      need(typeof validator === 'function', 'CODING_CONTRACT_VERSION_UNAVAILABLE');
      const grant = validator(resolved, {now: clock(), hostProtectedRoots});
      const assertGrant = async () => {
        const current = await authority.resolve(grant_ref, context);
        need(current && digest(current) === digest(grant), 'CODING_GRANT_CHANGED_OR_REVOKED');
        return validator(current, {now: clock(), hostProtectedRoots});
      };
      for (const [name, [kind, ...methods]] of Object.entries(portSpecs)) {
        if (!ports[name] || ports[name].kind !== kind || !methods.every(method => typeof ports[name][method] === 'function')) return answer('WAIT', 'CODING_REQUIRED_PORT_MISSING:' + name, {profile});
        need(ports[name].mode === profile, 'CODING_PORT_PROFILE_MISMATCH');
      }
      if (profile === 'LIVE_SCOPED_HOST') need(version2, 'CODING_LIVE_V2_GRANT_REQUIRED');
      need(gitPort.isolation === 'ISOLATED_WORKTREE' && testRunner.isolation === 'ALLOWLISTED_OS_SANDBOX' && testRunner.network === 'DENY', 'CODING_SAFE_OS_RUNNER_REQUIRED');
      if (version2 && profile === 'LIVE_SCOPED_HOST') need(lifecycle && typeof lifecycle.persistArtifact === 'function' && typeof lifecycle.recordOutcome === 'function', 'CODING_NATIVE_LIFECYCLE_REQUIRED');
      need(typeof qaPort.principal_id === 'string' && qaPort.principal_id !== grant.producer_id && /^sha256:[a-f0-9]{64}$/.test(qaPort.rubric_digest), 'CODING_INDEPENDENT_QA_REQUIRED');
      need(modelPort.capability_id === grant.model_capability.capability_id && modelPort.route_id === grant.model_capability.route_id && grant.model_capability.output_schema_digest === PATCH_PROPOSAL_SCHEMA_DIGEST, 'CODING_MODEL_BINDING');
      need(attempt_scope && attempt_scope.mission_id === grant.mission_id && attempt_scope.task_id === grant.task_id && attempt_scope.worker_id === grant.producer_id && typeof attempt_scope.attempt_id === 'string' && typeof attempt_scope.logical_request_id === 'string' && /^(?:[1-9][0-9]*)$/.test(String(attempt_scope.fence)), 'CODING_ATTEMPT_SCOPE');
      need((version2 ? 10 : 8) + grant.test_capabilities.length <= grant.max_steps, 'CODING_MAX_STEPS');
      const call = async fn => { await assertGrant(); need(++step <= grant.max_steps, 'CODING_MAX_STEPS'); return fn(); };
      const issue = await call(() => githubReader.readIssue({repository: grant.repository, issue_number: grant.issue_number, grant_ref}));
      exact(issue, ['repository', 'issue_number', 'title', 'body', 'digest']);
      need(digest(issue.repository) === digest(grant.repository) && issue.issue_number === grant.issue_number && typeof issue.title === 'string' && issue.title.length <= 512 && typeof issue.body === 'string' && Buffer.byteLength(issue.body) <= 16384 && digest({repository: issue.repository, issue_number: issue.issue_number, title: issue.title, body: issue.body}) === issue.digest, 'CODING_ISSUE_SCOPE');
      if (version2) need(issue.digest === grant.issue_digest, 'CODING_APPROVED_BRIEF_MISMATCH');
      const readPaths = version2 ? grant.read_allowlist : grant.path_allowlist;
      const baseline = await call(() => gitPort.inspectBase({repository: grant.repository, base_sha: grant.base_sha, paths: readPaths}));
      need(baseline?.base_sha === grant.base_sha, 'CODING_BASE_SHA_MISMATCH');
      need(Array.isArray(baseline.files) && baseline.files.length === readPaths.length && new Set(baseline.files.map(file => file.path)).size === readPaths.length && baseline.files.every(file => readPaths.includes(file.path) && file.ancestry_verified === true && file.ancestor_symlinks === false && ['file', 'missing'].includes(file.kind) && (file.kind === 'missing' || ['100644', '100755'].includes(file.mode))), 'CODING_SYMLINK_OR_BASELINE_DENIED');
      model = await call(() => modelPort.proposePatch({grant_ref, attempt_scope, issue, baseline, output_schema_digest: PATCH_PROPOSAL_SCHEMA_DIGEST, max_attempts: 1, budget_cap_micros: grant.budget.amount_micros, deadline: grant.expires_at}));
      if (version2 && (/UNKNOWN|UNCERTAIN/.test(model?.accounting_status ?? '') || /UNKNOWN|UNCERTAIN/.test(model?.reason ?? ''))) return finish('HOLD', model.reason ?? 'CODING_MODEL_OUTCOME_UNKNOWN', {attempt_scope});
      if (version2 && model?.decision === 'REPAIR' && model.accounting_status === 'CONFIRMED') return finish('REPAIR', model.reason ?? 'CODING_MODEL_OUTPUT_REPAIR', {attempt_scope});
      need(model?.accounting_status === 'CONFIRMED' && model.wire_attempts === 1 && model.route_id === grant.model_capability.route_id && model.attempt_id === attempt_scope.attempt_id && model.evidence_level === profile && model.model?.id === MODEL_POLICY.model && model.model?.digest === MODEL_POLICY.digest && Number.isSafeInteger(model.actual_cost_micros) && model.actual_cost_micros >= 0 && model.actual_cost_micros <= grant.budget.amount_micros && Number.isSafeInteger(model.usage?.input_tokens) && model.usage.input_tokens >= 0 && Number.isSafeInteger(model.usage?.output_tokens) && model.usage.output_tokens >= 0, 'CODING_ACCOUNTED_MODEL_RECEIPT_REQUIRED');
      if (version2 && profile === 'LIVE_SCOPED_HOST') need(model.native_receipt?.response?.evidence_level === 'LIVE_LOCAL_MODEL' && model.native_receipt?.native_attempt?.state === 'CONFIRMED' && model.host_binding_digest === digest(model.native_receipt), 'CODING_LIVE_NATIVE_PROVENANCE_REQUIRED');
      const patch = validatePatchProposal(model.proposal, {grant, baseline, hostProtectedRoots});
      const branch = grant.branch_prefix + grant.grant_id;
      const isolated = await call(() => gitPort.createWorktree({repository: grant.repository, base_sha: grant.base_sha, branch, grant_ref, deadline: grant.expires_at}));
      need(isolated?.isolated === true && isolated.base_sha === grant.base_sha && isolated.branch === branch && typeof isolated.worktree_id === 'string', 'CODING_WORKTREE_ISOLATION'); worktree_id = isolated.worktree_id;
      const applied = await call(() => gitPort.applyPatch({worktree_id, base_sha: grant.base_sha, patch, grant_ref, deadline: grant.expires_at}));
      need(applied?.patch_digest === patch.patch_digest, 'CODING_PATCH_APPLICATION_DIGEST');
      const readback = await call(() => gitPort.readback({worktree_id, base_sha: grant.base_sha}));
      need(readback?.isolated === true && readback.clean === true && readback.committed === true && readback.base_sha === grant.base_sha && readback.head_sha !== grant.base_sha && /^[a-f0-9]{40}$/.test(readback.head_sha) && Array.isArray(readback.files) && readback.files.length === patch.changes.length && new Set(readback.files.map(x => x.path)).size === patch.changes.length, 'CODING_READBACK');
      need(readback.files.every(file => patch.changes.some(change => change.path === file.path && change.after_digest === file.digest) && file.kind === 'file' && file.ancestor_symlinks === false), 'CODING_READBACK_DIGEST');
      if (version2) need(/^[a-f0-9]{40}$/.test(readback.tree_sha), 'CODING_TREE_BINDING_REQUIRED');
      const results = [];
      for (const capability of grant.test_capabilities) {
        need(Date.parse(clock()) + capability.timeout_ms <= Date.parse(grant.expires_at), 'CODING_TEST_DEADLINE');
        const invocation_id = invocationIdFactory({grant, capability, readback});
        need(typeof invocation_id === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{7,159}$/.test(invocation_id), 'CODING_TEST_INVOCATION_ID');
        const result = await call(() => testRunner.run({worktree_id, capability, grant_ref, deadline: grant.expires_at, ...(version2 ? {expected_head_sha: readback.head_sha, expected_tree_sha: readback.tree_sha, profile_digest: grant.test_profile_digest, invocation_id} : {})}));
        need(result?.capability_id === capability.capability_id && result.command_digest === capability.command_digest && result.sandbox_enforced === true && result.network === 'DENY' && Number.isSafeInteger(result.exit_code) && /^sha256:[a-f0-9]{64}$/.test(result.output_digest) && Number.isSafeInteger(result.timeout_ms) && result.timeout_ms > 0 && result.timeout_ms <= capability.timeout_ms, 'CODING_TEST_RECEIPT');
        if (version2) need(result.tested_head_sha === readback.head_sha && result.tested_tree_sha === readback.tree_sha && result.profile_digest === grant.test_profile_digest && result.invocation_id === invocation_id, 'CODING_STALE_TEST_RECEIPT');
        results.push(result);
      }
      if (version2) { const afterTests = await call(() => gitPort.readback({worktree_id, base_sha: grant.base_sha})); need(afterTests.head_sha === readback.head_sha && afterTests.tree_sha === readback.tree_sha && afterTests.clean === true, 'CODING_TEST_TREE_CHANGED'); }
      artifact = freezeCodingArtifact({contract_version: version2 ? 'awe.e1.coding-artifact/2' : 'awe.e1.coding-artifact/1', grant_digest: digest(grant), issue_digest: issue.digest, repository: grant.repository, issue_number: grant.issue_number, base_sha: grant.base_sha, branch, head_sha: readback.head_sha, ...(version2 ? {tree_sha: readback.tree_sha, attempt_scope} : {}), patch, tests: results, producer_id: grant.producer_id, rubric_digest: qaPort.rubric_digest, model_receipt_digest: digest(model), steps_used: step, profile});
      if (version2 && lifecycle?.persistArtifact) await call(() => lifecycle.persistArtifact({artifact, proposal: model.proposal, model_receipt: model, product_status: results.some(result => result.exit_code !== 0) ? 'PRODUCER_TEST_FAILED' : 'PENDING_INDEPENDENT_QA'}));
      if (results.some(result => result.exit_code !== 0)) return finish('REPAIR', 'CODING_FIXED_TEST_FAILED');
      const qa = await call(() => qaPort.evaluate({artifact, artifact_digest: artifact.artifact_digest, grant_ref}));
      need(qa && qa.artifact_digest === artifact.artifact_digest && qa.rubric_digest === artifact.rubric_digest && qa.evaluator_id === qaPort.principal_id && qa.evaluator_id !== grant.producer_id && qa.producer_id === grant.producer_id && qa.accepted === false, 'CODING_INDEPENDENT_QA_BINDING');
      if (qa.verdict !== 'PASS') return finish('REPAIR', 'CODING_INDEPENDENT_QA_REJECTED', {qa});
      const intent = immutable({intent_kind: 'DRAFT_PR', repository: grant.repository, issue_number: grant.issue_number, base_sha: grant.base_sha, head_sha: readback.head_sha, branch, title: patch.summary.slice(0, 160), artifact_digest: artifact.artifact_digest, qa_digest: digest(qa), grant_digest: digest(grant), draft: true, automatic_merge: false, production_release: false});
      const prepared = await call(() => publisher.prepareDraftIntent({intent, intent_digest: digest(intent), grant_ref, qa}));
      need(prepared?.status === 'DRAFT_PR_INTENT' && prepared.intent_digest === digest(intent) && prepared.external_mutations === 0, 'CODING_DRAFT_INTENT_BINDING');
      return finish('DRAFT_PR_INTENT', 'CODING_PREPARED_FOR_SCOPED_HOST_PUBLICATION', {qa, intent, intent_digest: digest(intent)});
    } catch (error) {
      if (!model && modelPort?.lastReceipt) model = immutable({native_receipt: modelPort.lastReceipt, accounting_status: modelPort.lastReceipt.response?.accounting_status ?? 'UNVERIFIED', wire_attempts: modelPort.lastReceipt.response?.wire_attempts ?? 0});
      if (version2 && /UNKNOWN|UNCERTAIN/.test(model?.accounting_status ?? '')) return finish('HOLD', error.code ?? 'CODING_MODEL_OUTCOME_UNKNOWN');
      return finish(error.code?.includes('EXPIRED') ? 'WAIT' : 'BLOCK', error.code ?? 'CODING_TRUSTED_PORT_FAILURE');
    }
  }});
}
export function createCodingExecutor(options) { return build(options, 'LIVE_SCOPED_HOST'); }
export function createOfflineCodingExecutorForTests(options, {label}) { need(label === 'OFFLINE_TEST_DOUBLE', 'CODING_TEST_LABEL_REQUIRED'); return build(options, 'OFFLINE_TEST_DOUBLE'); }
