import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {digest, immutable, need, utc} from '../../contracts/index.mjs';
import {createNativeE1Host} from '../staging.mjs';
import {createPsqlSession, createCoordinator, createAuthorityServer, createAuthorityClient, validateResourceDescriptor} from '../../coordinator/index.mjs';
import {createCodingRunStore} from '../../coordinator/coding-run.mjs';
import {modelRequestIds} from '../artifact-binding.mjs';
import {verifyProgramReceipt} from '../program-runner/receipts.mjs';
import {PROGRAM_PROFILE_DIGEST} from '../program-runner/profiles.mjs';
import {createRepairMission} from './repair-mission.mjs';
import {createGitPort} from './git-port.mjs';
import {createCodingGrantAuthority} from './grant-authority.mjs';
import {CODING_HOST_PROTECTED_ROOTS} from './policy.mjs';
import {CODING_CONTRACT_VERSION_V2, CODING_PERMISSIONS, PATCH_PROPOSAL_SCHEMA_DIGEST} from '../../executors/coding/contracts.mjs';
import {MODEL_POLICY} from '../../broker/schemas.mjs';
import {BRIEF_SHA256, ORACLE_COMMITMENT} from '../../qa-coding/commitments.mjs';

const runtimeRoot = fileURLToPath(new URL('../../../', import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const allowedStages = new Set(['head_plan', 'code_r02', 'code_r03', 'product_gate']);
const safeFile = filename => { const st = fs.lstatSync(filename); need(st.isFile() && !st.isSymbolicLink() && st.nlink === 1 && st.size <= 131072, 'REPAIR_SESSION_FILE'); return fs.readFileSync(filename); };
const load = filename => { try { return JSON.parse(safeFile(filename).toString('utf8')); } catch (error) { if (error.code === 'REPAIR_SESSION_FILE') throw error; need(false, 'REPAIR_SESSION_JSON'); } };
function writeOnce(filename, value) {
  if (fs.existsSync(filename)) { need(digest(load(filename)) === digest(value), 'REPAIR_SESSION_IMMUTABLE_FILE_CHANGED'); return; }
  fs.mkdirSync(path.dirname(filename), {recursive: true}); const fd = fs.openSync(filename, 'wx', 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value, null, 2) + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

/** Pure comparison of old immutable evidence with the fresh read-only native
 * view. The report predates native QA FAIL; its WAIT_QA label is not rewritten. */
export function inspectRepairPrior({report, witness, snapshot, events, report_sha256}) {
  need(report?.run_id === 'g1_normalize_01' && witness?.schema === 'awe.g1.independent-negative-cold-review/1' && witness.verdict === 'FAIL' && witness.reason === 'CLI_SYNTAX_ERROR_REPRODUCED' && witness.report_sha256 === 'sha256:' + report_sha256.replace(/^sha256:/, '') && witness.qa_fail_events === 1 && witness.qa_pass_events === 0, 'REPAIR_PRIOR_WITNESS');
  const project_id = report.fixture.spec.project_id, mission_id = report.fixture.spec.mission_id;
  need(witness.project_id === project_id && witness.mission_id === mission_id && snapshot.project.project_id === project_id && Number(snapshot.project.quota_used) === 1 && Number(snapshot.project.spent) === 0 && Number(snapshot.project.reserved) === 0, 'REPAIR_PRIOR_PROJECT');
  const task = snapshot.tasks.find(t => t.mission_id === mission_id && t.task_id === 'code_r01' && t.is_current);
  need(task?.state === 'FAILED' && task.result_hash === witness.result_hash && digest(task.result) === task.result_hash && task.plan_digest === witness.plan_digest && report.native_task.result_hash === task.result_hash, 'REPAIR_PRIOR_NATIVE_FAILURE');
  const artifact = task.result.evidence.coding_artifact, {accepted, artifact_digest, ...artifactBody} = artifact;
  need(accepted === false && artifact_digest === digest(artifactBody) && artifact_digest === witness.artifact_digest && digest(artifact) === digest(report.outcome.artifact) && artifact.head_sha === witness.head_sha && artifact.tree_sha === witness.tree_sha && artifact.issue_digest === witness.issue_digest, 'REPAIR_PRIOR_ARTIFACT');
  const attempts = snapshot.attempts.filter(a => a.mission_id === mission_id);
  need(attempts.length === 1, 'REPAIR_PRIOR_ATTEMPT_COUNT'); const attempt = attempts[0];
  need(attempt.state === 'CONFIRMED' && attempt.project_id === project_id && attempt.task_id === 'code_r01' && attempt.attempt_id === witness.native_attempt.attempt_id && attempt.request_hash === witness.native_attempt.request_hash && attempt.route_id === MODEL_POLICY.route_id && attempt.worker_id === task.producer_id && String(attempt.fence) === String(task.fence) && Number(attempt.actual_cost) === 0 && Number(attempt.quota_units) === 1 && digest(attempt) === digest(report.native_attempts[0]), 'REPAIR_PRIOR_NATIVE_ATTEMPT');
  const model = task.result.evidence.model_receipt;
  need(model.accounting_status === 'CONFIRMED' && model.native_receipt.response.evidence_level === 'LIVE_LOCAL_MODEL' && model.native_receipt.response.request_hash === attempt.request_hash && digest(model.native_receipt.response.usage) === digest(attempt.usage) && digest(model.native_receipt.native_attempt) === digest(attempt), 'REPAIR_PRIOR_MODEL_PROVENANCE');
  const fail = events.filter(e => e.mission_id === mission_id && e.task_id === 'code_r01' && e.kind === 'QA_FAIL'), pass = events.filter(e => e.mission_id === mission_id && e.task_id === 'code_r01' && e.kind === 'QA_PASS');
  need(fail.length === 1 && pass.length === 0 && fail[0].body.evaluator_id === 'e1_qa' && fail[0].body.result_hash === task.result_hash, 'REPAIR_PRIOR_QA_EVENTS');
  const producer = artifact.tests[0], receipt = producer.program_receipt;
  const request = {files: artifact.patch.changes.map(({path, after_text}) => ({path, content_utf8: after_text})), stdin: '{"id":" Z9 ","kind":" Open ","n":4}\n', entrypoint: 'cli.py', binding: {tested_head_sha: artifact.head_sha, tested_tree_sha: artifact.tree_sha, invocation_id: producer.invocation_id}};
  verifyProgramReceipt(receipt, request);
  need(producer.exit_code !== 0 && receipt.exit_code !== 0 && /SyntaxError/.test(receipt.stderr), 'REPAIR_PRIOR_PUBLIC_FAILURE');
  const prior = {project_id, mission_id, task_id: 'code_r01', attempt_id: attempt.attempt_id, logical_request_id: attempt.logical_request_id, worker_id: attempt.worker_id, fence: Number(attempt.fence), plan_digest: task.plan_digest, result_hash: task.result_hash, artifact_digest, head_sha: artifact.head_sha, tree_sha: artifact.tree_sha, request_hash: attempt.request_hash};
  const failedPublicTest = {reason: witness.reason, exit_code: receipt.exit_code, stderr: receipt.stderr, stdout: receipt.stdout, input_origin: 'ORIGINAL_PUBLIC_EXAMPLE_ONLY', tested_head_sha: artifact.head_sha, tested_tree_sha: artifact.tree_sha, receipt_digest: receipt.receipt_digest};
  return immutable({prior, failedPublicTest, artifact, issue: report.issue});
}

/** Staging composition only: ordinary A1 publication and the existing A2/A3
 * services. Nothing starts on import and no model call is made by this helper. */
export async function openRepairSession(config) {
  const {run_id, started_at, resourcePath, issueSnapshotPath, priorReportPath, priorWitnessPath, privateRoot, source_digest} = config;
  need(/^[a-z][a-z0-9_]{0,39}$/.test(run_id) && /^sha256:[a-f0-9]{64}$/.test(source_digest) && path.isAbsolute(privateRoot), 'REPAIR_SESSION_CONFIG'); utc(started_at);
  need(Date.parse(started_at) <= Date.now() && Date.now() < Date.parse(started_at) + 2 * 3600000, 'REPAIR_SESSION_DEADLINE');
  fs.mkdirSync(privateRoot, {recursive: true, mode: 0o700});
  need(!fs.lstatSync(privateRoot).isSymbolicLink() && fs.realpathSync(privateRoot).toLowerCase() === path.resolve(privateRoot).toLowerCase(), 'REPAIR_SESSION_PRIVATE_ROOT');
  const resource = validateResourceDescriptor(load(resourcePath)), reportBytes = safeFile(priorReportPath), report = JSON.parse(reportBytes), witness = load(priorWitnessPath), snapshotIssue = load(issueSnapshotPath);
  const briefBytes = safeFile(path.join(runtimeRoot, 'E1/qa-coding/public-brief.json')), brief = JSON.parse(briefBytes);
  need(sha(briefBytes) === BRIEF_SHA256 && snapshotIssue.title === brief.title && snapshotIssue.body === brief.body && snapshotIssue.issue_number === 8 && digest(snapshotIssue.repository) === digest({owner: 'failm3', name: 'awe-group-runtime'}), 'REPAIR_SESSION_BRIEF');
  const issue = {...snapshotIssue, digest: digest(snapshotIssue)};
  let priorDb, priorRpc, host, storeDb;
  try {
    priorDb = await createPsqlSession(resource, {role: 'qa'});
    const priorCoordinator = createCoordinator({db: priorDb, project_id: report.fixture.spec.project_id});
    const oldSnapshot = await priorCoordinator.snapshot(), oldEvents = await priorCoordinator.events();
    const inspected = inspectRepairPrior({report, witness, snapshot: oldSnapshot, events: oldEvents, report_sha256: sha(reportBytes)}), {prior, failedPublicTest} = inspected;
    need(issue.digest === inspected.artifact.issue_digest && issue.digest === report.coding_grant.issue_digest, 'REPAIR_SESSION_SAME_BRIEF');
    const f = createRepairMission({run_id, issue, prior, failedPublicTest, now: started_at});
    const plansRoot = path.join(privateRoot, 'plans'); fs.mkdirSync(plansRoot, {recursive: true});
    writeOnce(path.join(privateRoot, 'SESSION.json'), {schema: 'awe.e1.repair-session/1', run_id, started_at, source_digest, issue_digest: issue.digest, prior_result_hash: prior.result_hash, root_grant_digest: digest(f.grant)});
    writeOnce(path.join(plansRoot, 'plan_1.json'), f.plan);
    let publishedPlan = f.plan; const plans = [f.plan];
    for (const name of fs.readdirSync(plansRoot).filter(n => /^plan_[23]\.json$/.test(n)).sort()) {
      const plan = load(path.join(plansRoot, name)); need(plan.revision === publishedPlan.revision + 1 && plan.previous_digest === digest(publishedPlan), 'REPAIR_SESSION_PLAN_CHAIN');
      f.publish(plan); publishedPlan = plan; plans.push(immutable(plan));
    }
    const policy = {budget_cap_micros: '0', quota_cap: 3, max_parallel: 1, resource_limits: {local_model: 1, cpu: 1}, capabilities: Object.fromEntries(f.capabilities.map(cap => [cap.ref.capability_id, {resource_keys: [cap.executor_kind === 'llm' ? 'local_model' : 'cpu'], max_claims: 1, priority: 0}]))};
    host = await createNativeE1Host({resource, authority: f.authority, ingress: f.ingress, capabilities: f.capabilities, domainManifests: [f.domainManifest], ownerGrants: [f.grant], policy});
    await host.admitPublished(f.spec.mission_id, f.contexts.coordinator);
    const brokerCredential = host.authority.issueCredential({role: 'BROKER', principal_id: 'e1_worker', project_id: f.spec.project_id, capabilities: ['e1.head.coding', 'e1.coding.patch']});
    const productCredential = host.authority.issueCredential({role: 'WORKER', principal_id: 'e1_worker', project_id: f.spec.project_id, capabilities: ['e1.coding.product']});
    const qaCredential = host.authority.issueCredential({role: 'QA', principal_id: 'e1_qa', project_id: f.spec.project_id});
    const client = createAuthorityClient({url: host.authority.url, token: brokerCredential.token}), productClient = createAuthorityClient({url: host.authority.url, token: productCredential.token});
    const readOnly = Object.freeze({kind: priorCoordinator.kind, project_id: priorCoordinator.project_id, snapshot: priorCoordinator.snapshot, events: priorCoordinator.events, getCursor: priorCoordinator.getCursor});
    priorRpc = await createAuthorityServer({coordinator: readOnly, qaCoordinator: readOnly});
    const priorCredential = priorRpc.issueCredential({role: 'QA', principal_id: 'e1_qa', project_id: prior.project_id});
    const prior_reader = Object.freeze({url: priorRpc.url, token: priorCredential.token, project_id: prior.project_id, binding: prior});
    storeDb = await createPsqlSession(resource, {role: 'coordinator'});
    const store = createCodingRunStore({db: storeDb, project_id: f.spec.project_id});
    const binding = {schema: 'awe.e1.coding-run-binding/1', run_id, project_id: f.spec.project_id, mission_id: f.spec.mission_id, root_grant_digest: digest(f.grant), brief_digest: issue.digest, oracle_digest: 'sha256:' + ORACLE_COMMITMENT.replace(/^sha256:/, ''), source_digest, original_base_sha: prior.head_sha, deadline: f.spec.deadline, head_task_id: 'head_plan', code_task_ids: ['code_r01', 'code_r02', 'code_r03'], head_capability_id: 'e1.head.coding', code_capability_id: 'e1.coding.patch', limits: {head: 1, code: 3, total: 4}, prior_attempt_refs: [prior], product_task_id: 'product_gate', product_capability_id: 'e1.coding.product', product_output_schema_digest: f.capabilities.find(c => c.ref.capability_id === 'e1.coding.product').ref.output_schema.digest};
    const initial = await store.open(binding), counts = initial.counters;
    need(initial.binding_digest === digest(binding) && counts && ['total', 'head', 'code', 'prior', 'new_total', 'unknown', 'unregistered', 'remaining_total', 'remaining_head', 'remaining_code'].every(k => Number.isSafeInteger(counts[k]) && counts[k] >= 0) && counts.prior === 1, 'REPAIR_SESSION_NATIVE_COUNTERS');
    need(!counts.hold && counts.unknown === 0 && counts.unregistered === 0 && !counts.limit_exceeded, 'REPAIR_SESSION_NATIVE_HOLD');
    const snapshot = () => host.coordinator.snapshot();
    const getTask = async id => { need(allowedStages.has(id), 'REPAIR_SESSION_TASK_ID'); return (await snapshot()).tasks.find(t => t.mission_id === f.spec.mission_id && t.task_id === id && t.is_current) ?? null; };
    const session = {f, host, store, prior, prior_reader, qaCredential, client, productClient, issue, binding, failedPublicTest, snapshot, getTask,
      get publishedPlan() { return publishedPlan; },
      get currentPlan() { return publishedPlan; },
      get plans() { return immutable(plans); },
      async publishPlan(plan) {
        need([2, 3].includes(plan.revision), 'REPAIR_SESSION_PLAN_REVISION'); writeOnce(path.join(plansRoot, 'plan_' + plan.revision + '.json'), plan);
        if (digest(plan) !== digest(publishedPlan)) { need(plan.revision === publishedPlan.revision + 1 && plan.previous_digest === digest(publishedPlan), 'REPAIR_SESSION_PLAN_CHAIN'); f.publish(plan); publishedPlan = plan; plans.push(immutable(plan)); }
        await host.admitPublished(f.spec.mission_id, f.contexts.coordinator); return immutable(plan);
      },
      async claimOrResume(task_id) {
        need(allowedStages.has(task_id), 'REPAIR_SESSION_TASK_ID'); let state = await snapshot(), task = state.tasks.find(t => t.mission_id === f.spec.mission_id && t.task_id === task_id && t.is_current);
        need(task, 'REPAIR_SESSION_TASK_MISSING');
        if (task.state === 'READY') {
          const selectedClient = task_id === 'product_gate' ? productClient : client;
          const claim = await selectedClient.claim({mission_id: f.spec.mission_id, task_id, capabilities: [task.capability_id], lease_ms: 300000}); need(claim.status === 'CLAIMED' && claim.task_id === task_id, 'REPAIR_SESSION_CLAIM_DENIED');
          state = await snapshot(); task = state.tasks.find(t => t.mission_id === f.spec.mission_id && t.task_id === task_id && t.is_current);
        }
        need(['RUNNING', 'WAIT_QA', 'ACCEPTED', 'FAILED'].includes(task.state) && task.producer_id === 'e1_worker' && task.project_id === f.spec.project_id && task.plan_digest === digest(publishedPlan), 'REPAIR_SESSION_STALE_TASK');
        if (task.state === 'RUNNING') {
          const lease = state.leases.find(l => l.mission_id === f.spec.mission_id && l.task_id === task_id);
          need(lease && !lease.held && lease.worker_id === task.producer_id && String(lease.fence) === String(task.fence) && Date.parse(lease.expires_at) > Date.now() && Date.parse(lease.execution_deadline) > Date.now() && Date.parse(task.deadline) > Date.now(), 'REPAIR_SESSION_EXPIRED_LEASE_STOP');
        }
        return immutable({mission_id: f.spec.mission_id, task_id, worker_id: task.producer_id, fence: task.fence, ...modelRequestIds(f.spec.mission_id, task_id)});
      },
      async prepareRound({task_id, base_sha}) { return prepareRepairRound({task_id, base_sha, privateRoot, prior, report, issue, readPreviousTask: async id => (await snapshot()).tasks.find(t => t.mission_id === f.spec.mission_id && t.task_id === id)}); },
      createRoundAuthority({task_id, scope, base_sha, command_digest}) {
        need(['code_r02', 'code_r03'].includes(task_id) && task_id === scope.task_id, 'REPAIR_SESSION_CODE_TASK');
        const hostPolicy = {schema: 'awe.e1.coding-host-policy/1', repository: issue.repository, issue_digest: issue.digest, base_sha, path_allowlist: ['normalizer.py', 'cli.py'], read_allowlist: ['normalizer.py', 'cli.py'], test_profile_digest: PROGRAM_PROFILE_DIGEST, owner_grant_digest: digest(f.grant), model_capability_id: 'e1.coding.patch'};
        const authority = createCodingGrantAuthority({authority: f.authority, spec: f.spec, ownerGrant: f.grant, policy: hostPolicy, verifyNativeClaim: async ({grant, principal}) => {
          const s = await snapshot(), t = s.tasks.find(t => t.mission_id === f.spec.mission_id && t.task_id === task_id && t.is_current);
          if (!(principal.project_id === f.spec.project_id && grant.project_id === f.spec.project_id && t?.producer_id === scope.worker_id && String(t.fence) === String(scope.fence) && t.plan_digest === digest(publishedPlan) && ['RUNNING', 'WAIT_QA', 'ACCEPTED', 'FAILED'].includes(t.state))) return false;
          if (t.state === 'RUNNING') { const l = s.leases.find(l => l.mission_id === scope.mission_id && l.task_id === task_id); return Boolean(l && !l.held && l.worker_id === scope.worker_id && String(l.fence) === String(scope.fence) && Date.parse(l.expires_at) > Date.now() && Date.parse(l.execution_deadline) > Date.now()); }
          return true;
        }});
        const grant = {contract_version: CODING_CONTRACT_VERSION_V2, grant_id: 'coding_' + run_id + '_' + task_id, owner_id: f.spec.owner_id, project_id: f.spec.project_id, mission_id: f.spec.mission_id, task_id, producer_id: 'e1_worker', repository: issue.repository, issue_number: issue.issue_number, issue_digest: issue.digest, base_sha, branch_prefix: 'codex/', path_allowlist: hostPolicy.path_allowlist, read_allowlist: hostPolicy.read_allowlist, test_profile_digest: PROGRAM_PROFILE_DIGEST, model_capability: {capability_id: 'e1.coding.patch', version: '1.0.0', route_id: MODEL_POLICY.route_id, output_schema_digest: PATCH_PROPOSAL_SCHEMA_DIGEST}, test_capabilities: [{capability_id: 'e1.coding.public-tests', version: '1.0.0', command_digest, timeout_ms: 20000}], budget: {currency: 'NONE', amount_micros: 0}, issued_at: started_at, expires_at: f.spec.deadline, max_steps: 16, max_model_attempts: 1, max_patch_bytes: 32768, max_files: 2, permissions: [...CODING_PERMISSIONS]};
        return {authority, grant: immutable(grant), grant_ref: authority.issue(grant, f.contexts.owner), hostPolicy};
      },
      async close() { await Promise.allSettled([host.close(), priorRpc.close(), priorDb.close(), storeDb.close()]); }
    };
    return Object.freeze(session);
  } catch (error) {
    await Promise.allSettled([host?.close(), priorRpc?.close(), priorDb?.close(), storeDb?.close()]); throw error;
  }
}

/** Only synthetic local Git materialization. Candidate source is copied from
 * already committed AWE bytes, never repaired or authored by this helper. */
export async function prepareRepairRound({task_id, base_sha, privateRoot, prior, report, issue, readPreviousTask}) {
  need(['code_r02', 'code_r03'].includes(task_id) && /^[a-f0-9]{40}$/.test(base_sha), 'REPAIR_ROUND_SCOPE');
  const first = task_id === 'code_r02', sourceRoot = first ? path.join(runtimeRoot, '.private', 'coding-' + report.run_id, 'repository') : path.join(privateRoot, 'rounds', 'code_r02', 'repository');
  if (first) need(base_sha === prior.head_sha, 'REPAIR_ROUND_ORIGINAL_BASE');
  else { const previous = await readPreviousTask('code_r02'); need(previous?.state === 'FAILED' && previous.result_hash === digest(previous.result) && previous.result.evidence.coding_artifact.head_sha === base_sha, 'REPAIR_ROUND_PREVIOUS_FAILURE'); }
  const roundRoot = path.join(privateRoot, 'rounds', task_id), repositoryRoot = path.join(roundRoot, 'repository'), worktreesRoot = path.join(roundRoot, 'worktrees'), journalRoot = path.join(roundRoot, 'git-journal');
  fs.mkdirSync(roundRoot, {recursive: true}); const hooks = path.join(roundRoot, 'empty-hooks'); fs.mkdirSync(hooks, {recursive: true}); need(fs.readdirSync(hooks).length === 0, 'REPAIR_ROUND_HOOKS');
  const config = path.join(roundRoot, 'empty-git-config'); if (!fs.existsSync(config)) fs.writeFileSync(config, '', {flag: 'wx'}); need(safeFile(config).length === 0, 'REPAIR_ROUND_GIT_CONFIG');
  const env = Object.fromEntries(['SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP'].filter(k => process.env[k]).map(k => [k, process.env[k]]));
  Object.assign(env, {GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: config, GIT_NO_REPLACE_OBJECTS: '1', GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0'});
  const git = (args, cwd, binary = false) => execFileSync('git', ['-c', 'core.hooksPath=' + hooks, '-c', 'core.fsmonitor=false', '-c', 'core.autocrlf=false', '-c', 'commit.gpgSign=false', '-c', 'protocol.allow=never', '-c', 'init.templateDir=' + hooks, ...args], {cwd, env, encoding: binary ? null : 'utf8', windowsHide: true, timeout: 15000, maxBuffer: 1048576, stdio: ['ignore', 'pipe', 'pipe']});
  need(fs.lstatSync(sourceRoot).isDirectory() && !fs.lstatSync(sourceRoot).isSymbolicLink() && fs.realpathSync(sourceRoot).toLowerCase() === path.resolve(sourceRoot).toLowerCase() && fs.lstatSync(path.join(sourceRoot, '.git')).isDirectory() && !fs.lstatSync(path.join(sourceRoot, '.git')).isSymbolicLink() && !fs.existsSync(path.join(sourceRoot, '.git/objects/info/alternates')), 'REPAIR_ROUND_SOURCE');
  const sourceMain = git(['rev-parse', 'HEAD'], sourceRoot).trim();
  need(git(['symbolic-ref', '--short', 'HEAD'], sourceRoot).trim() === 'main' && git(['remote'], sourceRoot).trim() === '' && git(['status', '--porcelain'], sourceRoot).trim() === '', 'REPAIR_ROUND_SOURCE_CLEAN');
  need(git(['rev-parse', '--verify', '--end-of-options', base_sha + '^{commit}'], sourceRoot).trim() === base_sha, 'REPAIR_ROUND_BASE_EXISTS');
  const paths = git(['ls-tree', '-r', '--name-only', base_sha], sourceRoot).trim().split(/\r?\n/).sort(); need(digest(paths) === digest(['cli.py', 'normalizer.py']), 'REPAIR_ROUND_EXACT_TREE');
  writeOnce(path.join(roundRoot, 'ROUND.json'), {schema: 'awe.e1.repair-round/1', task_id, base_sha, source_main_sha: sourceMain, original_base_sha: prior.head_sha});
  if (!fs.existsSync(repositoryRoot)) {
    // The only transport exception is this verified canonical local source.
    // Global protocol.allow=never still denies every network transport.
    git(['-c', 'protocol.file.allow=always', 'clone', '--no-hardlinks', '--no-checkout', '--no-tags', '--', sourceRoot, repositoryRoot], roundRoot);
  }
  need(fs.lstatSync(path.join(repositoryRoot, '.git')).isDirectory(), 'REPAIR_ROUND_PARTIAL_CLONE');
  const remotes = git(['remote'], repositoryRoot).trim();
  if (remotes === 'origin') { need(git(['remote', 'get-url', 'origin'], repositoryRoot).trim().replaceAll('\\', '/').toLowerCase() === sourceRoot.replaceAll('\\', '/').toLowerCase(), 'REPAIR_ROUND_REMOTE_SOURCE'); git(['remote', 'remove', 'origin'], repositoryRoot); }
  else need(remotes === '', 'REPAIR_ROUND_REMOTE_DENIED');
  if (git(['rev-parse', 'HEAD'], repositoryRoot).trim() !== base_sha || git(['symbolic-ref', '--short', 'HEAD'], repositoryRoot).trim() !== 'main') git(['checkout', '-B', 'main', base_sha], repositoryRoot);
  need(git(['status', '--porcelain'], repositoryRoot).trim() === '' && git(['rev-parse', 'HEAD'], repositoryRoot).trim() === base_sha && git(['remote'], repositoryRoot).trim() === '', 'REPAIR_ROUND_BASE_READBACK');
  for (const file of ['cli.py', 'normalizer.py']) need(fs.lstatSync(path.join(repositoryRoot, file)).nlink === 1 && fs.readFileSync(path.join(repositoryRoot, file)).equals(git(['show', base_sha + ':' + file], repositoryRoot, true)), 'REPAIR_ROUND_BYTES');
  need(git(['rev-parse', 'HEAD'], sourceRoot).trim() === sourceMain && git(['status', '--porcelain'], sourceRoot).trim() === '', 'REPAIR_ROUND_ORIGINAL_CHANGED');
  const gitPort = createGitPort({repositoryRoot, worktreesRoot, journalRoot, repository: issue.repository, allowedPaths: ['normalizer.py', 'cli.py'], hostProtectedRoots: CODING_HOST_PROTECTED_ROOTS});
  return {gitPort, roundRoot, repositoryRoot, worktreesRoot, journalRoot, base_sha, tree_sha: git(['rev-parse', 'HEAD^{tree}'], repositoryRoot).trim()};
}
