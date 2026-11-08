import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {execFileSync, fork} from 'node:child_process';
import {digest, immutable, need} from '../../contracts/index.mjs';
import {validateResourceDescriptor} from '../../coordinator/resource.mjs';
import {createNativeE1Host} from '../staging.mjs';
import {createAuthorityClient} from '../../coordinator/authority-server.mjs';
import {createLocalModelBroker, MODEL_POLICY} from '../../broker/index.mjs';
import {modelRequestIds} from '../artifact-binding.mjs';
import {createCodingExecutor} from '../../executors/coding/executor.mjs';
import {CODING_CONTRACT_VERSION_V2, CODING_PERMISSIONS, PATCH_PROPOSAL_SCHEMA_DIGEST} from '../../executors/coding/contracts.mjs';
import {createCodingMission} from './mission.mjs';
import {CODING_HOST_PROTECTED_ROOTS} from './policy.mjs';
import {createCodingGrantAuthority} from './grant-authority.mjs';
import {createIssueReader} from './issue-reader.mjs';
import {createGitPort} from './git-port.mjs';
import {createAccountedPatchModelPort} from './model-port.mjs';
import {createCodingCoordinatorBinding} from './coordinator-binding.mjs';
import {createLocalDraftIntentPublisher} from './publisher-intent.mjs';
import {runProgram, programRunnerSourcePins} from '../program-runner/runner.mjs';
import {PROGRAM_PROFILE_DIGEST} from '../program-runner/profiles.mjs';
import {BRIEF_SHA256, ORACLE_COMMITMENT} from '../../qa-coding/commitments.mjs';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const hash = b => createHash('sha256').update(b).digest('hex');
const env = Object.fromEntries(['SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP'].filter(k => process.env[k]).map(k => [k, process.env[k]]));
function load(p) { const st = fs.lstatSync(p); need(st.isFile() && !st.isSymbolicLink() && st.nlink === 1 && st.size <= 65536, 'G1_CONFIG_FILE'); return JSON.parse(fs.readFileSync(p, 'utf8')); }
function save(p, value) { fs.mkdirSync(path.dirname(p), {recursive: true}); const t = p + '.tmp'; fs.writeFileSync(t, JSON.stringify(value, null, 2) + '\n', {mode: 0o600}); fs.renameSync(t, p); }
export function codingSourcePins() {
  const files = [];
  for (const area of ['E1/host/coding', 'E1/host/program-runner', 'E1/qa-coding', 'E1/executors/coding']) {
    function walk(dir) { for (const entry of fs.readdirSync(path.join(root, dir), {withFileTypes: true})) { const p = dir + '/' + entry.name; if (entry.isDirectory() && entry.name !== 'evidence' && !entry.name.startsWith('.')) walk(p); else if (entry.isFile() && /\.(mjs|py|json)$/.test(p)) files.push({path: p, sha256: hash(fs.readFileSync(path.join(root, p)))}); } }
    walk(area);
  }
  return files.sort((a, b) => a.path.localeCompare(b.path, 'en'));
}
function leaf(message, timeout = 180000) {
  return new Promise((resolve, reject) => {
    const child = fork(new URL('../../qa-coding/leaf.mjs', import.meta.url), [], {cwd: root, env, stdio: ['ignore', 'ignore', 'pipe', 'ipc'], windowsHide: true});
    let outcome; const timer = setTimeout(() => { child.kill(); reject(Error('G1_QA_TIMEOUT')); }, timeout);
    child.stderr.on('data', () => {});
    child.on('message', m => { if (m.type === 'QA_READY') return; outcome = m; child.disconnect(); });
    child.once('error', () => { clearTimeout(timer); reject(Error('G1_QA_SPAWN')); });
    child.once('exit', code => { clearTimeout(timer); if (code !== 0 || outcome?.type !== 'EVALUATED') reject(Object.assign(Error(outcome?.code ?? 'G1_QA_FAILED'), {check: outcome?.check})); else resolve(outcome); });
    child.send(message);
  });
}

/** Explicit bounded G1 only. The baseline is intentionally incomplete. Every
 * candidate byte comes from actual A3 generation; no source repair is here. */
export async function runCodingPilot({run_id, resourcePath, issueSnapshotPath}) {
  need(/^[a-z][a-z0-9_]{0,39}$/.test(run_id), 'G1_RUN_ID');
  const now = new Date().toISOString(), privateRoot = path.join(root, '.private', 'coding-' + run_id);
  need(!fs.existsSync(privateRoot), 'G1_RUN_ALREADY_EXISTS_NO_RETRY');
  fs.mkdirSync(privateRoot, {recursive: true, mode: 0o700});
  const checkpoint = path.join(privateRoot, 'CHECKPOINT.json'), source_pins = codingSourcePins();
  save(checkpoint, {status: 'INITIALIZING', run_id, started_at: now, source_pins, model_wire_limit: 1, used_model_wires: 0});
  const lock = path.join(root, '.private', 'CODING-MODEL-LOCK.json');
  fs.writeFileSync(lock, JSON.stringify({run_id, pid: process.pid, at: now}), {flag: 'wx', mode: 0o600});
  let host, f, scope, qaResult, outcome;
  const record = value => save(checkpoint, {...load(checkpoint), ...value, updated_at: new Date().toISOString()});
  try {
    const resource = validateResourceDescriptor(load(resourcePath)), snapshot = load(issueSnapshotPath);
    const publicFile = path.join(root, 'E1/qa-coding/public-brief.json');
    need(hash(fs.readFileSync(publicFile)) === BRIEF_SHA256, 'G1_BRIEF_SOURCE_PIN');
    const brief = load(publicFile);
    need(snapshot.issue_number === 8 && snapshot.title === brief.title && snapshot.body === brief.body && snapshot.repository.owner === 'failm3' && snapshot.repository.name === 'awe-group-runtime', 'G1_APPROVED_BRIEF');
    const issue = {...snapshot, digest: digest(snapshot)};
    const rubric = {checks: ['schema', 'sources', 'scope'], brief_sha256: BRIEF_SHA256, oracle_commitment: ORACLE_COMMITMENT, test_profile_digest: PROGRAM_PROFILE_DIGEST};
    f = createCodingMission({run_id, issue, rubric, now});
    const repositoryRoot = path.join(privateRoot, 'repository'); fs.mkdirSync(repositoryRoot);
    const git = args => execFileSync('git', ['-c', 'core.autocrlf=false', '-c', 'core.hooksPath=NUL', '-c', 'commit.gpgSign=false', '-c', 'user.name=AWE Synthetic Baseline', '-c', 'user.email=fixture@localhost.invalid', ...args], {cwd: repositoryRoot, env: {...env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: 'NUL', GIT_TERMINAL_PROMPT: '0'}, encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']}).trim();
    git(['init', '-b', 'main']);
    fs.writeFileSync(path.join(repositoryRoot, 'normalizer.py'), 'def normalize_event(value):\n    return None\n');
    fs.writeFileSync(path.join(repositoryRoot, 'cli.py'), 'import normalizer\nraise NotImplementedError("G1 incomplete baseline")\n');
    git(['add', '--', 'normalizer.py', 'cli.py']); git(['commit', '-m', 'Incomplete synthetic G1 baseline; not a solution']);
    const base_sha = git(['rev-parse', 'HEAD']);
    const gitPort = createGitPort({repositoryRoot, worktreesRoot: path.join(privateRoot, 'worktrees'), journalRoot: path.join(privateRoot, 'git-journal'), repository: issue.repository, allowedPaths: ['normalizer.py', 'cli.py'], hostProtectedRoots: CODING_HOST_PROTECTED_ROOTS});
    const policy = {budget_cap_micros: '0', quota_cap: 1, max_parallel: 1, resource_limits: {local_model: 1}, capabilities: {'e1.coding.patch': {resource_keys: ['local_model'], max_claims: 1, priority: 0}}};
    host = await createNativeE1Host({resource, authority: f.authority, ingress: f.ingress, capabilities: f.capabilities, domainManifests: [f.domainManifest], ownerGrants: [f.grant], policy});
    await host.admitPublished(f.spec.mission_id, f.contexts.coordinator);
    const brokerCredential = host.authority.issueCredential({role: 'BROKER', principal_id: 'e1_worker', project_id: f.spec.project_id, capabilities: ['e1.coding.patch']});
    const qaCredential = host.authority.issueCredential({role: 'QA', principal_id: 'e1_qa', project_id: f.spec.project_id});
    const client = createAuthorityClient({url: host.authority.url, token: brokerCredential.token});
    const claim = await client.claim({mission_id: f.spec.mission_id, task_id: 'code_r01', capabilities: ['e1.coding.patch'], lease_ms: 300000});
    need(claim.status === 'CLAIMED', 'G1_NATIVE_CLAIM');
    scope = {mission_id: claim.mission_id, task_id: claim.task_id, worker_id: claim.worker_id, fence: claim.fence, ...modelRequestIds(claim.mission_id, claim.task_id)};
    const currentTask = async () => (await host.coordinator.snapshot()).tasks.find(t => t.mission_id === scope.mission_id && t.task_id === scope.task_id && t.is_current);
    const hostPolicy = {schema: 'awe.e1.coding-host-policy/1', repository: issue.repository, issue_digest: issue.digest, base_sha, path_allowlist: ['normalizer.py', 'cli.py'], read_allowlist: ['normalizer.py', 'cli.py'], test_profile_digest: PROGRAM_PROFILE_DIGEST, owner_grant_digest: digest(f.grant), model_capability_id: 'e1.coding.patch'};
    const authority = createCodingGrantAuthority({authority: f.authority, spec: f.spec, ownerGrant: f.grant, policy: hostPolicy, verifyNativeClaim: async ({grant, principal}) => {
      const s = await host.coordinator.snapshot(), t = s.tasks.find(t => t.mission_id === grant.mission_id && t.task_id === grant.task_id && t.is_current);
      if (!(principal.project_id === f.spec.project_id && grant.project_id === f.spec.project_id && t?.project_id === f.spec.project_id && t.producer_id === scope.worker_id && String(t.fence) === String(scope.fence) && t.plan_digest === digest(f.plan) && ['RUNNING', 'WAIT_QA', 'ACCEPTED'].includes(t.state))) return false;
      if (t.state === 'RUNNING') { const lease = s.leases.find(l => l.mission_id === scope.mission_id && l.task_id === scope.task_id && String(l.fence) === String(scope.fence)); if (!lease || lease.worker_id !== scope.worker_id || Date.parse(lease.expires_at) <= Date.now()) return false; }
      return true;
    }});
    const command_digest = digest({profile_digest: PROGRAM_PROFILE_DIGEST, command: ['python3', '-B', '-S', 'cli.py'], test_id: 'public-example-01'});
    const grant = {contract_version: CODING_CONTRACT_VERSION_V2, grant_id: 'coding_' + run_id, owner_id: f.spec.owner_id, project_id: f.spec.project_id, mission_id: f.spec.mission_id, task_id: 'code_r01', producer_id: 'e1_worker', repository: issue.repository, issue_number: issue.issue_number, issue_digest: issue.digest, base_sha, branch_prefix: 'codex/', path_allowlist: hostPolicy.path_allowlist, read_allowlist: hostPolicy.read_allowlist, test_profile_digest: PROGRAM_PROFILE_DIGEST, model_capability: {capability_id: 'e1.coding.patch', version: '1.0.0', route_id: MODEL_POLICY.route_id, output_schema_digest: PATCH_PROPOSAL_SCHEMA_DIGEST}, test_capabilities: [{capability_id: 'e1.coding.public-tests', version: '1.0.0', command_digest, timeout_ms: 20000}], budget: {currency: 'NONE', amount_micros: 0}, issued_at: now, expires_at: f.spec.deadline, max_steps: 16, max_model_attempts: 1, max_patch_bytes: 32768, max_files: 2, permissions: [...CODING_PERMISSIONS]};
    const grant_ref = authority.issue(grant, f.contexts.owner);
    const broker = createLocalModelBroker({accounting: client, registry: f.registry, timeoutMs: 120000, contextTokens: 8192, maxOutputTokens: 2048});
    const modelPort = createAccountedPatchModelPort({broker, spec: f.spec, grant: f.grant, verifyNativeAttempt: async ({scope: expected}) => (await host.coordinator.snapshot()).attempts.find(a => a.attempt_id === expected.attempt_id)});
    const coordinatorBinding = createCodingCoordinatorBinding({client, scope, verifyNativeTask: currentTask});
    const testRunner = {kind: 'FIXED_SANDBOX_TEST_RUNNER', mode: 'LIVE_SCOPED_HOST', isolation: 'ALLOWLISTED_OS_SANDBOX', network: 'DENY', async run({worktree_id, capability, expected_head_sha, expected_tree_sha, profile_digest, invocation_id}) {
      need(capability.command_digest === command_digest && profile_digest === PROGRAM_PROFILE_DIGEST, 'G1_FIXED_TEST_SCOPE');
      const w = gitPort.resolveWorktree(worktree_id); need(w.head_sha === expected_head_sha && w.tree_sha === expected_tree_sha, 'G1_TEST_TREE');
      const receipt = await runProgram({files: w.files.map(({path, content_utf8}) => ({path, content_utf8})), stdin: '{"id":" Z9 ","kind":" Open ","n":4}\n', entrypoint: 'cli.py', binding: {tested_head_sha: w.head_sha, tested_tree_sha: w.tree_sha, invocation_id}});
      let passed = receipt.exit_code === 0 && !receipt.timed_out && !receipt.output_truncated && receipt.stderr === '';
      try { passed = passed && digest(JSON.parse(receipt.stdout)) === digest({id: 'Z9', kind: 'open'}); } catch { passed = false; }
      return immutable({...receipt, capability_id: capability.capability_id, command_digest, exit_code: passed ? 0 : 1, output_digest: digest({receipt: receipt.receipt_digest, passed}), timeout_ms: capability.timeout_ms, program_receipt: receipt});
    }};
    const qaPort = {kind: 'INDEPENDENT_FROZEN_ARTIFACT_QA', mode: 'LIVE_SCOPED_HOST', principal_id: 'e1_qa', rubric_digest: digest(rubric), async evaluate({artifact}) {
      const completion = coordinatorBinding.completion; need(completion, 'G1_NATIVE_COMPLETION_FIRST');
      const w = gitPort.resolveWorktree(outcome?.worktree_id ?? artifact.worktree_id ?? (await findWorktree()));
      qaResult = await leaf({url: host.authority.url, token: qaCredential.token, binding: {mission_id: f.spec.mission_id, task_id: 'code_r01', plan_digest: digest(f.plan), result_hash: completion.result_hash}, git: {repository_root: repositoryRoot, worktree_root: w.root}, rubric});
      return qaResult.qa;
    }};
    async function findWorktree() { const entries = fs.readdirSync(path.join(privateRoot, 'git-journal')).filter(n => /^wt_[a-f0-9]{32}\.json$/.test(n)); need(entries.length === 1, 'G1_ONE_WORKTREE'); return load(path.join(privateRoot, 'git-journal', entries[0])).worktree_id; }
    record({status: 'READY_FOR_ONE_MODEL_ATTEMPT', mission_id: f.spec.mission_id, project_id: f.spec.project_id, resource_id: resource.resource_id, scope, issue_digest: issue.digest, brief_sha256: BRIEF_SHA256, oracle_commitment: ORACLE_COMMITMENT, base_sha, coding_grant: grant, host_policy: hostPolicy, fixture: {spec: f.spec, grant: f.grant, plan: f.plan, rubric}, repository_root: repositoryRoot});
    const executor = createCodingExecutor({authority, githubReader: createIssueReader({snapshot, expectedDigest: issue.digest}), modelPort, gitPort, testRunner, qaPort, publisher: createLocalDraftIntentPublisher({directory: path.join(privateRoot, 'intents')}), hostProtectedRoots: CODING_HOST_PROTECTED_ROOTS, lifecycle: {persistArtifact: args => coordinatorBinding.complete(args), recordOutcome: value => { save(path.join(privateRoot, 'executor-outcome.json'), value); record({executor_outcome_ref: 'executor-outcome.json', decision: value.decision, reason: value.reason}); }}});
    // Mark this host attempt as consumed BEFORE invoking the executor. There is
    // no code path that reopens this directory or sends a second wire.
    record({status: 'EXECUTING_ONE_SHOT', used_model_wires: 1});
    outcome = await executor.run({grant_ref, context: f.contexts.executor, attempt_scope: scope});
    const state = await host.coordinator.snapshot();
    const report = {schema: 'awe.e1.g1-report/1', status: outcome.decision === 'DRAFT_PR_INTENT' && qaResult?.qa.verdict === 'PASS' ? 'PASS_LIVE_MULTI_FILE_G1' : outcome.decision === 'HOLD' ? 'HOLD' : 'BLOCKED_OR_REPAIR', run_id, started_at: now, finished_at: new Date().toISOString(), source_pins, source_pin_digest: digest(source_pins), issue, input_origin: 'SOL_AUTHENTICATED_GITHUB_SNAPSHOT', brief_sha256: BRIEF_SHA256, oracle_commitment: ORACLE_COMMITMENT, fixture: {spec: f.spec, grant: f.grant, plan: f.plan, rubric}, coding_grant: grant, outcome, native_task: state.tasks.find(t => t.mission_id === f.spec.mission_id && t.task_id === 'code_r01' && t.is_current), native_attempts: state.attempts.filter(a => a.mission_id === f.spec.mission_id), ledger: {spent: state.project.spent, reserved: state.project.reserved, quota_used: state.project.quota_used}, qa: qaResult ?? null, runner_source_pins: programRunnerSourcePins(), api_actual_cost_micros: 0, paid_generations: 0, external_effects: 0, sol_candidate_edits: 0, adaptive_repair: 'NOT_TESTED', dynamic_agents: 'NOT_TESTED', github_dispatch: 'LOCAL_INTENT_ONLY', accepted: false};
    need(digest(codingSourcePins()) === digest(source_pins), 'G1_SOURCE_CHANGED_DURING_RUN');
    save(path.join(root, 'E1/coding/evidence', run_id + '.json'), report);
    if (qaResult) save(path.join(privateRoot, 'qa-receipt.json'), qaResult);
    record({status: report.status, outcome_ref: 'executor-outcome.json', report: 'E1/coding/evidence/' + run_id + '.json', qa_ref: qaResult ? 'qa-receipt.json' : null});
    if (report.status === 'PASS_LIVE_MULTI_FILE_G1') {
      const w = gitPort.resolveWorktree(outcome.worktree_id);
      for (const file of w.files) { const target = path.join(root, 'E1/coding/artifacts', run_id, file.path); fs.mkdirSync(path.dirname(target), {recursive: true}); fs.writeFileSync(target, file.content_utf8); }
    }
    console.log(JSON.stringify({status: report.status, mission_id: f.spec.mission_id, model_attempts: report.native_attempts.length, usage: report.native_attempts.map(a => a.usage), decision: outcome.decision, reason: outcome.reason, api_actual_cost_micros: 0, evidence: 'E1/coding/evidence/' + run_id + '.json'}));
    return report;
  } catch (error) {
    record({status: 'BLOCKED_BEFORE_OR_DURING_G1', reason: error.code ?? error.message, check: error.check ?? null});
    console.error(JSON.stringify({status: 'BLOCKED_BEFORE_OR_DURING_G1', reason: error.code ?? error.message, check: error.check ?? null, run_id, paid_generations: 0}));
    throw error;
  } finally {
    if (host) await host.close().catch(() => {});
    if (fs.existsSync(lock) && load(lock).pid === process.pid) fs.unlinkSync(lock);
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  need(process.argv[2] === '--authorized-local-g1' && process.argv.length === 4, 'G1_EXPLICIT_COMMAND');
  runCodingPilot(load(process.argv[3])).catch(() => { process.exitCode = 1; });
}
