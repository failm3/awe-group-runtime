import fs from 'node:fs';
import path from 'node:path';
import {fork} from 'node:child_process';
import {digest, immutable, need} from '../../contracts/index.mjs';
import {RUNTIME_ROOT, readHostJson, writeHostJson, repairSourcePins} from '../mission-runner.mjs';
import {openRepairSession} from './repair-session.mjs';
import {createLocalModelBroker} from '../../broker/index.mjs';
import {MODEL_POLICY} from '../../broker/schemas.mjs';
import {createCodingExecutor} from '../../executors/coding/executor.mjs';
import {createIssueReader} from './issue-reader.mjs';
import {CODING_HOST_PROTECTED_ROOTS} from './policy.mjs';
import {createRepairPatchModelPort} from './repair-context.mjs';
import {createLocalDraftIntentPublisher} from './publisher-intent.mjs';
import {createRecoverableModelPort, createRecoverableTestRunner, createStableInvocationIdFactory, createRecoverableCoordinatorBinding} from './recovery.mjs';
import {runProgram} from '../program-runner/runner.mjs';
import {PROGRAM_PROFILE_DIGEST} from '../program-runner/profiles.mjs';
import {ORACLE_COMMITMENT} from '../../qa-coding/commitments.mjs';
import {REPAIR_HEAD_SCHEMA_DIGEST, REPAIR_PRODUCT_SCHEMA_DIGEST, validateRepairHead} from './repair-contracts.mjs';

const PUBLIC_INPUT = '{"id":" Z9 ","kind":" Open ","n":4}\n';
const command_digest = digest({profile_digest: PROGRAM_PROFILE_DIGEST, command: ['python3', '-B', '-S', 'cli.py'], test_id: 'public-example-01'});
const env = Object.fromEntries(['SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP'].filter(k => process.env[k]).map(k => [k, process.env[k]]));
const nativeRefs = ({task_id, attempt_id, logical_request_id, worker_id, fence}) => ({task_id, attempt_id, logical_request_id, worker_id, fence: String(fence)});

export function createPhaseAccounting(client, {store, run_id, scope, kind}) {
  scope = immutable(scope);
  const scoped = request => {
    need(['mission_id', 'task_id', 'attempt_id', 'logical_request_id', 'worker_id', 'fence'].every(k => String(request[k]) === String(scope[k])), 'REPAIR_ACCOUNTING_SCOPE');
  };
  const gate = async request => {
    scoped(request);
    const row = await store.read(run_id), refs = row.state.refs;
    need(row.phase === (kind === 'HEAD' ? 'HEAD_PENDING' : 'CODE_PENDING') && !row.counters.hold && row.counters.total <= 4 &&
      refs.task_id === scope.task_id && refs.attempt_id === scope.attempt_id && refs.worker_id === scope.worker_id && String(refs.fence) === String(scope.fence), 'REPAIR_NATIVE_PHASE_REQUIRED');
  };
  return Object.freeze({async reserve(request) { request = immutable(request); await gate(request); need(request.route_id === MODEL_POLICY.route_id && request.capability_id === (kind === 'HEAD' ? 'e1.head.coding' : 'e1.coding.patch') && request.reserve_micros === 0 && request.quota_units === 1, 'REPAIR_ACCOUNTING_ROUTE'); return client.reserve(request); }, async markSending(request) { request = immutable(request); await gate(request); return client.markSending(request); },
    settle: request => { scoped(request); return client.settle(request); }, unknown: request => { scoped(request); return client.unknown(request); }, failBeforeSend: request => { scoped(request); return client.failBeforeSend(request); }});
}

async function qaChild(session, task_id, round) {
  const task = await session.getTask(task_id);
  need(task?.result_hash && ['WAIT_QA', 'ACCEPTED', 'FAILED'].includes(task.state), 'REPAIR_QA_STAGE');
  const message = {url: session.host.authority.url, token: session.qaCredential.token, prior_reader: session.prior_reader,
    binding: {mission_id: task.mission_id, task_id, plan_digest: task.plan_digest, result_hash: task.result_hash},
    outerrow: await session.store.read(session.binding.run_id),
    ...(round ? {git: {repository_root: round.repositoryRoot, worktree_root: round.gitPort.resolveWorktree(findWorktree(round)).root}} : {})};
  return new Promise((resolve, reject) => {
    const child = fork(new URL('../../qa-repair/leaf.mjs', import.meta.url), [], {cwd: RUNTIME_ROOT, env, stdio: ['ignore', 'ignore', 'pipe', 'ipc'], windowsHide: true});
    let result; const timer = setTimeout(() => { child.kill(); reject(Error('REPAIR_QA_TIMEOUT')); }, 180000);
    child.stderr.on('data', () => {});
    child.on('message', value => { if (value.type === 'QA_READY') return; result = value; child.disconnect(); });
    child.once('error', () => { clearTimeout(timer); reject(Error('REPAIR_QA_SPAWN')); });
    child.once('exit', code => { clearTimeout(timer); if (code !== 0 || result?.type !== 'EVALUATED') reject(Object.assign(Error(result?.code ?? 'REPAIR_QA_REJECT'), {check: result?.check})); else resolve(result); });
    child.send(message);
  });
}
function findWorktree(round) {
  const list = fs.readdirSync(round.journalRoot).filter(x => /^wt_[a-f0-9]{32}\.json$/.test(x));
  need(list.length === 1, 'REPAIR_SINGLE_CANDIDATE_WORKTREE'); return readHostJson(path.join(round.journalRoot, list[0])).worktree_id;
}
function acceptedHead(snapshot, mission_id) {
  const candidates = [...snapshot.tasks, ...(snapshot.task_history ?? []).map(x => x.body)].filter(t => t.mission_id === mission_id && t.task_id === 'head_plan' && t.state === 'ACCEPTED' && t.result_hash === digest(t.result));
  need(candidates.length > 0 && new Set(candidates.map(x => x.result_hash)).size === 1, 'REPAIR_ACCEPTED_HEAD_REQUIRED');
  return candidates[0];
}
function publicFailure(task) {
  const test = task?.result?.evidence?.coding_artifact?.tests?.find(x => x.exit_code !== 0);
  if (test) return {exit_code: test.program_receipt?.exit_code ?? test.exit_code, stderr: test.program_receipt?.stderr ?? '', stdout: test.program_receipt?.stdout ?? ''};
  return {reason: 'INDEPENDENT_PRODUCT_QA_REJECTED', failed_result_hash: task.result_hash};
}

export async function runRepairDriver(config, {fault}) {
  const session = await openRepairSession(config), {f, store} = session;
  const phaseFile = path.join(config.privateRoot, 'DRIVER.json');
  let lastRound, lastOutcome, completion;
  const checkpoint = value => writeHostJson(phaseFile, {...(fs.existsSync(phaseFile) ? readHostJson(phaseFile) : {}), ...value, at: new Date().toISOString()});
  async function advance(phase, decision, refs = {}) {
    const row = await store.read(config.run_id);
    if (row.phase === phase) return row;
    need(!row.counters.hold && !['HOLD', 'BLOCKED', 'STOPPED'].includes(row.phase), 'REPAIR_OUTER_STOP');
    return store.advance({run_id: config.run_id, expected_revision: Number(row.revision), operation_id: 'op_' + row.revision + '_' + phase.toLowerCase(), transition: {phase, decision, refs: {...row.state.refs, ...refs}}});
  }
  async function finishHead() {
    let row = await store.read(config.run_id);
    if (!['NEW', 'HEAD_PENDING'].includes(row.phase)) return;
    const scope = await session.claimOrResume('head_plan');
    if (row.phase === 'NEW') row = await advance('HEAD_PENDING', 'CLAIMED_HEAD', {...nativeRefs(scope), plan_digest: digest(session.currentPlan)});
    let task = await session.getTask('head_plan');
    if (task.state === 'RUNNING') {
      const file = path.join(config.privateRoot, 'HEAD-RESPONSE.json'), intent = path.join(config.privateRoot, 'HEAD-INTENT.json');
      let response;
      const state = await session.snapshot(), prior = state.attempts.find(a => a.attempt_id === scope.attempt_id);
      if (fs.existsSync(file)) {
        const cache = readHostJson(file); need(cache.scope_digest === digest(scope) && prior?.state === 'CONFIRMED' && cache.response.request_hash === prior.request_hash, 'REPAIR_HEAD_CACHE_BINDING'); response = cache.response;
      } else {
        need(!prior && !fs.existsSync(intent), 'REPAIR_HEAD_NO_BLIND_RETRY');
        writeHostJson(intent, {scope, input_digest: digest(task.document.input)});
        const broker = createLocalModelBroker({accounting: createPhaseAccounting(session.client, {store, run_id: config.run_id, scope, kind: 'HEAD'}), registry: f.registry, contextTokens: 8192, maxOutputTokens: 512, timeoutMs: 120000});
        response = await broker.invoke({scope, spec: f.spec, grant: f.grant, capability_id: 'e1.head.coding', input: task.document.input, data_label: 'CLEAN_CODE'});
        writeHostJson(file, {scope_digest: digest(scope), response});
      }
      need(response.decision === 'PROPOSED' && response.accounting_status === 'CONFIRMED' && response.evidence_level === 'LIVE_LOCAL_MODEL', 'REPAIR_HEAD_RESPONSE_NOT_PROVEN');
      validateRepairHead(response.output);
      const attempt = (await session.snapshot()).attempts.find(a => a.attempt_id === scope.attempt_id);
      need(attempt?.state === 'CONFIRMED' && digest(attempt.usage) === digest(response.usage) && attempt.request_hash === response.request_hash, 'REPAIR_HEAD_NATIVE_PROVENANCE');
      const result = {output_schema_digest: REPAIR_HEAD_SCHEMA_DIGEST, output: response.output, artifact_digest: digest(response.output), evidence: {request_hash: response.request_hash, response_digest: response.response_digest, usage: response.usage, model_receipt: {response, native_attempt: attempt, scope, input: task.document.input}}};
      await session.client.complete({...scope, result, result_hash: digest(result)});
      task = await session.getTask('head_plan');
    }
    const qa = await qaChild(session, 'head_plan'); writeHostJson(path.join(config.privateRoot, 'HEAD-QA.json'), qa);
    need(qa.qa.verdict === 'PASS', 'REPAIR_HEAD_QA_FAIL');
    task = await session.getTask('head_plan'); validateRepairHead(task.result.output);
    need(task.result.output.decision === 'REPAIR', 'REPAIR_HEAD_DECIDED_BLOCK_SCOPE');
    await advance('HEAD_CONFIRMED', 'INDEPENDENT_HEAD_ACCEPTED', {...nativeRefs(scope), plan_digest: task.plan_digest, head_output_digest: digest(task.result.output), decision_ref: task.result_hash});
  }
  async function publishCode(task_id, revision, previous_digest, feedback) {
    const head = acceptedHead(await session.snapshot(), f.spec.mission_id);
    const plan = f.codingPlan({draft: head.result.output, revision, previous_digest, task_id, publicFailure: feedback});
    await session.publishPlan(plan);
    await advance('PLAN_READY', 'COMPILED_ACCEPTED_AWE_HEAD', {plan_digest: digest(plan), head_output_digest: digest(head.result.output)});
  }
  async function codeStage(task_id) {
    const row = await store.read(config.run_id), scope = await session.claimOrResume(task_id);
    const base_sha = task_id === 'code_r02' ? session.prior.head_sha : (await session.snapshot()).tasks.find(t => t.task_id === 'code_r02')?.result?.evidence?.coding_artifact?.head_sha;
    need(/^[a-f0-9]{40}$/.test(base_sha), 'REPAIR_NATIVE_ROUND_BASE');
    const round = lastRound = await session.prepareRound({task_id, base_sha});
    if (row.phase === 'PLAN_READY') await advance('CODE_PENDING', 'CLAIMED_CODE', {...nativeRefs(scope), plan_digest: digest(session.currentPlan), candidate_base_sha: base_sha});
    const directory = path.join(round.roundRoot, 'recovery');
    const task = await session.getTask(task_id);
    const auth = session.createRoundAuthority({task_id, scope, base_sha, command_digest});
    const broker = createLocalModelBroker({accounting: createPhaseAccounting(session.client, {store, run_id: config.run_id, scope, kind: 'CODE'}), registry: f.registry, contextTokens: 8192, maxOutputTokens: 2048, timeoutMs: 120000});
    const realModel = createRepairPatchModelPort({taskInput: task.document.input, broker, spec: f.spec, grant: f.grant, verifyNativeAttempt: async ({scope: expected}) => (await session.snapshot()).attempts.find(a => a.attempt_id === expected.attempt_id)});
    const modelPort = createRecoverableModelPort({modelPort: realModel, directory, project_id: f.spec.project_id, readNativeState: session.snapshot, onModelPersisted: metadata => fault('AFTER_MODEL_PERSISTED', metadata)});
    const request = args => {
      const w = round.gitPort.resolveWorktree(args.worktree_id);
      need(w.head_sha === args.expected_head_sha && w.tree_sha === args.expected_tree_sha && args.profile_digest === PROGRAM_PROFILE_DIGEST, 'REPAIR_TEST_SOURCE_TREE');
      return {files: w.all_files.map(({path, content_utf8}) => ({path, content_utf8})), stdin: PUBLIC_INPUT, entrypoint: 'cli.py', binding: {tested_head_sha: w.head_sha, tested_tree_sha: w.tree_sha, invocation_id: args.invocation_id}};
    };
    const realTests = {kind: 'FIXED_SANDBOX_TEST_RUNNER', mode: 'LIVE_SCOPED_HOST', isolation: 'ALLOWLISTED_OS_SANDBOX', network: 'DENY', async run(args) {
      need(args.capability.command_digest === command_digest, 'REPAIR_TEST_COMMAND');
      const receipt = await runProgram(request(args)); let passed = receipt.exit_code === 0 && !receipt.timed_out && !receipt.output_truncated && receipt.output_encoding_valid && receipt.stderr === '';
      try { passed = passed && digest(JSON.parse(receipt.stdout)) === digest({id: 'Z9', kind: 'open'}); } catch { passed = false; }
      return immutable({...receipt, capability_id: args.capability.capability_id, command_digest, exit_code: passed ? 0 : 1, output_digest: digest({receipt: receipt.receipt_digest, passed}), timeout_ms: args.capability.timeout_ms, program_receipt: receipt});
    }};
    const testRunner = createRecoverableTestRunner({testRunner: realTests, directory, scope, project_id: f.spec.project_id, readNativeState: session.snapshot, resolveTestRequest: request});
    async function advanceToQA(value) {
      const a = value.result.evidence.coding_artifact;
      let current = await store.read(config.run_id);
      const refs = {...nativeRefs(scope), plan_digest: digest(session.currentPlan), candidate_base_sha: a.base_sha, candidate_head_sha: a.head_sha, candidate_tree_sha: a.tree_sha, proposal_digest: a.patch.patch_digest, model_receipt_digest: a.model_receipt_digest, git_journal_ref: task_id + '/git-journal', artifact_digest: a.artifact_digest, qa_result_hash: value.result_hash, test_receipt_digest: digest(a.tests), tests_passed: a.tests.every(t => t.exit_code === 0)};
      if (current.phase === 'CODE_PENDING') current = await advance('CANDIDATE_READY', 'EXACT_COMMITTED_CANDIDATE', refs);
      if (current.phase === 'CANDIDATE_READY') current = await advance('TESTED', 'FIXED_PROGRAM_TESTED', refs);
      if (current.phase === 'TESTED') current = await advance('QA_PENDING', 'NATIVE_RESULT_WAIT_QA', refs);
      return current;
    }
    const binding = createRecoverableCoordinatorBinding({client: session.client, scope, directory, project_id: f.spec.project_id, readNativeState: session.snapshot,
      verifyArtifactReadback: async a => { const w = round.gitPort.resolveWorktree(findWorktree(round)); return w.head_sha === a.head_sha && w.tree_sha === a.tree_sha && a.patch.changes.every(c => w.files.some(f => f.path === c.path && f.digest === c.after_digest)); },
      onNativeCompleted: async value => { await advanceToQA(value); await fault('AFTER_NATIVE_COMPLETED', {scope, result_hash: value.result_hash, head_sha: value.result.evidence.coding_artifact.head_sha, tree_sha: value.result.evidence.coding_artifact.tree_sha}); }});
    const publisher = createLocalDraftIntentPublisher({directory: path.join(round.roundRoot, 'intents')});
    let qa;
    const qaPort = {kind: 'INDEPENDENT_FROZEN_ARTIFACT_QA', mode: 'LIVE_SCOPED_HOST', principal_id: 'e1_qa', rubric_digest: digest(f.rubric), async evaluate() { qa = await qaChild(session, task_id, round); writeHostJson(path.join(round.roundRoot, 'QA.json'), qa); return qa.qa; }};
    completion = await binding.restore();
    if (!completion) {
      const executor = createCodingExecutor({authority: auth.authority, githubReader: createIssueReader({snapshot: {repository: session.issue.repository, issue_number: session.issue.issue_number, title: session.issue.title, body: session.issue.body}, expectedDigest: session.issue.digest}), modelPort, gitPort: round.gitPort, testRunner, qaPort, publisher, hostProtectedRoots: CODING_HOST_PROTECTED_ROOTS, invocationIdFactory: createStableInvocationIdFactory({directory, scope}), lifecycle: {persistArtifact: x => binding.complete(x), recordOutcome: value => writeHostJson(path.join(round.roundRoot, 'OUTCOME.json'), value)}});
      lastOutcome = await executor.run({grant_ref: auth.grant_ref, context: f.contexts.executor, attempt_scope: scope});
      completion = binding.completion;
      need(completion, lastOutcome.reason);
    }
    await advanceToQA(completion);
    if (!qa) await qaPort.evaluate();
    if (qa.qa.verdict !== 'PASS') {
      await advance('REPAIR_READY', 'INDEPENDENT_CANDIDATE_FAILED', {qa_verdict: 'FAIL', failure_ref: completion.result_hash});
      return {passed: false, task: await session.getTask(task_id), round};
    }
    const a = completion.result.evidence.coding_artifact;
    const intent = immutable({intent_kind: 'DRAFT_PR', repository: a.repository, issue_number: a.issue_number, base_sha: a.base_sha, head_sha: a.head_sha, branch: a.branch, title: a.patch.summary.slice(0, 160), artifact_digest: a.artifact_digest, qa_digest: digest(qa.qa), grant_digest: a.grant_digest, draft: true, automatic_merge: false, production_release: false});
    await publisher.prepareDraftIntent({intent, intent_digest: digest(intent), qa: qa.qa});
    await advance('PRODUCT_PENDING', 'INDEPENDENT_CODE_ACCEPTED', {qa_verdict: 'PASS', code_task_id: task_id, code_result_hash: completion.result_hash, tests_passed: true});
    checkpoint({code_task_id: task_id, local_intent: intent, code_result_hash: completion.result_hash});
    return {passed: true, task: await session.getTask(task_id), round, intent};
  }
  async function productStage(round) {
    const row = await store.read(config.run_id), code = await session.getTask(row.state.refs.code_task_id), a = code.result.evidence.coding_artifact;
    let task = await session.getTask('product_gate');
    const scope = await session.claimOrResume('product_gate');
    if (task.state === 'READY' || task.state === 'RUNNING') {
      const output = {product_pass: true, head_sha: a.head_sha, tree_sha: a.tree_sha, code_result_hash: code.result_hash, oracle_digest: ORACLE_COMMITMENT, prior_result_hash: session.prior.result_hash};
      const result = {output_schema_digest: REPAIR_PRODUCT_SCHEMA_DIGEST, output, artifact_digest: digest(output), evidence: {code_task_id: code.task_id, code_result_hash: code.result_hash, prior_result_hash: session.prior.result_hash}};
      await session.productClient.complete({...scope, result, result_hash: digest(result)}); task = await session.getTask('product_gate');
    }
    const qa = await qaChild(session, 'product_gate', round); writeHostJson(path.join(config.privateRoot, 'PRODUCT-QA.json'), qa);
    need(qa.qa.verdict === 'PASS', 'REPAIR_FINAL_PRODUCT_QA_FAIL');
    task = await session.getTask('product_gate');
    await advance('RESULT_READY', 'INDEPENDENT_FINAL_PRODUCT_ACCEPTED', {product_pass: true, product_result_hash: task.result_hash});
  }
  try {
    await finishHead();
    let row = await store.read(config.run_id);
    if (row.phase === 'HEAD_CONFIRMED') {
      if (session.currentPlan.revision === 1) await publishCode('code_r02', 2, digest(session.currentPlan), session.failedPublicTest);
      else await advance('PLAN_READY', 'RECOVER_ADMITTED_PLAN', {plan_digest: digest(session.currentPlan)});
    }
    for (let rounds = 0; rounds < 2; rounds++) {
      row = await store.read(config.run_id);
      if (row.phase === 'RESULT_READY') break;
      if (row.phase === 'PRODUCT_PENDING') {
        const code = await session.getTask(row.state.refs.code_task_id); lastRound = await session.prepareRound({task_id: code.task_id, base_sha: code.result.evidence.coding_artifact.base_sha});
        await productStage(lastRound); break;
      }
      if (row.phase === 'REPAIR_READY') {
        const failed = await session.getTask(row.state.refs.task_id), head = acceptedHead(await session.snapshot(), f.spec.mission_id);
        need(head.result.output.max_code_attempts === 2 && failed.task_id === 'code_r02', 'REPAIR_HEAD_OR_ATTEMPT_LIMIT');
        await publishCode('code_r03', 3, digest(session.currentPlan), publicFailure(failed));
      }
      const current = session.currentPlan.tasks.find(t => t.capability.capability_id === 'e1.coding.patch'); need(current, 'REPAIR_CURRENT_CODE_PLAN');
      const value = await codeStage(current.task_id); lastRound = value.round;
      if (value.passed) { await productStage(value.round); break; }
    }
    row = await store.read(config.run_id); need(row.phase === 'RESULT_READY' && !row.counters.hold, 'REPAIR_NOT_RESULT_READY');
    const native = await session.snapshot(), supervisor = readHostJson(path.join(config.privateRoot, 'SUPERVISOR.json'));
    need(supervisor.observed_exits.length === 2 && supervisor.observed_exits.every(x => x.exit_code === 90 && x.original_process_observed_dead), 'REPAIR_AUTOMATIC_CHILD_RECOVERY_NOT_PROVEN');
    const code = await session.getTask(row.state.refs.code_task_id), w = lastRound.gitPort.resolveWorktree(findWorktree(lastRound));
    for (const file of w.all_files) { const target = path.join(RUNTIME_ROOT, 'E1/coding/artifacts', config.run_id, file.path); fs.mkdirSync(path.dirname(target), {recursive: true}); fs.writeFileSync(target, file.content_utf8); }
    const report = {schema: 'awe.e1.two-file-bounded-repair/1', status: 'TWO_FILE_BOUNDED_REPAIR_PASS', run_id: config.run_id, source_digest: config.source_digest, source_pins: config.source_pins, fixture: {spec: f.spec, grant: f.grant, plan: session.currentPlan, rubric: f.rubric}, prior: session.prior, outer: row, native, accepted_head: acceptedHead(native, f.spec.mission_id).result, final_code: code.result, final_product_qa: readHostJson(path.join(config.privateRoot, 'PRODUCT-QA.json')), local_intent: readHostJson(phaseFile).local_intent, supervised_child_faults: supervisor.observed_exits, fault_witnesses: [0, 1].map(i => readHostJson(path.join(config.privateRoot, 'FAULT-' + i + '.json'))), actual_model_wires_including_prior: row.counters.total, api_actual_cost_micros: 0, paid_generations: 0, sol_candidate_edits: 0, sol_manual_phase_commands_after_start: 0, full_three_file_G2: 'NOT_PROVEN', dynamic_agents: 'NOT_PROVEN', hostile_process_or_power_loss_recovery: 'NOT_PROVEN', original_G1: 'FAILED_ONE_SHOT_PRESERVED', accepted: false};
    need(digest(repairSourcePins()) === config.source_digest, 'REPAIR_FINAL_SOURCE_CHANGED');
    writeHostJson(path.join(RUNTIME_ROOT, 'E1/coding/evidence', 'REPAIR-' + config.run_id + '.json'), report); checkpoint({status: report.status, head_sha: w.head_sha, tree_sha: w.tree_sha});
    return {status: report.status, run_id: config.run_id, head_sha: w.head_sha, tree_sha: w.tree_sha, total_model_wires_including_prior: row.counters.total, paid_generations: 0, full_G2: 'NOT_PROVEN'};
  } catch (error) {
    const row = await store.read(config.run_id).catch(() => null);
    checkpoint({status: 'STOPPED_OR_HOLD', reason: error.code ?? error.message, check: error.check ?? null, phase: row?.phase ?? null, counters: row?.counters ?? null});
    throw error;
  } finally { await session.close(); }
}
