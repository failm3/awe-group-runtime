import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync, spawnSync} from 'node:child_process';
import {digest, validateBoundValue} from '../../contracts/index.mjs';
import {MODEL_POLICY} from '../../broker/index.mjs';
import {CODING_CONTRACT_VERSION, CODING_PERMISSIONS, PATCH_PROPOSAL_SCHEMA, PATCH_PROPOSAL_SCHEMA_DIGEST, byteDigest, validateCodingTaskGrant, validatePatchProposal, createCodingExecutor, safeRepositoryPath} from '../../executors/coding/index.mjs';
import {createOfflineCodingExecutorForTests} from '../../executors/coding/executor.mjs';

const BEFORE = 'export function numericSorted(values) { return [...values].sort(); }\n';
const AFTER = 'export function numericSorted(values) { return [...values].sort((a, b) => a - b); }\n';
const clone = value => structuredClone(value);
const NOW = '2026-11-08T00:00:00.000Z';
const TEST_CAP = {capability_id: 'code.numeric.regression', version: '1.0.0', command_digest: digest({program: 'node', args: ['test.mjs']}), timeout_ms: 10000};
function grant(base_sha = 'a'.repeat(40)) { return {contract_version: CODING_CONTRACT_VERSION, grant_id: 'coding_synthetic', owner_id: 'owner', project_id: 'project_code', mission_id: 'mission_code', task_id: 'coding_task', producer_id: 'coding_worker', repository: {owner: 'synthetic-owner', name: 'synthetic-maintenance'}, issue_number: 1, base_sha, branch_prefix: 'codex/', path_allowlist: ['src/numeric.mjs'], model_capability: {capability_id: 'e1.coding.patch', version: '1.0.0', route_id: MODEL_POLICY.route_id, output_schema_digest: PATCH_PROPOSAL_SCHEMA_DIGEST}, test_capabilities: [TEST_CAP], budget: {currency: 'NONE', amount_micros: 0}, issued_at: NOW, expires_at: '2026-11-09T00:00:00.000Z', max_steps: 12, max_model_attempts: 1, max_patch_bytes: 4096, max_files: 1, permissions: [...CODING_PERMISSIONS]}; }
function baseline(base_sha = 'a'.repeat(40)) { return {base_sha, files: [{path: 'src/numeric.mjs', kind: 'file', mode: '100644', content_utf8: BEFORE, digest: byteDigest(BEFORE), ancestry_verified: true, ancestor_symlinks: false}]}; }
function proposal(base_sha = 'a'.repeat(40)) { return {base_sha, summary: 'Fix numerical ordering while preserving input', changes: [{path: 'src/numeric.mjs', before_digest: byteDigest(BEFORE), after_text: AFTER}]}; }
const scope = {mission_id: 'mission_code', task_id: 'coding_task', worker_id: 'coding_worker', attempt_id: 'coding_attempt', logical_request_id: 'coding_request', fence: 1};

function localGitFixture(t, options = {}) {
  const tempParent = path.resolve(os.tmpdir()), root = fs.mkdtempSync(path.join(tempParent, 'awe-e1-coding-unit-'));
  assert.ok(path.resolve(root).startsWith(tempParent + path.sep) && path.basename(root).startsWith('awe-e1-coding-unit-'));
  t.after(() => { const checked = path.resolve(root); assert.ok(checked.startsWith(tempParent + path.sep) && path.basename(checked).startsWith('awe-e1-coding-unit-')); fs.rmSync(checked, {recursive: true, force: true}); });
  const repositoryPath = path.join(root, 'repo'), worktreePath = path.join(root, 'worktree'); fs.mkdirSync(repositoryPath);
  const env = {SystemRoot: process.env.SystemRoot, PATH: process.env.PATH, TEMP: os.tmpdir(), TMP: os.tmpdir(), GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: path.join(root, 'empty-git-config')}; fs.writeFileSync(env.GIT_CONFIG_GLOBAL, '');
  const git = (args, cwd = repositoryPath) => execFileSync('git', ['-c', 'user.name=AWE Synthetic Fixture', '-c', 'user.email=fixture@localhost.invalid', ...args], {cwd, env, windowsHide: true, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe']}).trim();
  git(['init', '--initial-branch=main']); fs.mkdirSync(path.join(repositoryPath, 'src')); fs.writeFileSync(path.join(repositoryPath, 'src/numeric.mjs'), BEFORE);
  fs.writeFileSync(path.join(repositoryPath, 'test.mjs'), "import assert from 'node:assert/strict'; import {numericSorted} from './src/numeric.mjs'; const a=[10,2,-1]; assert.deepEqual(numericSorted(a),[-1,2,10]); assert.deepEqual(a,[10,2,-1]); assert.deepEqual(numericSorted([]),[]);\n");
  git(['add', '--', 'src/numeric.mjs', 'test.mjs']); git(['commit', '-m', 'Synthetic failing numerical-sort fixture']);
  if (options.symlinkBase) {
    // A native Git symlink tree entry does not require Windows symlink privileges.
    fs.writeFileSync(path.join(root, 'symlink-target.txt'), 'outside.mjs');
    const blob = git(['hash-object', '-w', path.join(root, 'symlink-target.txt')]);
    git(['update-index', '--cacheinfo', '120000,' + blob + ',src/numeric.mjs']);
    git(['commit', '-m', 'Synthetic native Git symlink entry']);
  }
  const base = git(['rev-parse', 'HEAD']), taskGrant = grant(base), events = [], publisherCalls = [];
  const context = Object.freeze({unit: true}), grantRef = 'synthetic-owner-grant'; let revoked = false;
  const runTest = cwd => spawnSync(process.execPath, ['test.mjs'], {cwd, env: {SystemRoot: process.env.SystemRoot, TEMP: os.tmpdir(), TMP: os.tmpdir()}, windowsHide: true, timeout: 10000, encoding: 'utf8'});
  assert.notEqual(runTest(repositoryPath).status, 0, 'The base fixture must actually fail before the patch.');
  const sameRepository = repository => assert.deepEqual(repository, taskGrant.repository);
  const ancestrySafe = relative => { const parts = relative.split('/'); for (let i = 1; i < parts.length; i++) { const p = path.join(worktreePath, ...parts.slice(0, i)); if (fs.existsSync(p) && fs.lstatSync(p).isSymbolicLink()) return false; } return true; };
  const ports = {
    clock: () => NOW,
    authority: {kind: 'OWNER_TASK_GRANT_AUTHORITY', async resolve(ref, actor) { return ref === grantRef && actor === context && !revoked ? taskGrant : null; }},
    githubReader: {kind: 'SCOPED_GITHUB_ISSUE_READER', mode: 'OFFLINE_TEST_DOUBLE', async readIssue(request) { events.push('issue'); sameRepository(request.repository); const value = {repository: taskGrant.repository, issue_number: 1, title: 'Synthetic numeric sort maintenance', body: 'Sort negative and multi-digit values numerically while preserving input.'}; return {...value, digest: digest(value)}; }},
    modelPort: {kind: 'ACCOUNTED_PATCH_MODEL_PORT', mode: 'OFFLINE_TEST_DOUBLE', capability_id: 'e1.coding.patch', route_id: MODEL_POLICY.route_id, async proposePatch(request) { events.push('model'); assert.equal(request.max_attempts, 1); const value = {proposal: proposal(base), accounting_status: 'CONFIRMED', wire_attempts: 1, route_id: MODEL_POLICY.route_id, attempt_id: scope.attempt_id, actual_cost_micros: 0, usage: {input_tokens: 1, output_tokens: 1}, model: {id: MODEL_POLICY.model, digest: MODEL_POLICY.digest}, evidence_level: 'OFFLINE_TEST_DOUBLE'}; if (options.qaSeededBug) value.proposal.changes[0].after_text = 'export function numericSorted(values) { return [...values].sort((a, b) => Math.trunc(a) - Math.trunc(b)); }\n'; if (options.model) options.model(value); return value; }},
    gitPort: {kind: 'ISOLATED_GIT_WORKTREE_PORT', mode: 'OFFLINE_TEST_DOUBLE', isolation: 'ISOLATED_WORKTREE',
      async inspectBase(request) { events.push('inspect'); sameRepository(request.repository); assert.equal(git(['rev-parse', request.base_sha + '^{commit}']), base); return {base_sha: base, files: request.paths.map(relative => { const entry = git(['ls-tree', base, '--', relative]); const mode = entry.split(' ')[0]; const content = git(['show', base + ':' + relative]) + (mode === '120000' ? '' : '\n'); return {path: relative, kind: mode === '120000' ? 'symlink' : 'file', mode, content_utf8: content, digest: byteDigest(content), ancestry_verified: true, ancestor_symlinks: false}; })}; },
      async createWorktree(request) { events.push('worktree'); git(['worktree', 'add', '-b', request.branch, worktreePath, request.base_sha]); return {isolated: true, base_sha: base, branch: request.branch, worktree_id: 'synthetic-worktree'}; },
      async applyPatch(request) { events.push('apply'); for (const change of request.patch.changes) { const target = path.resolve(worktreePath, change.path); assert.ok(target.startsWith(path.resolve(worktreePath) + path.sep)); assert.equal(ancestrySafe(change.path), true); fs.writeFileSync(target, change.after_text); } git(['add', '--', ...request.patch.changes.map(x => x.path)], worktreePath); git(['commit', '-m', 'Apply bounded synthetic maintenance patch'], worktreePath); return {patch_digest: request.patch.patch_digest}; },
      async readback() { events.push('readback'); const paths = git(['diff', '--name-only', base, 'HEAD'], worktreePath).split(/\r?\n/).filter(Boolean); return {isolated: true, base_sha: base, head_sha: git(['rev-parse', 'HEAD'], worktreePath), committed: true, clean: git(['status', '--porcelain'], worktreePath) === '', files: paths.map(relative => ({path: relative, digest: byteDigest(fs.readFileSync(path.join(worktreePath, relative), 'utf8')), kind: fs.lstatSync(path.join(worktreePath, relative)).isSymbolicLink() ? 'symlink' : 'file', ancestor_symlinks: !ancestrySafe(relative)}))}; }
    },
    // This runner is a labelled synthetic unit double. It demonstrates fixed argv
    // and fail-before/pass-after, NOT a proved Windows/WSL security sandbox.
    testRunner: {kind: 'FIXED_SANDBOX_TEST_RUNNER', mode: 'OFFLINE_TEST_DOUBLE', isolation: 'ALLOWLISTED_OS_SANDBOX', network: 'DENY', async run(request) { events.push('tests'); assert.deepEqual(request.capability, TEST_CAP); const result = runTest(worktreePath); return {capability_id: TEST_CAP.capability_id, command_digest: TEST_CAP.command_digest, sandbox_enforced: true, network: 'DENY', exit_code: result.status ?? 1, output_digest: byteDigest((result.stdout ?? '') + (result.stderr ?? '')), timeout_ms: 10000}; }},
    qaPort: {kind: 'INDEPENDENT_FROZEN_ARTIFACT_QA', mode: 'OFFLINE_TEST_DOUBLE', principal_id: 'independent_qa', rubric_digest: digest({numeric_order: true, decimal_order: true, preserves_input: true, frozen_patch: true}), async evaluate({artifact}) {
      events.push('qa'); assert.ok(Object.isFrozen(artifact.patch.changes));
      const {artifact_digest, accepted, ...payload} = artifact;
      // Separate fixed holdout is not supplied to the producer/model prompt.
      const qa = spawnSync(process.execPath, ['--input-type=module', '-e', "import assert from 'node:assert/strict'; import {numericSorted} from './src/numeric.mjs'; const a=[1.9,1.1]; assert.deepEqual(numericSorted(a),[1.1,1.9]); assert.deepEqual(a,[1.9,1.1]);"], {cwd: worktreePath, env: {SystemRoot: process.env.SystemRoot, TEMP: os.tmpdir(), TMP: os.tmpdir()}, windowsHide: true, timeout: 10000, encoding: 'utf8'});
      return {artifact_digest, rubric_digest: artifact.rubric_digest, evaluator_id: 'independent_qa', producer_id: 'coding_worker', verdict: qa.status === 0 && accepted === false && digest(payload) === artifact_digest ? 'PASS' : 'FAIL', accepted: false};
    }},
    publisher: {kind: 'SCOPED_DRAFT_PR_INTENT_PUBLISHER', mode: 'OFFLINE_TEST_DOUBLE', async prepareDraftIntent(request) { events.push('intent'); publisherCalls.push(request); assert.equal(request.intent.automatic_merge, false); assert.equal(request.intent.production_release, false); return {status: 'DRAFT_PR_INTENT', intent_digest: request.intent_digest, external_mutations: 0}; }}
  };
  return {root, repositoryPath, worktreePath, taskGrant, ports, git, events, publisherCalls, grantRef, context, revoke() { revoked = true; }, executor: () => createOfflineCodingExecutorForTests(ports, {label: 'OFFLINE_TEST_DOUBLE'}), request: {grant_ref: grantRef, context, attempt_scope: scope}};
}

test('coding schema is compatible with frozen A1 bounded schemas and validates a compact patch', () => {
  const value = proposal(); assert.equal(validateBoundValue(PATCH_PROPOSAL_SCHEMA, value).base_sha, value.base_sha);
  assert.equal(validateCodingTaskGrant(grant(), {now: NOW}).budget.amount_micros, 0);
});
test('exact repository paths reject traversal, ADS, URL encoding, Windows aliases and protected core', () => {
  for (const relative of ['../outside.mjs', '/absolute.mjs', 'src\\outside.mjs', 'C:/x.mjs', 'src/a:ads', 'src/%2e%2e/a', 'src/CON.txt', 'src/nul', 'src/a.', '.git/config', '.github/workflows/run.yml', 'E1/contracts/index.mjs', 'E1/coordinator/a.sql', '.env', 'AGENTS.md']) {
    const value = grant(); value.path_allowlist = [relative]; assert.throws(() => validateCodingTaskGrant(value, {now: NOW}), relative);
  }
  assert.equal(safeRepositoryPath('src/numeric.mjs'), 'src/numeric.mjs');
});
test('grant rejects paid route, missing permissions, non-codex branches, arbitrary tests and unbounded steps', () => {
  for (const change of [x => { x.budget = {currency: 'USD', amount_micros: 1}; }, x => { x.permissions.pop(); }, x => { x.branch_prefix = 'main/'; }, x => { x.test_capabilities[0].command = 'arbitrary shell'; }, x => { x.max_steps = 1000; }, x => { x.expires_at = NOW; }, x => { x.model_capability.route_id = 'cloud'; }]) { const value = clone(grant()); change(value); assert.throws(() => validateCodingTaskGrant(value, {now: NOW})); }
});
test('patch denies base/digest/path/size/symlink substitution and protected metadata', () => {
  for (const change of [x => { x.base_sha = 'b'.repeat(40); }, x => { x.changes[0].path = 'src/not-allowed.mjs'; }, x => { x.changes[0].before_digest = 'sha256:' + '0'.repeat(64); }, x => { x.changes[0].after_text = 'x'.repeat(4097); }, x => { x.accepted = true; }, x => { x.changes[0].command = 'shell'; }]) { const value = proposal(); change(value); assert.throws(() => validatePatchProposal(value, {grant: grant(), baseline: baseline()})); }
  for (const change of [x => { x.files[0].kind = 'symlink'; x.files[0].mode = '120000'; }, x => { x.files[0].ancestor_symlinks = true; }, x => { x.files[0].ancestry_verified = false; }]) { const value = baseline(); change(value); assert.throws(() => validatePatchProposal(proposal(), {grant: grant(), baseline: value})); }
});
test('missing owner authority or actual issue grant yields WAIT with no execution', async () => {
  assert.equal((await createCodingExecutor({}).run({})).decision, 'WAIT');
  const executor = createCodingExecutor({authority: {kind: 'OWNER_TASK_GRANT_AUTHORITY', resolve: async () => null}});
  assert.equal((await executor.run({grant_ref: 'unapproved', context: {}})).reason, 'CODING_OWNER_TASK_GRANT_MISSING');
});
test('actual temporary Git fixture is red before, green after, isolated and prepares only a draft intent', async t => {
  const f = localGitFixture(t), result = await f.executor().run(f.request);
  assert.equal(result.decision, 'DRAFT_PR_INTENT'); assert.equal(result.profile, 'OFFLINE_TEST_DOUBLE'); assert.equal(result.accepted, false); assert.equal(result.self_development_verified, false); assert.equal(result.external_mutations, 0);
  assert.equal(fs.readFileSync(path.join(f.repositoryPath, 'src/numeric.mjs'), 'utf8'), BEFORE); assert.equal(fs.readFileSync(path.join(f.worktreePath, 'src/numeric.mjs'), 'utf8'), AFTER);
  assert.notEqual(result.artifact.head_sha, f.taskGrant.base_sha); assert.equal(f.git(['remote', '-v']), ''); assert.equal(f.publisherCalls.length, 1);
  assert.deepEqual(f.events, ['issue', 'inspect', 'model', 'worktree', 'apply', 'readback', 'tests', 'qa', 'intent']);
});
test('unaccounted model receipt blocks before creating a worktree', async t => {
  const f = localGitFixture(t, {model: value => { value.accounting_status = 'UNCONFIRMED'; }}), result = await f.executor().run(f.request);
  assert.equal(result.reason, 'CODING_ACCOUNTED_MODEL_RECEIPT_REQUIRED'); assert.equal(f.events.includes('worktree'), false); assert.equal(f.publisherCalls.length, 0);
});
test('missing scoped publisher or safe runner waits before issue/model/worktree', async t => {
  const f = localGitFixture(t); delete f.ports.publisher;
  const result = await f.executor().run(f.request); assert.equal(result.decision, 'WAIT'); assert.equal(result.reason, 'CODING_REQUIRED_PORT_MISSING:publisher'); assert.equal(f.events.length, 0);
});
test('independent QA holdout catches a seeded decimal bug missed by fixed integer tests', async t => {
  const f = localGitFixture(t, {qaSeededBug: true}), result = await f.executor().run(f.request);
  assert.equal(result.decision, 'REPAIR'); assert.equal(result.reason, 'CODING_INDEPENDENT_QA_REJECTED'); assert.equal(f.publisherCalls.length, 0); assert.equal(result.artifact.accepted, false);
  assert.ok(result.artifact.tests.every(x => x.exit_code === 0));
});
test('failed regression never reaches QA or publisher', async t => {
  const f = localGitFixture(t, {model: value => { value.proposal.changes[0].after_text = 'export function numericSorted(values) { return values; }\n'; }}), result = await f.executor().run(f.request);
  assert.equal(result.decision, 'REPAIR'); assert.equal(result.reason, 'CODING_FIXED_TEST_FAILED'); assert.equal(f.events.includes('qa'), false); assert.equal(f.publisherCalls.length, 0);
});
test('production factory refuses explicitly offline ports without pretending live evidence', async t => {
  const f = localGitFixture(t), result = await createCodingExecutor(f.ports).run(f.request);
  assert.equal(result.decision, 'BLOCK'); assert.equal(result.reason, 'CODING_PORT_PROFILE_MISMATCH'); assert.equal(f.events.length, 0);
});
test('native Git symlink tree entry is rejected before model/worktree creation', async t => {
  const f = localGitFixture(t, {symlinkBase: true}), result = await f.executor().run(f.request);
  assert.equal(result.reason, 'CODING_SYMLINK_OR_BASELINE_DENIED'); assert.deepEqual(f.events, ['issue', 'inspect']); assert.equal(f.publisherCalls.length, 0);
});
test('owner revocation after model response blocks the first worktree mutation', async t => {
  let f; f = localGitFixture(t, {model: () => f.revoke()}); const result = await f.executor().run(f.request);
  assert.equal(result.reason, 'CODING_GRANT_CHANGED_OR_REVOKED'); assert.equal(f.events.includes('worktree'), false); assert.equal(f.publisherCalls.length, 0);
});
test('fixed test timeout must fit the remaining grant before the runner is called', async t => {
  const f = localGitFixture(t); let current = NOW; f.ports.clock = () => current;
  const readback = f.ports.gitPort.readback;
  f.ports.gitPort.readback = async request => { const value = await readback(request); current = new Date(Date.parse(f.taskGrant.expires_at) - 5000).toISOString(); return value; };
  const result = await f.executor().run(f.request);
  assert.equal(result.reason, 'CODING_TEST_DEADLINE'); assert.equal(f.events.includes('tests'), false); assert.equal(f.publisherCalls.length, 0);
});
