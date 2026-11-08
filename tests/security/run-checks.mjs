// Offline orchestration only. Child tests use the unchanged D-01 regression guard.
import {mkdirSync, writeFileSync, readFileSync, readdirSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {join} from 'node:path';
import assert from 'node:assert/strict';
import {BASE_SHA, BASE_MANIFEST_SHA, root, sha256, owned, inventory} from './check-package.mjs';

const started = new Date().toISOString();
const runId = 'run-' + started.replaceAll(/[:.]/g, '-') + '-' + process.pid;
const out = join(root, 'tests', 'security', 'evidence', runId);
mkdirSync(out, {recursive: true});
const env = {AWE_OFFLINE: '1', TZ: 'UTC', LANG: 'C', NO_COLOR: '1'};
for (const key of ['SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP']) if (process.env[key]) env[key] = process.env[key];
const records = [];
function command(id, executable, args) {
  const result = spawnSync(executable, args, {cwd: root, env, encoding: 'utf8', timeout: 60000,
    maxBuffer: 8 * 1024 * 1024, windowsHide: true});
  const stdout = result.stdout ?? '', stderr = result.stderr ?? '';
  writeFileSync(join(out, id + '.stdout.txt'), stdout); writeFileSync(join(out, id + '.stderr.txt'), stderr);
  const record = {id, executable, argv: args, cwd: root, exit_status: result.status,
    signal: result.signal, error: result.error?.message ?? null,
    stdout: {path: id + '.stdout.txt', sha256: sha256(Buffer.from(stdout))},
    stderr: {path: id + '.stderr.txt', sha256: sha256(Buffer.from(stderr))}};
  records.push(record); return {record, stdout};
}
const guard = ['--require', './baseline/offline-guard.cjs'];
const node = (id, args) => command(id, process.execPath, [...guard, ...args]);
const summary = stdout => Object.fromEntries([...stdout.matchAll(/^# (tests|pass|fail|cancelled|skipped|todo) (\d+)$/gm)]
  .map(m => [m[1], Number(m[2])]));
const head = command('git-head', 'git', ['rev-parse', 'HEAD']);
// User-required baseline gate applies to every evidence rerun too.
assert.equal(head.stdout.trim(), BASE_SHA, 'Wrong source HEAD: stop before tests');
const gitStatus = command('git-status', 'git', ['status', '--porcelain', '--untracked-files=all']);
const branch = command('git-branch', 'git', ['branch', '--show-current']);
command('git-diff-check', 'git', ['diff', '--check']);
const startingInventory = inventory().filter(e => owned(e.path));
const packageCheck = node('package-check', ['tests/security/check-package.mjs']);
const contracts = node('contracts-tests', ['--test', '--test-isolation=none', '--test-concurrency=1', '--test-reporter=tap',
  ...readdirSync(join(root, 'tests/contracts')).filter(n => n.endsWith('.test.mjs')).sort().map(n => 'tests/contracts/' + n)]);
const security = node('security-tests', ['--test', '--test-isolation=none', '--test-concurrency=1', '--test-reporter=tap',
  ...readdirSync(join(root, 'tests/security')).filter(n => n.endsWith('.test.mjs')).sort().map(n => 'tests/security/' + n)]);
const first = node('security-fixtures-first', ['tests/security/fixture-results.mjs']);
const repeat = node('security-fixtures-repeat', ['tests/security/fixture-results.mjs']);
const d01First = node('d01-fixtures-first', ['baseline/fixture-results.mjs']);
const d01Repeat = node('d01-fixtures-repeat', ['baseline/fixture-results.mjs']);
node('sandbox-design', ['awe/sandbox/inspect-plan.mjs']);
const beforeInventory = inventory().filter(e => owned(e.path));
const sourceStable = JSON.stringify(startingInventory) === JSON.stringify(beforeInventory);
writeFileSync(join(out, 'source-inventory.json'), JSON.stringify(beforeInventory, null, 2) + '\n');
const matrix = JSON.parse(readFileSync(join(root, 'tests/security/coverage-matrix.json')));
const fixtureRows = first.stdout.trim().split('\n').filter(Boolean).map(s => JSON.parse(s));
const caseSet = new Set(fixtureRows.map(r => r.id));
const mapping = matrix.mapping.map(row => ({...row, status:
  row.cases.every(id => caseSet.has(id)) && row.test_prefixes.every(p => security.stdout.includes('# Subtest: ' + p)) ? 'PASS_OFFLINE_SUBSET' : 'FAIL'}));
writeFileSync(join(out, 'coverage-results.json'), JSON.stringify({mapping, not_run: matrix.not_run}, null, 2) + '\n');
const contractSummary = summary(contracts.stdout), securitySummary = summary(security.stdout);
const changedPaths = gitStatus.stdout.trimEnd().split('\n').filter(Boolean).map(line => line.slice(3).replace(/^"|"$/g, ''));
const scopeOk = changedPaths.every(owned);
const deterministic = first.stdout === repeat.stdout && d01First.stdout === d01Repeat.stdout;
const ok = records.every(r => r.exit_status === 0 && r.error === null) && scopeOk && deterministic && sourceStable &&
  packageCheck.stdout.includes('"status":"PASS"') && mapping.every(r => r.status === 'PASS_OFFLINE_SUBSET') &&
  fixtureRows.length === 33 && fixtureRows.every(r => r.result === 'PASS') &&
  [contractSummary, securitySummary].every(s => s.tests > 0 && s.pass === s.tests && s.fail === 0 && s.skipped === 0);
const receipt = {run_id: runId, status: ok ? 'PASS_OFFLINE_SUBSET' : 'FAIL', started_at: started,
  finished_at: new Date().toISOString(), scope: 'D-02 E0/E1 SIMULATED; local self-run, not independent infrastructure acceptance',
  source: {head: head.stdout.trim(), branch: branch.stdout.trim(), initial_required_sha: BASE_SHA,
    baseline_manifest_sha256: BASE_MANIFEST_SHA, d01_frozen_bytes_unchanged: packageCheck.record.exit_status === 0,
    d02_ownership_only: scopeOk, d02_source_stable_during_run: sourceStable,
    source_inventory_sha256: sha256(readFileSync(join(out, 'source-inventory.json')))},
  environment: {node: process.version, platform: process.platform, arch: process.arch,
    node_executable_sha256: sha256(readFileSync(process.execPath)), sanitized_environment_keys: Object.keys(env).sort(),
    synthetic_clock: '2026-11-05T12:00:00.000Z', random_seed: 'NONE_DETERMINISTIC_FIXTURES',
    guard_sha256: sha256(readFileSync(join(root, 'baseline/offline-guard.cjs'))),
    guard_scope: 'JS network/process regression guard only; not OS egress enforcement'},
  commands: records, contracts_summary: contractSummary, security_summary: securitySummary,
  negative_fixture_count: fixtureRows.length, deterministic_fixture_bytes: deterministic,
  future_infrastructure_probes: '10 NOT_RUN', not_run: matrix.not_run};
writeFileSync(join(out, 'run-receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
const hashes = readdirSync(out).sort().map(name => sha256(readFileSync(join(out, name))) + '  ' + name).join('\n') + '\n';
writeFileSync(join(out, 'EVIDENCE.sha256'), hashes);
// Independently re-read the saved bytes and verify this run's checksum list.
for (const line of hashes.trim().split('\n')) {
  const [expected, name] = line.split('  '); assert.equal(sha256(readFileSync(join(out, name))), expected);
}
console.log(JSON.stringify({status: receipt.status, contracts: contractSummary, security: securitySummary,
  negative_fixtures: fixtureRows.length, deterministic, evidence: out,
  receipt_sha256: sha256(readFileSync(join(out, 'run-receipt.json')))}));
if (!ok) process.exitCode = 1;
