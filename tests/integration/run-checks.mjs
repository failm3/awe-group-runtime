// Parent orchestrator runs fixed local commands only. All test/demo children use D01's unchanged guard.
import {mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {join} from 'node:path';
import {root, sha, inventory, BASE, manifestPath} from './package.mjs';

const started = new Date().toISOString(), runId = 'run-' + started.replaceAll(/[:.]/g, '-') + '-' + process.pid;
const out = join(root, 'tests/integration/evidence', runId); mkdirSync(out, {recursive: true});
const env = {AWE_OFFLINE: '1', TZ: 'UTC', LANG: 'C', NO_COLOR: '1', GIT_OPTIONAL_LOCKS: '0'};
for (const key of ['SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP']) if (process.env[key]) env[key] = process.env[key];
const records = [], guard = ['--require', './baseline/offline-guard.cjs'];
function command(id, executable, argv) {
  const r = spawnSync(executable, argv, {cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: 60000, maxBuffer: 16 * 1024 * 1024});
  const stdout = r.stdout ?? '', stderr = r.stderr ?? '';
  writeFileSync(join(out, id + '.stdout.txt'), stdout); writeFileSync(join(out, id + '.stderr.txt'), stderr);
  records.push({id, executable, argv, cwd: root, exit_status: r.status, signal: r.signal,
    error: r.error?.message ?? null, stdout_sha256: sha(Buffer.from(stdout)), stderr_sha256: sha(Buffer.from(stderr))});
  return stdout;
}
const node = (id, argv) => command(id, process.execPath, [...guard, ...argv]);
const archiveMode = process.argv.includes('--archive');
if (archiveMode && existsSync(join(root, '.git'))) throw Error('ARCHIVE_MODE_REQUIRES_NO_GIT_METADATA');
const head = archiveMode ? BASE : command('git-head', 'git', ['rev-parse', 'HEAD']).trim();
if (head !== BASE) { console.error('STOP: wrong HEAD', head); process.exit(1); }
if (!archiveMode) {
  const branch = command('git-branch', 'git', ['branch', '--show-current']).trim();
  if (branch !== 'codex/awe-e0-integration') { console.error('STOP: wrong branch', branch); process.exit(1); }
  command('git-status', 'git', ['status', '--porcelain=v1', '--untracked-files=all']);
  command('git-diff-check', 'git', ['diff', '--check']);
}
const before = inventory();
node('package-check', ['tests/integration/package.mjs']);
const testArgs = ['--test', '--test-isolation=none', '--test-concurrency=1', '--test-reporter=tap'];
const suites = {}, files = [];
const summary = text => Object.fromEntries([...text.matchAll(/^# (tests|pass|fail|cancelled|skipped|todo) (\d+)$/gm)].map(m => [m[1], +m[2]]));
for (const name of ['contracts', 'security', 'state', 'integration']) {
  const tests = readdirSync(join(root, 'tests', name)).filter(n => n.endsWith('.test.mjs')).sort().map(n => 'tests/' + name + '/' + n);
  files.push(...tests); suites[name] = summary(node(name + '-tests', [...testArgs, ...tests]));
}
const combined = summary(node('combined-tests', [...testArgs, ...files]));
const determinism = {};
for (const [id, path] of [['d01-fixtures', 'baseline/fixture-results.mjs'], ['d02-fixtures', 'tests/security/fixture-results.mjs'],
  ['d03-demo', 'tests/state/demo.mjs'], ['joint-demo', 'tests/integration/demo.mjs']]) {
  const first = node(id + '-first', [path]), repeat = node(id + '-repeat', [path]);
  determinism[id] = {byte_equal: first === repeat, stdout_sha256: sha(Buffer.from(first))};
}
node('sandbox-design', ['awe/sandbox/inspect-plan.mjs']);
const stable = JSON.stringify(before) === JSON.stringify(inventory());
writeFileSync(join(out, 'source-inventory.json'), JSON.stringify(before, null, 2) + '\n');
const goodSummary = s => s.tests > 0 && s.tests === s.pass && s.fail === 0 && s.cancelled === 0 && s.skipped === 0 && s.todo === 0;
const ok = records.every(r => r.exit_status === 0 && r.error === null) && stable
  && [...Object.values(suites), combined].every(goodSummary) && Object.values(determinism).every(v => v.byte_equal)
  && combined.tests === Object.values(suites).reduce((sum, s) => sum + s.tests, 0);
const receipt = {run_id: runId, status: ok ? 'PASS_E0_LOCAL' : 'FAIL', started_at: started, finished_at: new Date().toISOString(),
  base_sha: head, head_verification: archiveMode ? 'ARCHIVE_MANIFEST_ONLY_NO_GIT' : 'LIVE_GIT_HEAD_AND_BRANCH',
  production_ready: false, independent_acceptance: false,
  environment: {node: process.version, executable: process.execPath, executable_sha256: sha(readFileSync(process.execPath)),
    platform: process.platform, arch: process.arch, environment_keys: Object.keys(env).sort(), synthetic_clock: '2026-11-05T12:00:00.000Z',
    guard_sha256: sha(readFileSync(join(root, 'baseline/offline-guard.cjs'))), guard_is_os_sandbox: false},
  source_manifest_sha256: existsSync(join(root, manifestPath)) ? sha(readFileSync(join(root, manifestPath))) : null,
  source_stable_during_run: stable,
  suites, combined, determinism, commands: records,
  not_run: ['PG/durable transaction', 'VM/OS/egress', 'real issuer/auth', 'physical tools/providers', 'independent QA', 'remote CI', 'D04-D07']};
writeFileSync(join(out, 'run-receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
const hashes = readdirSync(out).sort().map(n => sha(readFileSync(join(out, n))) + '  ' + n).join('\n') + '\n';
writeFileSync(join(out, 'EVIDENCE.sha256'), hashes);
for (const line of hashes.trim().split('\n')) { const [expected, name] = line.split('  '); if (sha(readFileSync(join(out, name))) !== expected) throw Error('EVIDENCE_DRIFT'); }
console.log(JSON.stringify({status: receipt.status, suites, combined, determinism, evidence: out,
  receipt_sha256: sha(readFileSync(join(out, 'run-receipt.json')))}));
if (!ok) process.exitCode = 1;
