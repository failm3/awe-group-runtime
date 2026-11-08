// Fixed local Node tests + read-only Git introspection. The parent records evidence; every test child has
// the unchanged D-01 JS network/child-process guard. This is not an OS firewall.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdirSync, readFileSync, writeFileSync, readdirSync, lstatSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';

const root = fileURLToPath(new URL('../../', import.meta.url));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
assert.equal(process.versions.node, '24.21.0', 'D-01 pinned toolchain');
function git(args) {
  const result = spawnSync('git', args, {cwd: root, encoding: 'utf8', windowsHide: true, timeout: 10000});
  assert.equal(result.status, 0, 'Read-only git check failed');
  return result.stdout.trim();
}
const head = git(['rev-parse', 'HEAD']);
assert.equal(head, '3abee561ae97428680a4fe5826b0f40ae676319a', 'STOP: wrong starting commit');
const branch = git(['branch', '--show-current']);
assert.equal(branch, 'codex/awe-d03-offline', 'Unexpected D-03 branch');
assert.equal(git(['diff', '--check']), '');
const directory = join(root, 'tests/state/evidence/run-' + new Date().toISOString().replaceAll(':', '-').replace('.', '-'));
mkdirSync(directory, {recursive: true});
const env = {AWE_OFFLINE: '1', TZ: 'UTC'};
for (const key of ['SystemRoot', 'WINDIR', 'TEMP', 'TMP']) if (process.env[key]) env[key] = process.env[key];
const prefix = ['--require', './baseline/offline-guard.cjs'];
const results = [];
function run(name, args) {
  const argv = [...prefix, ...args];
  const result = spawnSync(process.execPath, argv, {cwd: root, env, encoding: 'utf8', timeout: 60000, maxBuffer: 8 * 1024 * 1024, windowsHide: true});
  writeFileSync(join(directory, `${name}.stdout.txt`), result.stdout ?? '');
  writeFileSync(join(directory, `${name}.stderr.txt`), (result.stderr ?? '') + (result.error ? String(result.error) : ''));
  const tap = result.stdout ?? '';
  const summary = args.includes('--test') ? Object.fromEntries(['tests','pass','fail','cancelled','skipped','todo']
    .map(key => [key, Number(tap.match(new RegExp(`^# ${key} (\\d+)$`, 'm'))?.[1] ?? -1)])) : null;
  results.push({name, executable: process.execPath, argv, cwd: root, exit_code: result.status, signal: result.signal, summary});
  return result;
}
run('boundaries', ['tests/state/verify-boundaries.mjs']);
const flags = ['--test', '--test-reporter=tap', '--test-isolation=none', '--test-concurrency=1'];
run('d01-contracts', [...flags, 'tests/contracts/*.test.mjs']);
const tests = run('d03-state', [...flags, 'tests/state/*.test.mjs']);
const first = run('demo-first', ['tests/state/demo.mjs']);
const repeat = run('demo-repeat', ['tests/state/demo.mjs']);
const deterministic = first.status === 0 && repeat.status === 0 && first.stdout === repeat.stdout;
const sourceFiles = [];
function scan(directoryPath, relative) {
  for (const name of readdirSync(directoryPath).sort()) {
    const path = join(directoryPath, name), rel = `${relative}/${name}`;
    if (rel === 'tests/state/evidence') continue;
    const stat = lstatSync(path);
    assert(!stat.isSymbolicLink());
    if (stat.isDirectory()) scan(path, rel);
    else {const bytes = readFileSync(path); sourceFiles.push({path: rel, bytes: bytes.length, sha256: sha256(bytes)});}
  }
}
for (const relative of ['awe/state','awe/project_factory','awe/events','tests/state']) scan(join(root, relative), relative);
const matrix = [...(tests.stdout ?? '').matchAll(/^(ok|not ok) (\d+) - (.+)$/gm)].map(match => ({id: Number(match[2]), test: match[3],
  result: match[1] === 'ok' ? 'VERIFIED_E0_PASS' : 'FAIL'}));
writeFileSync(join(directory, 'test-matrix.json'), JSON.stringify({scope: 'E0 synthetic local self-run', cases: matrix,
  not_run: ['D02_PEP_INTEGRATION','REAL_POSTGRESQL_DDL_AND_FAULTS','MULTIPROCESS_RACES','OS_ISOLATION_RLS',
    'POWER_LOSS_DURABILITY','REAL_ARTIFACT_FSYNC_READBACK','REAL_PROVIDER_TOOL_OR_WORKSPACE','INDEPENDENT_QA_M04_M05_M06_M15_M18']}, null, 2) + '\n');
const suitesValid = results.filter(result => result.summary).every(({summary}) => summary.tests > 0
  && summary.pass === summary.tests && summary.fail === 0 && summary.cancelled === 0 && summary.skipped === 0 && summary.todo === 0);
const status = results.every(result => result.exit_code === 0) && suitesValid && deterministic
  && matrix.length === results.find(result => result.name === 'd03-state').summary.tests ? 'PASS_E0_ONLY' : 'FAIL';
writeFileSync(join(directory, 'run-receipt.json'), JSON.stringify({status, baseline_commit_required: '3abee561ae97428680a4fe5826b0f40ae676319a', head, branch,
  generated_at: new Date().toISOString(), node: process.version, node_executable: process.execPath,
  node_sha256: sha256(readFileSync(process.execPath)), environment_keys: Object.keys(env),
  release_manifest_sha256: sha256(readFileSync(join(root, 'baseline/release-manifest.json'))),
  results, demo_byte_identical: deterministic, source_files: sourceFiles,
  limitation: 'Memory + explicit serialized snapshot replay; no real DB, effects, trusted D02 or OS isolation; no production readiness.'}, null, 2) + '\n');
const hashes = readdirSync(directory).sort().map(name => `${sha256(readFileSync(join(directory, name)))}  ${name}`);
writeFileSync(join(directory, 'EVIDENCE.sha256'), hashes.join('\n') + '\n');
console.log(JSON.stringify({status, directory, results: results.map(({name, exit_code, summary}) => ({name, exit_code, summary})), demo_byte_identical: deterministic}, null, 2));
if (status !== 'PASS_E0_ONLY') process.exitCode = 1;
