import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {digest} from '../contracts/index.mjs';
import {verifyProgramReceipt as verifyRunnerAttestation} from '../host/program-runner/receipts.mjs';
import {BRIEF_SHA256, ORACLE_COMMITMENT} from './commitments.mjs';
import {diagnosticTree, sha256} from './tree-proof.mjs';

const holdoutBytes = readFileSync(new URL('./holdout.json', import.meta.url));
assert.equal(sha256(holdoutBytes), ORACLE_COMMITMENT);
const holdout = JSON.parse(holdoutBytes);
assert.equal(holdout.brief_sha256, BRIEF_SHA256);

export function compareStream({stdout, stderr, exit_code}, expected, format = 'jsonl') {
  if (exit_code !== 0 || stderr !== '') return false;
  try {
    if (format === 'array') return isDeepStrictEqual(JSON.parse(stdout), expected);
    if (stdout === '') return expected.length === 0;
    const lines = stdout.replace(/\r?\n$/, '').split(/\r?\n/);
    return isDeepStrictEqual(lines.map(line => JSON.parse(line)), expected);
  } catch {
    return false;
  }
}

export function verifyProgramReceipt(receipt, request, profileDigest) {
  verifyRunnerAttestation(receipt, request);
  assert.equal(receipt.schema, 'awe.e1.program-receipt/1');
  assert.equal(receipt.status, 'EXECUTED');
  assert.equal(receipt.sandbox_enforced, true);
  assert.equal(receipt.network, 'DENY');
  assert.equal(receipt.output_encoding_valid, true, 'invalid UTF-8');
  assert.equal(receipt.timed_out, false, 'QA execution timed out');
  assert.equal(receipt.output_truncated, false, 'QA output truncated');
  assert.ok(Number.isInteger(receipt.exit_code));
  assert.equal(typeof receipt.stdout, 'string');
  assert.equal(typeof receipt.stderr, 'string');
  assert.equal(receipt.tested_head_sha, request.binding.tested_head_sha);
  assert.equal(receipt.tested_tree_sha, request.binding.tested_tree_sha);
  assert.equal(receipt.invocation_id, request.binding.invocation_id);
  assert.equal(receipt.profile_digest, profileDigest);
  assert.equal(receipt.stdin_digest, sha256(request.stdin));
  const expectedSources = request.files.map(file => ({
    path: file.path, digest: sha256(file.content_utf8), bytes: Buffer.byteLength(file.content_utf8),
  })).sort((a,b) => a.path.localeCompare(b.path));
  assert.deepEqual([...receipt.source_files].sort((a,b) => a.path.localeCompare(b.path)), expectedSources);
  assert.ok(Object.keys(receipt.boundary).length > 0 && Object.values(receipt.boundary).every(value => value === true));
  const {receipt_digest, ...frozen} = receipt;
  assert.equal(digest(frozen), receipt_digest);
}

function singleFileProjection(trees, path) {
  const files = trees.base.files.map(file => file.path === path ? trees.final.files.find(candidate => candidate.path === path) : file);
  return diagnosticTree(files, trees.base.head_sha, 'single_' + path);
}

async function judgeSuite({trees, runProgram, profileDigest}) {
  const records = [];
  async function probe(label, tree, entrypoint, stdin, expected, format, shouldMatch = true) {
    const binding = {tested_head_sha: tree.head_sha, tested_tree_sha: tree.tree_sha, invocation_id: 'qa_' + randomBytes(16).toString('hex')};
    const request = {files:tree.files.map(({path, content_utf8}) => ({path, content_utf8})), stdin, entrypoint, binding};
    const receipt = await runProgram(request);
    verifyProgramReceipt(receipt, request, profileDigest);
    const matched = compareStream(receipt, expected, format);
    records.push({label, passed: matched === shouldMatch, matched, expected_to_match: shouldMatch,
      tree_type: tree.projection ? 'QA_DERIVED_UNCOMMITTED' : 'REAL_GIT_SNAPSHOT',
      entrypoint, ...binding, profile_digest: profileDigest, input_digest: receipt.stdin_digest,
      output_digest: receipt.output_digest, expected_digest: digest(expected), receipt_digest: receipt.receipt_digest, exit_code: receipt.exit_code});
  }

  const cliInput = holdout.cli.lines.join('\n');
  await probe('public_base_reject', trees.base, 'cli.py', cliInput, holdout.cli.expected, 'jsonl', false);
  for (const path of ['cli.py', 'normalizer.py']) {
    await probe('single_' + path + '_reject', singleFileProjection(trees, path), 'cli.py', cliInput, holdout.cli.expected, 'jsonl', false);
  }
  await probe('library', trees.final, 'library-probe.py', JSON.stringify(holdout.library.inputs), holdout.library.expected, 'array');
  await probe('cli', trees.final, 'cli.py', cliInput, holdout.cli.expected, 'jsonl');
  await probe('empty', trees.final, 'cli.py', holdout.empty.input, holdout.empty.expected, 'jsonl');
  // Diagnostic substitution proves the CLI consumes the library's *return value*.
  // Generate a fresh value per run, unavailable while the candidate is being authored.
  const token = randomBytes(16).toString('hex');
  const challenge = 'ask_' + randomBytes(8).toString('hex');
  const marker = {id: token, kind: 'qa_marker'};
  const sentinel = 'def normalize_event(value):\n    if value.get("id") == "' + challenge + '":\n        return {"id":"' + token + '","kind":"qa_marker"}\n    return None\n';
  const files = trees.final.files.map(file => file.path === 'normalizer.py' ? {path:file.path, mode:file.mode, content_utf8:sentinel} : file);
  await probe('cli_calls_library', diagnosticTree(files, trees.final.head_sha, 'sentinel'), 'cli.py',
    JSON.stringify({id:challenge,kind:'probe'})+'\n', [marker], 'jsonl');
  return records;
}

export async function evaluateComponent(args) {
  const probes = await judgeSuite(args);
  return {oracle_commitment: ORACLE_COMMITMENT, verdict: probes.every(probe => probe.passed) ? 'PASS' : 'FAIL', probes};
}
