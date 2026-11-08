import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {digest, immutable, need, validateBoundValue} from '../contracts/index.mjs';
import {toolProfile, TEXT_INPUT_SCHEMA, TEXT_OUTPUT_SCHEMA} from './profiles.mjs';

export function filePin(filename) {
  const resolved = fs.realpathSync(filename), stat = fs.lstatSync(resolved);
  need(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && stat.size > 0 && stat.size <= 67108864, 'TOOL_BINARY_FILE');
  return immutable({digest: 'sha256:' + createHash('sha256').update(fs.readFileSync(resolved)).digest('hex'), bytes: stat.size});
}
function environment(paths = []) {
  const env = Object.fromEntries(['SystemRoot', 'WINDIR'].filter(key => process.env[key]).map(key => [key, process.env[key]]));
  env.PATH = paths.join(path.delimiter); return env;
}
export function binaryVersion(filename) {
  const result = spawnSync(fs.realpathSync(filename), ['--version'], {env: environment(), encoding: 'utf8', timeout: 3000, maxBuffer: 16384, windowsHide: true});
  need(!result.error && result.status === 0 && result.stderr === '', 'TOOL_VERSION_PROBE');
  return result.stdout.split(/\r?\n/)[0].slice(0, 160);
}
export function verifyBinaryPins(binaries, pins) {
  need(binaries && pins && Object.keys(binaries).length === pins.length, 'TOOL_BINARY_BINDING');
  for (const pin of pins) need(typeof binaries[pin.role] === 'string' && digest(filePin(binaries[pin.role])) === digest({digest: pin.digest, bytes: pin.bytes}), 'TOOL_BINARY_PIN_MISMATCH');
}
export function assertRgaDependencySearchPaths(toolBinary) {
  const folder = path.dirname(fs.realpathSync(toolBinary));
  // Upstream prepends BOTH directories ahead of the caller's verified PATH.
  // This profile permits neither bundled override, even if bytes happen match.
  for (const directory of [folder, path.join(folder, 'lib')]) need(!fs.existsSync(path.join(directory, 'rg.exe')), 'TOOL_DEPENDENCY_SHADOW');
}

/** Only a fixed, stdin-only literal search. No command/argv/path comes from a
 * model or catalog description. This is a trusted installed utility adapter,
 * not a hostile-code OS sandbox and not an A2 admission substitute. */
export function runFixedTextTool({profile_id, binaries, pins, input, beforeSpawn = null, onSpawned = null}) {
  const p = toolProfile(profile_id); need(process.platform === p.platform, 'TOOL_PLATFORM');
  validateBoundValue(TEXT_INPUT_SCHEMA, input);
  need(/^[\x20-\x7e]{1,128}$/.test(input.pattern) && !input.text.includes('\0') && Buffer.byteLength(input.text) <= 8192, 'TOOL_INPUT_BOUND');
  const normalized = input.text.replaceAll('\r\n', '\n'), lines = normalized.split('\n');
  need(lines.length <= 65 && lines.every(line => line.length <= 256), 'TOOL_INPUT_LINES');
  need(Object.keys(binaries).sort().join(',') === [...p.binary_roles].sort().join(','), 'TOOL_BINARY_ROLES');
  verifyBinaryPins(binaries, pins);
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'awe-tool-stdin-'));
  const config = path.join(folder, 'rga-config.jsonc');
  try {
    fs.writeFileSync(config, '{}\n', {flag: 'wx', mode: 0o600});
    const args = ['--no-config', '--fixed-strings', '--case-sensitive', '--no-pre', '--no-search-zip', '--color=never', '--no-heading', '--no-line-number', '--no-filename', '--max-count=64', '--', input.pattern, '-'];
    if (profile_id === 'ripgrep-all-stdin') {
      // Disable both caches/config discovery; stdin never invokes preprocessors.
      args.unshift('--rga-no-cache', '--rga-config-file=' + config);
      assertRgaDependencySearchPaths(binaries.tool);
    }
    const env = environment(profile_id === 'ripgrep-all-stdin' ? [path.dirname(fs.realpathSync(binaries.rg))] : []);
    const executable = fs.realpathSync(binaries.tool);
    if (beforeSpawn) need(!beforeSpawn()?.then, 'TOOL_ASYNC_FINAL_GUARD_DENIED');
    const result = spawnSync(executable, args, {cwd: folder, env, input: normalized, encoding: 'utf8', timeout: 3000, maxBuffer: 32768, windowsHide: true});
    if (onSpawned && result.pid > 0) need(!onSpawned({pid: result.pid, exit_code: result.status})?.then, 'TOOL_ASYNC_OBSERVER_DENIED');
    need(!result.error && [0, 1].includes(result.status) && result.stderr === '', 'TOOL_EXECUTION_FAILED');
    verifyBinaryPins(binaries, pins);
    need(Buffer.byteLength(result.stdout) <= 16384 && result.stdout.isWellFormed(), 'TOOL_OUTPUT_BOUND');
    const matches = result.stdout === '' ? [] : result.stdout.replace(/\r?\n$/, '').split(/\r?\n/);
    const output = validateBoundValue(TEXT_OUTPUT_SCHEMA, {matches, count: matches.length});
    return immutable({schema: 'awe.e1.fixed-tool-execution/1', status: 'EXECUTED', profile_id, input_digest: digest(input), output, output_digest: digest(output), exit_code: result.status, binary_pins: pins, external_mutations: 0,
      invocation_policy: 'FIXED_STDIN_LITERAL_SEARCH_NO_CONFIG_NO_ADAPTER_NO_CACHE', os_hostile_code_sandbox: false, native_admission: 'NOT_ASSERTED_BY_THIS_PORT'});
  } finally {
    // Only our exact owned file and directory; never recursive deletion.
    if (fs.existsSync(config)) fs.unlinkSync(config);
    fs.rmdirSync(folder);
  }
}
