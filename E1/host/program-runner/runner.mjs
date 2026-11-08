import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {need} from '../../contracts/index.mjs';
import {PROGRAM_PROFILE, PROGRAM_PROFILE_DIGEST, validateProgramRequest} from './profiles.mjs';
import {verifyProgramReceipt} from './receipts.mjs';

const helperPath = fileURLToPath(new URL('./sandbox.py', import.meta.url));
export function programRunnerSourcePins() {
  return ['profiles.mjs', 'receipts.mjs', 'runner.mjs', 'sandbox.py'].map(file => ({file: 'E1/host/program-runner/' + file, digest: 'sha256:' + createHash('sha256').update(readFileSync(new URL(file, import.meta.url))).digest('hex')}));
}
export async function runProgram(request) {
  validateProgramRequest(request);
  const env = Object.fromEntries(['SystemRoot', 'WINDIR', 'PATH'].filter(key => process.env[key]).map(key => [key, process.env[key]]));
  env.WSL_UTF8 = '1';
  const executable = process.platform === 'win32' ? 'wsl.exe' : '/usr/bin/python3';
  const helper = process.platform === 'win32' ? '/mnt/' + helperPath[0].toLowerCase() + helperPath.slice(2).replaceAll('\\', '/') : helperPath;
  const args = process.platform === 'win32' ? ['--distribution', 'Ubuntu', '--user', 'nox', '--exec', '/usr/bin/python3', helper] : [helper];
  const payload = JSON.stringify({...request, profile_digest: PROGRAM_PROFILE_DIGEST});
  const helperDigest = 'sha256:' + createHash('sha256').update(readFileSync(helperPath)).digest('hex');
  need(Buffer.byteLength(payload) <= 65536, 'PROGRAM_REQUEST_BOUND');
  return new Promise((resolve, reject) => {
    let settled = false, size = 0; const chunks = [];
    const peer = spawn(executable, args, {env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true});
    const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolve(value); };
    // Python owns the actual candidate deadline and kills the process group.
    // This larger transport deadline is not a replacement for that kill.
    const timer = setTimeout(() => { peer.kill(); finish(Object.assign(Error('PROGRAM_HOST_TIMEOUT'), {code: 'PROGRAM_HOST_TIMEOUT'})); }, (PROGRAM_PROFILE.limits.wall_seconds + 15) * 1000);
    peer.stdout.on('data', chunk => {
      size += chunk.length;
      if (size > 65536) { peer.kill(); finish(Object.assign(Error('PROGRAM_HOST_OUTPUT_BOUND'), {code: 'PROGRAM_HOST_OUTPUT_BOUND'})); }
      else chunks.push(chunk);
    });
    peer.stderr.on('data', () => {}); // Never forward host diagnostics or paths.
    peer.once('error', () => finish(Object.assign(Error('PROGRAM_HOST_SPAWN'), {code: 'PROGRAM_HOST_SPAWN'})));
    peer.once('close', status => {
      if (settled) return;
      try {
        const output = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        need(status === 0 && output.status === 'EXECUTED', typeof output.reason === 'string' && /^PROGRAM_[A-Z_]+$/.test(output.reason) ? output.reason : 'PROGRAM_SANDBOX_SETUP');
        need(output.sandbox_source_digest === helperDigest, 'PROGRAM_HOST_SOURCE_PIN');
        finish(null, verifyProgramReceipt(output, request));
      } catch (error) { finish(error.code ? error : Object.assign(Error('PROGRAM_HOST_RECEIPT'), {code: 'PROGRAM_HOST_RECEIPT'})); }
    });
    peer.stdin.on('error', () => finish(Object.assign(Error('PROGRAM_HOST_INPUT'), {code: 'PROGRAM_HOST_INPUT'})));
    peer.stdin.end(payload);
  });
}
