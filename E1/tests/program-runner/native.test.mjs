import test from 'node:test';
import assert from 'node:assert/strict';
import {runProgram} from '../../host/program-runner/runner.mjs';

const enabled = process.env.AWE_PROGRAM_RUNNER_NATIVE === '1';
let sequence = 0;
// ENGINEERING_TEST_FIXTURE. Deliberately does not implement the G1 brief.
function request(cli, {entrypoint = 'cli.py', stdin = ''} = {}) {
  return {files: [{path: 'normalizer.py', content_utf8: 'def normalize_event(value):\n    return value\n'}, {path: 'cli.py', content_utf8: cli}], stdin, entrypoint,
    binding: {tested_head_sha: 'a'.repeat(40), tested_tree_sha: 'b'.repeat(40), invocation_id: 'native-engineering-' + ++sequence}};
}
const options = {skip: !enabled, timeout: 25000};
test('native: two modules execute with trusted kernel boundary and no candidate verdict', options, async () => {
  const result = await runProgram(request('from normalizer import normalize_event\nprint(normalize_event("fixture"))\n'));
  assert.equal(result.status, 'EXECUTED'); assert.equal(result.exit_code, 0); assert.equal(result.stdout, 'fixture\n'); assert.equal(result.stderr, '');
  assert.equal(result.output_truncated, false); assert.equal(result.boundary.fork_denied, true); assert.equal(result.boundary.tmpfs_bounded, true);
});
test('native: neutral library probe returns actual values without expected answers', options, async () => {
  const result = await runProgram(request('', {entrypoint: 'library-probe.py', stdin: '[1,{"x":"test"},null]'}));
  assert.equal(result.exit_code, 0); assert.deepEqual(JSON.parse(result.stdout), [1, {x: 'test'}, null]);
});
test('native: kernel denies process/thread/exec/network, source and host writes', options, async () => {
  const code = `import ctypes,errno,json,os,socket\nr=[]\nfor action in [lambda: os.fork(),lambda: socket.socket(),lambda: os.execv('/usr/bin/python3',['python3','-c','pass']),lambda: open('/work/cli.py','a'),lambda: open('/private/canary','w')]:\n    try:\n        action();r.append(False)\n    except OSError as e:\n        r.append(e.errno in [errno.EPERM,errno.EROFS,errno.ENOENT,errno.EACCES])\nlibc=ctypes.CDLL(None,use_errno=True)\nctypes.set_errno(0)\nr.append(libc.syscall(435,ctypes.c_void_p(0),0)==-1 and ctypes.get_errno()==errno.EPERM)\nr.append(not os.path.exists('/home') and not os.path.exists('/mnt/c') and not os.path.exists('/repo'))\nprint(json.dumps(r))\n`;
  const result = await runProgram(request(code));
  assert.equal(result.exit_code, 0); assert.deepEqual(JSON.parse(result.stdout), [true, true, true, true, true, true, true]);
});
test('native: bounded scratch permits small files and aggregate tmpfs rejects exhaustion', options, async () => {
  const code = `import errno,json\nwith open('/tmp/ok','w') as f:f.write('fixture')\nfull=False\ntry:\n    for i in range(32):\n        with open('/tmp/f'+str(i),'wb') as f:f.write(b'X'*1048576)\nexcept OSError as e:\n    full=e.errno in [errno.ENOSPC,errno.EFBIG]\nprint(json.dumps(full))\n`;
  const result = await runProgram(request(code));
  assert.equal(result.exit_code, 0); assert.equal(JSON.parse(result.stdout), true);
});
test('native: candidate MemoryError is a product execution failure with valid setup', options, async () => {
  const result = await runProgram(request('data=bytearray(536870912)\n'));
  assert.notEqual(result.exit_code, 0); assert.equal(result.sandbox_enforced, true); assert.match(result.stderr, /MemoryError/);
});
test('native: sleeping candidate times out, is killed, and does not yield PASS', options, async () => {
  const result = await runProgram(request('import time\ntime.sleep(30)\n'));
  assert.equal(result.timed_out, true); assert.notEqual(result.exit_code, 0); assert.equal(result.stdout, '');
});
test('native: output flood is bounded and marked incomplete', options, async () => {
  const result = await runProgram(request('import sys\nsys.stdout.write("X"*1000000)\nsys.stdout.flush()\n'));
  assert.equal(result.output_truncated, true); assert.ok(Buffer.byteLength(result.stdout) <= 16384);
});
