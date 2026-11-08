"""Trusted host runner for a bounded two-file Python program.

Candidate stdout is data, never a verdict. Expected answers are not accepted by
this interface. A kernel-filtered launcher emits a setup handshake BEFORE any
candidate import; only the host parent constructs the receipt.
"""
import hashlib
import json
import os
import platform
import re
import resource
import selectors
import signal
import subprocess
import sys
import tempfile
import time


PROFILE = {
    'schema': 'awe.e1.program-profile/1',
    'profile_id': 'python-stdlib-two-file-single-process',
    'version': '1.0.0', 'platform': 'linux-x86_64',
    'files': ['cli.py', 'normalizer.py'],
    'entrypoints': ['cli.py', 'library-probe.py'], 'cwd': '/work',
    'network': 'DENY', 'process_policy': 'SECCOMP_NO_FORK_CLONE_EXEC',
    'limits': {'source_bytes': 32768, 'stdin_bytes': 8192,
               'stdout_bytes': 16384, 'stderr_bytes': 4096,
               'address_space_bytes': 268435456, 'cpu_seconds': 2,
               'wall_seconds': 5, 'tmpfs_bytes': 16777216,
               'file_bytes': 1048576, 'open_fds': 32,
               'candidate_processes': 1},
}
LIMITS = PROFILE['limits']


def canonical(value):
    # All metadata keys are ASCII; interoperates with awe-canonical-json-v1.
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def sha(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha(canonical(value))


def require(condition, code):
    if not condition:
        raise ValueError(code)


def deny(code):
    print(json.dumps({'status': 'DENIED', 'reason': code,
                      'sandbox_enforced': False}, separators=(',', ':')))
    return 1


# This probe only exposes the callable's outputs. No oracle or expected values.
LIBRARY_PROBE = """import json,sys
from normalizer import normalize_event
values=json.load(sys.stdin)
if not isinstance(values,list) or len(values)>64:
    raise ValueError('LIBRARY_PROBE_INPUT')
print(json.dumps([normalize_event(value) for value in values],ensure_ascii=False))
"""


LAUNCHER = r'''import ctypes,errno,json,os,platform,runpy,socket,sys
CONFIG=@@CONFIG@@
if platform.system()!='Linux' or platform.machine()!='x86_64':
    raise RuntimeError('PLATFORM')
class Filter(ctypes.Structure):
    _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
# x86_64 native only; x32 ABI rejected before syscall matching. No clone,
# fork, threads, exec, namespace change, process-group escape, or network.
blocked=[41,53,56,57,58,59,101,109,112,155,157,165,166,170,171,175,176,
         248,249,250,272,298,303,304,308,310,311,313,317,321,322,323,425,435]
instructions=[Filter(0x20,0,0,4),Filter(0x15,1,0,0xc000003e),
              Filter(0x06,0,0,0x80000000),Filter(0x20,0,0,0),
              Filter(0x35,0,1,0x40000000),Filter(0x06,0,0,0x00050000|errno.EPERM)]
for number in blocked:
    instructions.extend([Filter(0x15,0,1,number),Filter(0x06,0,0,0x00050000|errno.EPERM)])
instructions.append(Filter(0x06,0,0,0x7fff0000))
filters=(Filter*len(instructions))(*instructions)
program=Program(len(instructions),filters)
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(38,1,0,0,0)!=0 or libc.prctl(22,2,ctypes.byref(program),0,0)!=0:
    raise RuntimeError('SECCOMP_INSTALL')
status={}
with open('/proc/self/status') as f:
    for line in f:
        if ':' in line:
            key,value=line.split(':',1);status[key]=value.strip()
boundary={
    'home_absent':not os.path.exists('/home'),
    'windows_absent':not os.path.exists('/mnt/c'),
    'repository_absent':not os.path.exists('/repo'),
    'private_absent':not os.path.exists('/private'),
    'network_namespace':os.readlink('/proc/self/ns/net')!=CONFIG['namespaces']['net'],
    'mount_namespace':os.readlink('/proc/self/ns/mnt')!=CONFIG['namespaces']['mnt'],
    'pid_namespace':os.readlink('/proc/self/ns/pid')!=CONFIG['namespaces']['pid'],
    'seccomp_enforced':status.get('Seccomp')=='2',
    'no_new_privileges':status.get('NoNewPrivs')=='1',
}
try:
    with open('/work/.awe-readonly-check','x') as f:f.write('x')
    boundary['source_readonly']=False
except OSError as error:
    boundary['source_readonly']=error.errno in (errno.EROFS,errno.EACCES)
try:
    sock=socket.socket();sock.close();boundary['socket_denied']=False
except OSError as error:
    boundary['socket_denied']=error.errno==errno.EPERM
try:
    child=os.fork()
    if child==0:os._exit(101)
    os.waitpid(child,0);boundary['fork_denied']=False
except OSError as error:
    boundary['fork_denied']=error.errno==errno.EPERM
ctypes.set_errno(0)
result=libc.syscall(59,ctypes.c_void_p(0),ctypes.c_void_p(0),ctypes.c_void_p(0))
boundary['exec_denied']=result==-1 and ctypes.get_errno()==errno.EPERM
stat=os.statvfs('/tmp')
boundary['tmpfs_bounded']=0<stat.f_blocks*stat.f_frsize<=CONFIG['tmpfs_bytes']
if not all(boundary.values()):raise RuntimeError('BOUNDARY')
handshake={'nonce':CONFIG['nonce'],'boundary':boundary,
           'python_version':platform.python_version()}
os.write(2,b'AWE_PROGRAM_READY:'+json.dumps(handshake,separators=(',',':')).encode()+b'\n')
# Candidate cannot erase the already captured handshake. It receives no extra
# pipe/FD, expected answer, credential, host environment, or host source path.
sys.path[:]=['/work']+[p for p in sys.path if p.startswith('/usr/')]
sys.argv=['/work/cli.py'] if CONFIG['entrypoint']=='cli.py' else ['/harness/library-probe.py']
runpy.run_path(sys.argv[0],run_name='__main__')
'''


def validate(request):
    require(type(request) is dict and set(request) ==
            {'files', 'stdin', 'entrypoint', 'binding', 'profile_digest'},
            'PROGRAM_REQUEST_SCHEMA')
    require(request['profile_digest'] == digest(PROFILE), 'PROGRAM_PROFILE')
    require(type(request['files']) is list and len(request['files']) == 2,
            'PROGRAM_FILES')
    names, source_files, size = set(), [], 0
    for file in request['files']:
        require(type(file) is dict and set(file) == {'path', 'content_utf8'},
                'PROGRAM_FILE_SCHEMA')
        name, text = file['path'], file['content_utf8']
        require(name in PROFILE['files'] and name not in names,
                'PROGRAM_PATH_DENIED')
        require(type(text) is str and '\0' not in text, 'PROGRAM_ENCODING')
        raw = text.encode('utf-8'); size += len(raw); names.add(name)
        source_files.append({'path': name, 'digest': sha(raw), 'bytes': len(raw)})
    require(size <= LIMITS['source_bytes'], 'PROGRAM_SOURCE_BOUND')
    require(type(request['stdin']) is str and
            len(request['stdin'].encode('utf-8')) <= LIMITS['stdin_bytes'],
            'PROGRAM_INPUT_BOUND')
    require(request['entrypoint'] in PROFILE['entrypoints'],
            'PROGRAM_ENTRYPOINT_DENIED')
    binding = request['binding']
    require(type(binding) is dict and set(binding) ==
            {'tested_head_sha', 'tested_tree_sha', 'invocation_id'},
            'PROGRAM_BINDING')
    require(all(type(binding[key]) is str and re.fullmatch('[a-f0-9]{40}', binding[key])
                for key in ['tested_head_sha', 'tested_tree_sha']) and
            type(binding['invocation_id']) is str and
            re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}', binding['invocation_id']),
            'PROGRAM_BINDING')
    return sorted(source_files, key=lambda file: file['path'])


def set_limits():
    # Seccomp in the launcher makes these per-process limits aggregate for the
    # candidate: no threads/processes can be created after the launcher starts.
    for key, amount in [(resource.RLIMIT_CPU, LIMITS['cpu_seconds']),
                        (resource.RLIMIT_AS, LIMITS['address_space_bytes']),
                        (resource.RLIMIT_FSIZE, LIMITS['file_bytes']),
                        (resource.RLIMIT_NOFILE, LIMITS['open_fds']),
                        (resource.RLIMIT_CORE, 0)]:
        resource.setrlimit(key, (amount, amount))


def kill_tree(peer):
    try:
        os.killpg(peer.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    peer.wait(timeout=3)


def capture(command, stdin):
    peer = subprocess.Popen(command, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={'PATH': '/usr/bin:/bin'},
                            preexec_fn=set_limits, start_new_session=True)
    started = time.monotonic()
    stdout, stderr = bytearray(), bytearray()
    timed_out = truncated = False
    selector = selectors.DefaultSelector()
    selector.register(peer.stdout, selectors.EVENT_READ, 'stdout')
    selector.register(peer.stderr, selectors.EVENT_READ, 'stderr')
    try:
        peer.stdin.write(stdin); peer.stdin.close()
        while selector.get_map():
            if time.monotonic() - started > LIMITS['wall_seconds']:
                timed_out = True; kill_tree(peer); break
            for key, _ in selector.select(timeout=.05):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj); continue
                target = stdout if key.data == 'stdout' else stderr
                limit = LIMITS['stdout_bytes'] if key.data == 'stdout' else LIMITS['stderr_bytes'] + 4096
                target.extend(chunk)
                if len(target) > limit:
                    del target[limit:]; truncated = True; kill_tree(peer); break
            if truncated:
                break
        if peer.poll() is None:
            remaining = max(.01, LIMITS['wall_seconds'] - (time.monotonic() - started))
            try:
                peer.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out = True; kill_tree(peer)
        return bytes(stdout), bytes(stderr), peer.returncode, timed_out, truncated, int((time.monotonic() - started) * 1000)
    finally:
        selector.close()
        if peer.poll() is None:
            kill_tree(peer)
        peer.stdout.close(); peer.stderr.close()


def text_bounded(raw, limit):
    try:
        return raw.decode('utf-8'), True
    except UnicodeDecodeError:
        # Invalid text is always a failed/incomplete output, never valid PASS.
        return raw.decode('utf-8', 'replace').encode('utf-8')[:limit].decode('utf-8', 'ignore'), False


def run(request):
    source_files = validate(request)
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64',
            'PROGRAM_PLATFORM')
    version = subprocess.run(['/usr/bin/bwrap', '--version'], capture_output=True,
                             timeout=3, check=True).stdout.decode().strip()
    help_text = subprocess.run(['/usr/bin/bwrap', '--help'], capture_output=True,
                               timeout=3, check=True).stdout.decode()
    require('--size' in help_text and '--remount-ro' in help_text,
            'PROGRAM_BWRAP_FEATURES')
    nonce = os.urandom(16).hex()
    config = {'namespaces': {name: os.readlink('/proc/self/ns/' + name)
                             for name in ['net', 'mnt', 'pid']},
              'entrypoint': request['entrypoint'], 'nonce': nonce,
              'tmpfs_bytes': LIMITS['tmpfs_bytes']}
    launcher = LAUNCHER.replace('@@CONFIG@@', repr(config))
    with tempfile.TemporaryDirectory(prefix='awe-program-') as folder:
        os.chmod(folder, 0o700)
        work = os.path.join(folder, 'work'); harness = os.path.join(folder, 'harness')
        os.mkdir(work); os.mkdir(harness)
        for file in request['files']:
            with open(os.path.join(work, file['path']), 'wb') as out:
                out.write(file['content_utf8'].encode('utf-8'))
        for name, text in [('launcher.py', launcher), ('library-probe.py', LIBRARY_PROBE)]:
            with open(os.path.join(harness, name), 'w', encoding='utf-8') as out:
                out.write(text)
        command = ['/usr/bin/bwrap', '--unshare-all', '--new-session',
                   '--die-with-parent', '--cap-drop', 'ALL', '--clearenv',
                   '--setenv', 'PATH', '/usr/bin:/bin',
                   '--setenv', 'PYTHONIOENCODING', 'utf-8',
                   '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib',
                   '--ro-bind', '/lib64', '/lib64', '--proc', '/proc',
                   '--dir', '/dev', '--dev-bind', '/dev/null', '/dev/null',
                   '--dev-bind', '/dev/urandom', '/dev/urandom',
                   '--size', str(LIMITS['tmpfs_bytes']), '--tmpfs', '/tmp',
                   '--ro-bind', work, '/work', '--ro-bind', harness, '/harness',
                   '--remount-ro', '/', '--chdir', '/work', '--',
                   '/usr/bin/python3', '-B', '-S', '/harness/launcher.py']
        raw_stdout, raw_stderr, exit_code, timed_out, truncated, duration = capture(
            command, request['stdin'].encode('utf-8'))
    prefix, separator, candidate_stderr = raw_stderr.partition(b'\n')
    require(separator and prefix.startswith(b'AWE_PROGRAM_READY:'),
            'PROGRAM_NO_TRUSTED_HANDSHAKE')
    handshake = json.loads(prefix[len(b'AWE_PROGRAM_READY:'):])
    require(handshake['nonce'] == nonce and all(handshake['boundary'].values()),
            'PROGRAM_BOUNDARY')
    if len(candidate_stderr) > LIMITS['stderr_bytes']:
        candidate_stderr = candidate_stderr[:LIMITS['stderr_bytes']]; truncated = True
    stdout, stdout_valid = text_bounded(raw_stdout, LIMITS['stdout_bytes'])
    stderr, stderr_valid = text_bounded(candidate_stderr, LIMITS['stderr_bytes'])
    truncated = truncated or not stdout_valid or not stderr_valid
    toolchain = {'platform': 'linux-x86_64',
                 'python_version': handshake['python_version'],
                 'python_digest': sha(open('/usr/bin/python3', 'rb').read()),
                 'bwrap_version': version}
    result = {'schema': 'awe.e1.program-receipt/1', 'status': 'EXECUTED',
              'sandbox_enforced': True, 'network': 'DENY',
              'boundary': handshake['boundary'], 'exit_code': exit_code,
              'timed_out': timed_out, 'output_truncated': truncated,
              'output_encoding_valid': stdout_valid and stderr_valid,
              'stdout': stdout, 'stderr': stderr,
              'stdout_bytes_digest': sha(raw_stdout),
              'stderr_bytes_digest': sha(candidate_stderr),
              'source_files': source_files, 'source_digest': digest(source_files),
              'stdin_digest': sha(request['stdin'].encode('utf-8')),
              'entrypoint': request['entrypoint'], 'profile_digest': digest(PROFILE),
              'sandbox_source_digest': sha(open(__file__, 'rb').read()),
              **request['binding'], 'toolchain': toolchain,
              'limits': LIMITS, 'duration_ms': duration}
    result['output_digest'] = digest({key: result[key] for key in
                                     ['stdout', 'stderr', 'exit_code', 'timed_out', 'output_truncated']})
    result['receipt_digest'] = digest(result)
    return result


def main():
    require(not sys.argv[1:], 'PROGRAM_ARGUMENTS_DENIED')
    raw = sys.stdin.buffer.read(65537)
    require(len(raw) <= 65536, 'PROGRAM_REQUEST_BOUND')
    print(json.dumps(run(json.loads(raw)), ensure_ascii=False, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        code = str(error)
        sys.exit(deny(code if re.fullmatch('PROGRAM_[A-Z_]+', code) else 'PROGRAM_SETUP_DENIED'))
