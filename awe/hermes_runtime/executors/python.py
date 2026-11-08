"""Reviewed synthetic programs only. Audit hooks are defense in depth, not a hostile-code sandbox."""
import sys, os, json, time

root = os.path.realpath(os.getcwd())
def guard(event, args):
    if event == 'open':
        p = args[0]
        if isinstance(p, str) and not os.path.realpath(p).startswith(root + os.sep):
            raise PermissionError('RT02_FILE_DENIED')
    if event.startswith(('socket.', 'subprocess.', 'ctypes.', 'os.exec', 'os.spawn')) or event in ('os.system', 'os.chdir', 'os.putenv', 'os.remove', 'os.rename', 'os.link', 'os.symlink'):
        raise PermissionError('RT02_CAPABILITY_DENIED')
sys.addaudithook(guard)
data = json.load(sys.stdin)
program = data['program']
value = None
if program == 'sum':
    value = sum(data['values'])
elif program == 'wait':
    time.sleep(60)
elif program == 'cpu':
    while True:
        pass
elif program == 'memory':
    xs = []
    while True:
        xs.append(bytearray(8 * 1024 * 1024))
elif program == 'crash':
    sys.exit(7)
elif program in ('flood', 'stderr'):
    stream = sys.stdout if program == 'flood' else sys.stderr
    for _ in range(1000):
        stream.write('x' * 4096)
        stream.flush()
elif program == 'probe':
    def denied(fn):
        try:
            fn()
            return False
        except (PermissionError, ImportError):
            return True
    value = {
        'environment_clean': not any(os.environ.get(k) for k in ('RT02_SECRET_CANARY', 'PYTHONPATH', 'PATH')),
        'filesystem_denied': denied(lambda: open(sys.executable, 'rb')),
        'network_denied': denied(lambda: sys.audit('socket.connect', None, ('127.0.0.1', 9))),
        'spawn_denied': denied(lambda: os.system('echo forbidden')),
    }
    with open('local.txt', 'w') as f:
        f.write('synthetic')
else:
    raise ValueError('PROGRAM_DENIED')
if value is not None:
    print(json.dumps({'schema': 'rt02.synthetic.result/1', 'value': value}), flush=True)
