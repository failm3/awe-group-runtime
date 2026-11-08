"""Trusted Windows Job owner. No shell, no PID-based attach/kill, no Hermes.

The target starts suspended; all limits and containment apply before resume.
Only the controller-selected, hash-pinned synthetic catalog may reach this host.
"""
import sys, os, json, ctypes as C, threading, time, base64, subprocess, msvcrt
from ctypes import wintypes as W

K = C.WinDLL('kernel32', use_last_error=True)
SIZE = C.c_size_t
U64 = C.c_ulonglong
class IO(C.Structure):
    _fields_ = [(n, U64) for n in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]
class BASIC(C.Structure):
    _fields_ = [('process_time', C.c_longlong), ('job_time', C.c_longlong), ('flags', W.DWORD), ('min_ws', SIZE), ('max_ws', SIZE), ('processes', W.DWORD), ('affinity', SIZE), ('priority', W.DWORD), ('scheduling', W.DWORD)]
class EXT(C.Structure):
    _fields_ = [('basic', BASIC), ('io', IO), ('process_memory', SIZE), ('job_memory', SIZE), ('peak_process', SIZE), ('peak_job', SIZE)]
class ACCOUNT(C.Structure):
    _fields_ = [('user', C.c_longlong), ('kernel', C.c_longlong), ('period_user', C.c_longlong), ('period_kernel', C.c_longlong), ('faults', W.DWORD), ('total', W.DWORD), ('active', W.DWORD), ('terminated', W.DWORD)]
class SA(C.Structure):
    _fields_ = [('length', W.DWORD), ('descriptor', W.LPVOID), ('inherit', W.BOOL)]
class STARTUP(C.Structure):
    _fields_ = [('cb',W.DWORD), ('reserved',W.LPWSTR), ('desktop',W.LPWSTR), ('title',W.LPWSTR), ('x',W.DWORD), ('y',W.DWORD), ('width',W.DWORD), ('height',W.DWORD), ('chars_x',W.DWORD), ('chars_y',W.DWORD), ('fill',W.DWORD), ('flags',W.DWORD), ('show',W.WORD), ('reserved2',W.WORD), ('bytes',C.POINTER(C.c_byte)), ('stdin',W.HANDLE), ('stdout',W.HANDLE), ('stderr',W.HANDLE)]
class PROCESS(C.Structure):
    _fields_ = [('process',W.HANDLE), ('thread',W.HANDLE), ('pid',W.DWORD), ('tid',W.DWORD)]
def api(name, args, result=W.BOOL):
    f = getattr(K, name); f.argtypes = args; f.restype = result; return f
create_job = api('CreateJobObjectW', [W.LPVOID,W.LPCWSTR], W.HANDLE)
set_job = api('SetInformationJobObject', [W.HANDLE,C.c_int,W.LPVOID,W.DWORD])
query_job = api('QueryInformationJobObject', [W.HANDLE,C.c_int,W.LPVOID,W.DWORD,W.LPVOID])
assign = api('AssignProcessToJobObject', [W.HANDLE,W.HANDLE])
terminate = api('TerminateJobObject', [W.HANDLE,W.UINT])
close = api('CloseHandle', [W.HANDLE])
pipe = api('CreatePipe', [C.POINTER(W.HANDLE),C.POINTER(W.HANDLE),C.POINTER(SA),W.DWORD])
set_handle = api('SetHandleInformation', [W.HANDLE,W.DWORD,W.DWORD])
create = api('CreateProcessW', [W.LPCWSTR,W.LPWSTR,W.LPVOID,W.LPVOID,W.BOOL,W.DWORD,W.LPVOID,W.LPCWSTR,C.POINTER(STARTUP),C.POINTER(PROCESS)])
resume = api('ResumeThread', [W.HANDLE], W.DWORD)
wait = api('WaitForSingleObject', [W.HANDLE,W.DWORD], W.DWORD)
get_exit = api('GetExitCodeProcess', [W.HANDLE,C.POINTER(W.DWORD)])
read = api('ReadFile', [W.HANDLE,W.LPVOID,W.DWORD,C.POINTER(W.DWORD),W.LPVOID])
write = api('WriteFile', [W.HANDLE,W.LPVOID,W.DWORD,C.POINTER(W.DWORD),W.LPVOID])
def checked(ok):
    if not ok:
        raise OSError('RT02_JOB_API_DENIED')
def emit(kind, **payload):
    print(json.dumps({'contract':'rt02.job/1','type':kind, **payload}, separators=(',',':')), flush=True)
def main():
    raw = sys.stdin.buffer.readline(8193)
    if len(raw) > 8192:
        raise ValueError('INPUT_LIMIT')
    q = json.loads(raw)
    job = create_job(None,None); checked(job)
    pi = PROCESS(); handles = []
    try:
        limits = EXT()
        # JOB_TIME | ACTIVE_PROCESS | JOB_MEMORY | DIE_ON_UNHANDLED_EXCEPTION | KILL_ON_JOB_CLOSE
        limits.basic.flags = 0x4 | 0x8 | 0x200 | 0x400 | 0x2000
        limits.basic.job_time = q['cpu_ms'] * 10000
        limits.basic.processes = 1
        limits.job_memory = q['memory_bytes']
        checked(set_job(job,9,C.byref(limits),C.sizeof(limits)))
        sa = SA(C.sizeof(SA),None,True)
        def make_pipe():
            a,b = W.HANDLE(),W.HANDLE(); checked(pipe(C.byref(a),C.byref(b),C.byref(sa),0)); handles.extend([a,b]); return a,b
        in_r,in_w = make_pipe(); out_r,out_w = make_pipe(); err_r,err_w = make_pipe()
        for h in (in_w,out_r,err_r): checked(set_handle(h,1,0))
        si = STARTUP(); si.cb = C.sizeof(si); si.flags = 0x100; si.stdin=in_r; si.stdout=out_w; si.stderr=err_w
        command = C.create_unicode_buffer(subprocess.list2cmdline([q['executable'], *q['args']]))
        environment = C.create_unicode_buffer('\0'.join(k+'='+v for k,v in sorted(q['env'].items()))+'\0\0')
        checked(create(q['executable'],command,None,None,True,0x4|0x400|0x08000000,environment,q['cwd'],C.byref(si),C.byref(pi)))
        handles.extend([pi.process,pi.thread])
        # If assignment fails the suspended process is terminated, never resumed.
        if not assign(job,pi.process):
            api('TerminateProcess',[W.HANDLE,W.UINT])(pi.process,125)
            raise OSError('RT02_JOB_ASSIGN_DENIED')
        for h in (in_r,out_w,err_w): close(h); handles.remove(h)
        stop = threading.Event(); reason = [None]; buffers = [bytearray(),bytearray()]; counts=[0,0]
        def cancel():
            # Raw Win32 read avoids holding Python's buffered-reader lock at shutdown.
            one=C.create_string_buffer(1); received=W.DWORD()
            read(msvcrt.get_osfhandle(sys.stdin.fileno()),one,1,C.byref(received),None)
            if not stop.is_set(): reason[0]='CANCELLED'; terminate(job,124)
        threading.Thread(target=cancel,daemon=True).start()
        def collect(h,index):
            block=C.create_string_buffer(4096); n=W.DWORD()
            while read(h,block,len(block),C.byref(n),None) and n.value:
                counts[index]+=n.value
                remaining=max(0,q['output_bytes']-len(buffers[index]))
                buffers[index].extend(block.raw[:min(n.value,remaining)])
                if counts[index]>q['output_bytes']:
                    reason[0]='OUTPUT_LIMIT'; terminate(job,123)
        readers=[threading.Thread(target=collect,args=(out_r,0)),threading.Thread(target=collect,args=(err_r,1))]
        for t in readers: t.start()
        checked(resume(pi.thread)!=0xffffffff)
        emit('STARTED',pid=pi.pid,assigned_before_resume=True,job_process_limit=1)
        data=q['stdin'].encode('utf-8'); written=W.DWORD()
        if data: checked(write(in_w,data,len(data),C.byref(written),None) and written.value==len(data))
        close(in_w); handles.remove(in_w)
        started=time.monotonic()
        while wait(pi.process,10)==258:
            usage=ACCOUNT(); checked(query_job(job,1,C.byref(usage),C.sizeof(usage),None))
            if (usage.user+usage.kernel)//10000 > q['cpu_ms']:
                reason[0]='CPU_LIMIT'; terminate(job,120)
            if (time.monotonic()-started)*1000 > q['wall_ms']:
                reason[0]='TIME_LIMIT'; terminate(job,122)
        stop.set()
        # No successful return before readers close and the Job has zero active children.
        for t in readers: t.join(2)
        if any(t.is_alive() for t in readers): raise RuntimeError('PIPE_CLOSE_UNPROVEN')
        code=W.DWORD(); checked(get_exit(pi.process,C.byref(code)))
        account=ACCOUNT()
        for _ in range(100):
            checked(query_job(job,1,C.byref(account),C.sizeof(account),None))
            if account.active==0: break
            time.sleep(0.005)
        peak=EXT(); checked(query_job(job,9,C.byref(peak),C.sizeof(peak),None))
        checked(account.active==0)
        emit('EXIT',pid=pi.pid,exit_code=code.value,reason=reason[0] or ('EXIT' if code.value==0 else 'NONZERO_EXIT'),
             stdout=base64.b64encode(buffers[0]).decode(),stderr=base64.b64encode(buffers[1]).decode(),
             stdout_bytes=counts[0],stderr_bytes=counts[1],cpu_micros=(account.user+account.kernel)//10,
             peak_job_bytes=peak.peak_job,active_processes=account.active,created_processes=account.total)
    finally:
        terminate(job,121)
        for h in reversed(handles): close(h)
        close(job)
try:
    main()
except Exception:
    emit('FAULT',code='RT_PROCESS_JOB_HOST_FAILED')
    sys.exit(1)
