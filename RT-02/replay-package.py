"""Smoke the exact ZIP over unchanged tracked base files, inside this candidate's sandbox."""
import pathlib,tempfile,zipfile,subprocess,json,hashlib,shutil,os
root=pathlib.Path(__file__).resolve().parent.parent
replay=pathlib.Path(tempfile.mkdtemp(prefix='zip-replay-',dir=root/'RT-02/sandbox')).resolve()
assert replay.is_relative_to((root/'RT-02/sandbox').resolve())
paths=subprocess.check_output(['git','ls-files','-z'],cwd=root).decode().split('\0')
for p in filter(None,paths):
    target=(replay/p).resolve(); assert target.is_relative_to(replay)
    target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/p,target)
archive=root/'RT-02/delivery/AWE-GROUP-RT02-LOCAL-CANDIDATE.zip'
with zipfile.ZipFile(archive) as z:
    for name in z.namelist():
        target=(replay/name).resolve(); assert target.is_relative_to(replay)
        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(z.read(name))
env={k:os.environ[k] for k in ('SystemRoot','WINDIR','TEMP','TMP') if k in os.environ};env['TZ']='UTC'
lock=json.loads((replay/'RT-02/runtime-lock.json').read_text())
args=[lock['executables']['node']['path'],'--test','--test-isolation=none','--test-concurrency=1','--test-reporter=tap','--test-name-pattern=executes real','tests/hermes_runtime/rt02/executors.test.mjs']
r=subprocess.run(args,cwd=replay,env=env,capture_output=True,timeout=30)
evidence=root/'RT-02/evidence';(evidence/'archive-smoke.tap').write_bytes(r.stdout);(evidence/'archive-smoke.stderr').write_bytes(r.stderr)
assert r.returncode==0 and b'# pass 3' in r.stdout
result={'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'overlay_base_files':len(list(filter(None,paths))),'archive_smoke':'PASS','tests':3,'pass':3,'fail':0,'counted_in_main_total':False,'replay_directory':str(replay),'args':args,'physical_decision':'DENY','real_hermes':'REAL_HERMES_NOT_RUN'}
(evidence/'archive-smoke.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result))
