#!/usr/bin/env bash
set -euo pipefail
base=/var/lib/awe-e1-test/awe_e1_a2a3_20261108
test ! -e "$base"
test -x /usr/lib/postgresql/18/bin/initdb
/usr/lib/postgresql/18/bin/psql --version
test "$(id -u)" = 0
python3 - <<'PY'
import json,os,socket,subprocess,hashlib
ports={}
for port in (5432,5433,55582):
    s=socket.socket()
    try:
        s.bind(('127.0.0.1',port));ports[str(port)]='AVAILABLE'
    except OSError:
        ports[str(port)]='IN_USE'
    finally:s.close()
assert ports['5433']=='AVAILABLE','E1_PORT_UNAVAILABLE'
mem={line.split(':')[0]:int(line.split()[1])*1024 for line in open('/proc/meminfo') if line.startswith(('MemTotal:','MemAvailable:'))}
space=os.statvfs('/var/lib')
assert mem['MemAvailable']>=1024**3,'INSUFFICIENT_MEMORY'
assert space.f_bavail*space.f_frsize>=2*1024**3,'INSUFFICIENT_DISK'
processes=subprocess.run(['ps','-eo','pid,lstart,args'],capture_output=True,text=True,check=True).stdout
pg='\n'.join(x for x in processes.splitlines() if '/postgres' in x or 'postgres:' in x)
r={'schema':'awe.e1.resource-preflight/1','ports':ports,'memory_available_bytes':mem['MemAvailable'],'linux_disk_available_bytes':space.f_bavail*space.f_frsize,'postgres_process_fingerprint_sha256':hashlib.sha256(pg.encode()).hexdigest(),'postgres_process_rows':len(pg.splitlines()),'e1_base_absent':True,'e0_touched':False}
os.makedirs('/tmp/awe-e1-preflight-control',mode=0o700,exist_ok=True)
open('/tmp/awe-e1-preflight-control/preflight.json','w').write(json.dumps(r))
print(json.dumps(r))
PY
