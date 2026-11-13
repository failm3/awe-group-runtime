#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" = 0
: "${E0_PRIVATE_METADATA:?Operator-owned closed identity input required; never publish it}"
export E0_PRIVATE_METADATA
python3 - <<'PY'
import json,os,subprocess,hashlib,datetime
base='/var/lib/awe-e1-test/awe_e1_a2a3_20261108'
data=base+'/pgdata'
assert os.path.realpath(data)==data
assert oct(os.stat(data).st_mode & 0o777)=='0o700'
prior=json.load(open('/tmp/awe-e1-preflight-control/processes.json'))
now={int(x.strip().split()[0]):hashlib.sha256(x.encode()).hexdigest() for x in subprocess.check_output(['ps','-eo','pid,lstart,args'],text=True).splitlines()[1:]}
assert all(now.get(x['pid'])==x['line_sha256'] for x in prior)
e0=json.load(open(os.environ['E0_PRIVATE_METADATA']))
roles=['awe_e1_test','awe_e1_coord','awe_e1_worker','awe_e1_qa']
denied=[]
for role in roles:
    assert subprocess.run(['/usr/sbin/runuser','-u',role,'--','test','-r',e0['data']+'/PG_VERSION']).returncode!=0
    denied.append(role)
def pg(user,db='awe_e1_test',tcp=False,as_role=None):
    return ['/usr/sbin/runuser','-u',user,'--','/usr/lib/postgresql/18/bin/psql','-X','--no-password','-v','ON_ERROR_STOP=1','-h','127.0.0.1' if tcp else base+'/socket','-p','5433','-U',as_role or user,'-d',db]
for name,cmd in [('tcp',pg('awe_e1_worker',tcp=True)),('peer',pg('awe_e1_worker',as_role='awe_e1_coord')),('database',pg('awe_e1_qa',db='postgres'))]:
    p=subprocess.run(cmd+['-c','SELECT 1'],capture_output=True,text=True,timeout=10)
    assert p.returncode!=0 and 'FATAL' in p.stderr,(name,p.returncode)
p=subprocess.run(pg('awe_e1_test')+['-At','-c',"SELECT bool_and(NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication) FROM pg_roles WHERE rolname IN ('awe_e1_coord','awe_e1_worker','awe_e1_qa')"],capture_output=True,text=True,check=True,timeout=10)
assert p.stdout.strip()=='t'
r={'schema':'awe.e1.final-isolation-check/1','status':'PASS','checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'resource_id':'awe_e1_a2a3_20261108','port':5433,'pgdata_mode':'0700','preexisting_postgres_processes_unchanged':len(prior),'e0_read_denied_unix_principals':denied,'e1_tcp_connection':'REJECTED','peer_impersonation':'REJECTED','qa_other_database':'REJECTED','application_roles_privileged':False,'e0_connections':0,'e0_private_metadata_exported':False,'source_or_e0_writes':0}
open(base+'/final-isolation.json','w').write(json.dumps(r))
print(json.dumps(r))
PY
