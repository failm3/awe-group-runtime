#!/usr/bin/env bash
set -euo pipefail
: "${E0_PRIVATE_METADATA:?Host-only closed E0 identity JSON is required for deny-read check; never commit it}"
export E0_PRIVATE_METADATA
base=/var/lib/awe-e1-test/awe_e1_a2a3_20261108
cluster="$base/pgdata"
socket="$base/socket"
bin=/usr/lib/postgresql/18/bin
test "$(id -u)" = 0
test ! -e "$base"
for name in awe_e1_test awe_e1_coord awe_e1_worker awe_e1_qa; do
  if getent passwd "$name" >/dev/null; then echo EXISTING_E1_ACCOUNT_REQUIRES_REVIEW >&2; exit 71; fi
done
if getent group awe_e1_test >/dev/null; then echo EXISTING_E1_GROUP_REQUIRES_REVIEW >&2; exit 71; fi
python3 - <<'PY'
import socket,os,json,subprocess,hashlib
s=socket.socket();s.bind(('127.0.0.1',5433));s.close()
rows=subprocess.check_output(['ps','-eo','pid,lstart,args'],text=True).splitlines()
baseline=[]
for line in rows:
    if '/postgres' in line or 'postgres:' in line:
        baseline.append({'pid':int(line.strip().split()[0]),'line_sha256':hashlib.sha256(line.encode()).hexdigest()})
open('/tmp/awe-e1-preflight-control/processes.json','w').write(json.dumps(baseline))
PY
groupadd --system awe_e1_test
for name in awe_e1_test awe_e1_coord awe_e1_worker awe_e1_qa; do
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid awe_e1_test "$name"
done
install -d -m 0750 -o awe_e1_test -g awe_e1_test /var/lib/awe-e1-test "$base"
install -d -m 0770 -o awe_e1_test -g awe_e1_test "$socket"
install -d -m 0700 -o awe_e1_test -g awe_e1_test "$base/log" "$base/backup"
printf '%s\n' '{"schema":"awe.e1.resource-marker/1","resource_id":"awe_e1_a2a3_20261108","port":5433,"database":"awe_e1_test","owner_scope":"LOCAL_TEST_ONLY","e0_access":"DENIED"}' > "$base/RESOURCE.json"
chown awe_e1_test:awe_e1_test "$base/RESOURCE.json"
chmod 0640 "$base/RESOURCE.json"
runuser -u awe_e1_test -- "$bin/initdb" -D "$cluster" --username=awe_e1_test --auth-local=peer --auth-host=scram-sha-256 --encoding=UTF8 --locale=C --no-instructions </dev/null
cat >> "$cluster/postgresql.conf" <<EOF
listen_addresses = '127.0.0.1'
port = 5433
unix_socket_directories = '$socket'
unix_socket_permissions = 0770
max_connections = 20
shared_buffers = '64MB'
work_mem = '4MB'
maintenance_work_mem = '32MB'
temp_file_limit = '128MB'
max_wal_size = '256MB'
min_wal_size = '80MB'
max_worker_processes = 2
max_parallel_workers = 0
jit = off
fsync = on
synchronous_commit = on
full_page_writes = on
logging_collector = on
log_directory = '$base/log'
log_filename = 'postgresql.log'
log_statement = 'none'
log_min_error_statement = 'panic'
log_connections = off
log_disconnections = off
EOF
cat > "$cluster/pg_hba.conf" <<'EOF'
# Isolated E1 test resource. Same Unix identity required; TCP denied.
local all all peer
host all all 127.0.0.1/32 reject
host all all ::1/128 reject
EOF
runuser -u awe_e1_test -- "$bin/pg_ctl" -D "$cluster" -l "$base/log/startup.log" -w -t 20 start </dev/null
runuser -u awe_e1_test -- "$bin/psql" -X -v ON_ERROR_STOP=1 -h "$socket" -p 5433 -U awe_e1_test -d postgres <<'SQL'
CREATE ROLE awe_e1_coord LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOINHERIT;
CREATE ROLE awe_e1_worker LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOINHERIT;
CREATE ROLE awe_e1_qa LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOINHERIT;
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
CREATE DATABASE awe_e1_test OWNER awe_e1_test;
REVOKE CONNECT ON DATABASE awe_e1_test FROM PUBLIC;
GRANT CONNECT ON DATABASE awe_e1_test TO awe_e1_test,awe_e1_coord,awe_e1_worker,awe_e1_qa;
\connect awe_e1_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA awe_e1_resource AUTHORIZATION awe_e1_test;
REVOKE ALL ON SCHEMA awe_e1_resource FROM PUBLIC;
CREATE TABLE awe_e1_resource.identity(resource_id text PRIMARY KEY,port integer NOT NULL,database_name name NOT NULL,scope text NOT NULL);
INSERT INTO awe_e1_resource.identity VALUES ('awe_e1_a2a3_20261108',5433,'awe_e1_test','LOCAL_TEST_ONLY');
GRANT USAGE ON SCHEMA awe_e1_resource TO awe_e1_coord,awe_e1_worker,awe_e1_qa;
GRANT SELECT ON awe_e1_resource.identity TO awe_e1_coord,awe_e1_worker,awe_e1_qa;
SQL
python3 - <<'PY'
import json,os,hashlib,subprocess
base='/var/lib/awe-e1-test/awe_e1_a2a3_20261108'
old=json.load(open('/tmp/awe-e1-preflight-control/processes.json'))
now={int(x.strip().split()[0]):hashlib.sha256(x.encode()).hexdigest() for x in subprocess.check_output(['ps','-eo','pid,lstart,args'],text=True).splitlines()[1:]}
assert all(now.get(x['pid'])==x['line_sha256'] for x in old),'PREEXISTING_POSTGRES_PROCESS_CHANGED'
e0=json.load(open(os.environ['E0_PRIVATE_METADATA']))
readable=subprocess.run(['runuser','-u','awe_e1_test','--','test','-r',e0['data']+'/PG_VERSION']).returncode==0
assert not readable,'E0_DATA_READABLE_TO_E1'
r={'schema':'awe.e1.provision-result/1','resource_id':'awe_e1_a2a3_20261108','status':'RUNNING','port':5433,'database':'awe_e1_test','postgres_version':'18.6','separate_unix_principals':4,'preexisting_postgres_processes_unchanged':len(old),'e0_data_access_denied':True,'e0_connections':0,'tcp':'LOOPBACK_LISTEN_AUTH_REJECT_ALL','authentication':'UNIX_PEER_MATCHING_PRINCIPAL','pgdata_in_git':False}
open(base+'/provision-result.json','w').write(json.dumps(r))
os.chmod(base+'/provision-result.json',0o640)
print(json.dumps(r))
PY
