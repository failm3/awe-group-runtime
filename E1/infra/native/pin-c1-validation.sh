#!/usr/bin/env bash
set -euo pipefail
# Authorized E1 test resource only. Does not restart any cluster or access E0.
test "$(id -u)" = 0
repo=$(realpath -- "${1:?Pass the clean runtime repository path}")
base=/var/lib/awe-e1-test/awe_e1_a2a3_20261108
socket="$base/socket"
bin=/usr/lib/postgresql/18/bin
test "$(readlink -f "$base/pgdata")" = "$base/pgdata"
test "$(stat -c %U "$base/pgdata")" = awe_e1_test
test "$(cat "$base/pgdata/PG_VERSION")" = 18
sql="$repo/E1/infra/migrations/0001-infra-expand.sql"
pin=$(sha256sum "$sql" | cut -d ' ' -f 1)
test ${#pin} = 64
pg(){ /usr/sbin/runuser -u awe_e1_test -- "$bin/psql" -X -v ON_ERROR_STOP=1 -h "$socket" -p 5433 -U awe_e1_test "$@"; }
test "$(pg -A -t -d awe_e1_test -c "SELECT resource_id FROM awe_e1_resource.identity WHERE port=5433 AND database_name=current_database()")" = awe_e1_a2a3_20261108
pg -d awe_e1_c1_probe -v pin="sha256:$pin" <<'SQL'
UPDATE awe_e1_infra.schema_history SET migration_digest=:'pin'
 WHERE migration_version='0001' AND migration_digest IN (:'pin','sha256:0000000000000000000000000000000000000000000000000000000000000000');
SQL
test "$(pg -A -t -d awe_e1_c1_probe -c "SELECT migration_digest FROM awe_e1_infra.schema_history WHERE migration_version='0001'")" = "sha256:$pin"
pg -d postgres <<'SQL'
CREATE DATABASE awe_e1_c1_pin_restore OWNER awe_e1_test;
REVOKE CONNECT ON DATABASE awe_e1_c1_pin_restore FROM PUBLIC;
SQL
/usr/sbin/runuser -u awe_e1_test -- "$bin/pg_dump" -h "$socket" -p 5433 -U awe_e1_test -d awe_e1_c1_probe -Fc -f "$base/backup/c1-probe-pinned.dump"
/usr/sbin/runuser -u awe_e1_test -- "$bin/pg_restore" -h "$socket" -p 5433 -U awe_e1_test -d awe_e1_c1_pin_restore --exit-on-error "$base/backup/c1-probe-pinned.dump"
test "$(pg -A -t -d awe_e1_c1_pin_restore -c "SELECT migration_digest FROM awe_e1_infra.schema_history WHERE migration_version='0001'")" = "sha256:$pin"
before=$(pg -A -t -d awe_e1_c1_probe -c "SELECT md5(string_agg(row_to_json(t)::text,',' ORDER BY id)) FROM e1_validation.test_records t")
after=$(pg -A -t -d awe_e1_c1_pin_restore -c "SELECT md5(string_agg(row_to_json(t)::text,',' ORDER BY id)) FROM e1_validation.test_records t")
test "$before" = "$after"
export E1_PIN="$pin" E1_DATA_DIGEST="$before"
python3 - <<'PY'
import json,os,datetime,hashlib,subprocess
base='/var/lib/awe-e1-test/awe_e1_a2a3_20261108'
prior=json.load(open('/tmp/awe-e1-preflight-control/processes.json'))
now={int(x.strip().split()[0]):hashlib.sha256(x.encode()).hexdigest() for x in subprocess.check_output(['ps','-eo','pid,lstart,args'],text=True).splitlines()[1:]}
assert all(now.get(x['pid'])==x['line_sha256'] for x in prior)
r={'schema':'awe.e1.c1-pinned-restore/1','status':'PASS','checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'migration_digest':'sha256:'+os.environ['E1_PIN'],'migration_metadata_matches_source':True,'restored_metadata_matches_source':True,'test_dataset_digest':os.environ['E1_DATA_DIGEST'],'test_rows':2,'backup_bytes':os.stat(base+'/backup/c1-probe-pinned.dump').st_size,'preexisting_pg_processes_unchanged':len(prior),'cluster_restarts_this_check':0,'e0_connections':0,'pgdata_published':False}
open(base+'/c1-pinned-restore.json','w').write(json.dumps(r))
print(json.dumps(r))
PY
