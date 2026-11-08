import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {check} from './errors.mjs';
async function verifyMigrationResource(db) {
  check(db?.kind === 'NATIVE_POSTGRESQL_PSQL_SESSION' && db.role === 'admin','A2_MIGRATION_ADMIN_REQUIRED');
  // Check the host's preexisting identity before any historical0001 statement.
  // Bootstrap sessions may deliberately have verify_marker:false; that must
  // never turn a matching database/port alone into permission to apply DDL.
  const identity=JSON.parse(await db.query("SELECT jsonb_build_object('database',current_database(),'role',session_user,'port',current_setting('port')::int,'pgdata',current_setting('data_directory'),'socket_directory',current_setting('unix_socket_directories'),'identity',(SELECT to_jsonb(i) FROM awe_e1_resource.identity i WHERE resource_id='awe_e1_a2a3_20261108'));"));
  check(identity.database==='awe_e1_test'&&identity.role==='awe_e1_test'&&identity.port===5433&&identity.pgdata==='/var/lib/awe-e1-test/awe_e1_a2a3_20261108/pgdata'&&identity.socket_directory==='/var/lib/awe-e1-test/awe_e1_a2a3_20261108/socket'&&identity.identity?.resource_id==='awe_e1_a2a3_20261108'&&identity.identity?.database_name==='awe_e1_test'&&identity.identity?.port===5433&&identity.identity?.scope==='LOCAL_TEST_ONLY','A2_MIGRATION_RESOURCE_DENIED');
}
export async function applyCloudAccountingMigration(db) {
  await verifyMigrationResource(db);
  const file='0003-cloud-accounting.sql',bytes=fs.readFileSync(new URL('./migrations/'+file,import.meta.url));
  await db.query(bytes.toString('utf8'));
  return {version:3,file,sha256:createHash('sha256').update(bytes).digest('hex')};
}
export async function applyCloudAuthorizationMigration(db) {
  await verifyMigrationResource(db);
  const file='0004-cloud-authorization.sql',bytes=fs.readFileSync(new URL('./migrations/'+file,import.meta.url));
  await db.query(bytes.toString('utf8'));
  return {version:4,file,sha256:createHash('sha256').update(bytes).digest('hex')};
}
export async function applyCloudScopeAmendmentMigration(db) {
  await verifyMigrationResource(db);
  const file='0005-cloud-scope-amendment.sql',bytes=fs.readFileSync(new URL('./migrations/'+file,import.meta.url));
  await db.query(bytes.toString('utf8'));
  return {version:5,file,sha256:createHash('sha256').update(bytes).digest('hex')};
}
export async function applyCloudScopeLockOrderMigration(db) {
  await verifyMigrationResource(db);
  const file='0006-cloud-scope-lock-order.sql',bytes=fs.readFileSync(new URL('./migrations/'+file,import.meta.url));
  await db.query(bytes.toString('utf8'));
  return {version:6,file,sha256:createHash('sha256').update(bytes).digest('hex')};
}
export async function applyCoordinatorMigrations(db) {
  await verifyMigrationResource(db);
  const results=[];
  for(const [index,name] of ['0001-durable-runtime.sql','0002-local-model-quiescence.sql','0003-cloud-accounting.sql','0004-cloud-authorization.sql','0005-cloud-scope-amendment.sql','0006-cloud-scope-lock-order.sql'].entries()) {
    const bytes=fs.readFileSync(new URL('./migrations/'+name,import.meta.url));await db.query(bytes.toString('utf8'));
    results.push({version:index+1,file:name,sha256:createHash('sha256').update(bytes).digest('hex')});
  }
  return results;
}
