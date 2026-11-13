import test from 'node:test';
import assert from 'node:assert/strict';
import {validateResourceDescriptor,psqlInvocation,createAdmissionBridge,applyCoordinatorMigrations} from '../../coordinator/index.mjs';
const resource={schema:'awe.e1.pg-resource/1',composition:'AWE_E1',resource_id:'awe_e1_a2a3_20261108',distro:'Ubuntu',port:5433,database:'awe_e1_test',socket_directory:'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/socket',pgdata:'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/pgdata',psql:'/usr/lib/postgresql/18/bin/psql',roles:Object.fromEntries(Object.entries({admin:'awe_e1_test',coordinator:'awe_e1_coord',worker:'awe_e1_worker',qa:'awe_e1_qa'}).map(([role,name])=>[role,{linux_user:name,database_role:name}]))};
test('resource spoofing is rejected before any process is spawned',()=>{
  validateResourceDescriptor(resource);
  for(const mutation of [r=>r.port=55582,r=>r.port=5432,r=>r.distro='Ubuntu-E0',r=>r.database='postgres',r=>r.pgdata='/tmp/92ef/pgdata',r=>r.socket_directory='/tmp/../socket',r=>r.roles.coordinator.database_role='awe_e1_test',r=>r.psql='/bin/sh',r=>r.extra='spoof']){const copy=structuredClone(resource);mutation(copy);assert.throws(()=>psqlInvocation(copy),error=>error.code.startsWith('A2_RESOURCE_'));}
  const command=psqlInvocation(resource);assert.ok(command.args.includes('/usr/sbin/runuser'));assert.ok(command.args.includes('awe_e1_coord'));assert.equal(command.args.includes('5432'),false);
});
test('A1 publication JSON cannot create an admission authority',()=>{
  assert.throws(()=>createAdmissionBridge({authenticate:()=>({})}),{code:'A2_TRUSTED_ADMISSION_PORTS'});
});
test('migration boundary rejects a foreign native identity before sending any DDL',async()=>{
  // Explicit offline recording port: no real connection or SQL execution.
  const expected={database:'awe_e1_test',role:'awe_e1_test',port:5433,pgdata:resource.pgdata,socket_directory:resource.socket_directory,identity:{resource_id:resource.resource_id,database_name:'awe_e1_test',port:5433,scope:'LOCAL_TEST_ONLY'}};
  for(const mutate of [r=>r.pgdata='/historical/e0/pgdata',r=>r.socket_directory='/tmp/foreign',r=>r.identity.resource_id='foreign',r=>r.identity.database_name='postgres',r=>r.identity.port=55582,r=>r.role='awe_e1_coord']){
    const calls=[],identity=structuredClone(expected);mutate(identity);const offlinePort={kind:'NATIVE_POSTGRESQL_PSQL_SESSION',role:'admin',async query(sql){calls.push(sql);return JSON.stringify(identity);}};
    await assert.rejects(()=>applyCoordinatorMigrations(offlinePort),{code:'A2_MIGRATION_RESOURCE_DENIED'});assert.equal(calls.length,1);assert.ok(calls[0].startsWith('SELECT jsonb_build_object'));assert.equal(calls[0].includes('CREATE TABLE'),false);
  }
});
