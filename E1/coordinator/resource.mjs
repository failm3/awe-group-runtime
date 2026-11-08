import {check} from './errors.mjs';
import {canonicalize} from '../contracts/index.mjs';

// This descriptor is supplied by the host's resource handoff, never by a job.
// Pinning this one bounded local staging resource prevents accidental E0 access.
export function validateResourceDescriptor(value) {
  canonicalize(value);
  const exact = (v, keys) => check(v && Object.keys(v).sort().join(',') === keys.sort().join(','), 'A2_RESOURCE_FIELDS');
  exact(value, ['schema', 'composition', 'resource_id', 'distro', 'port', 'database', 'socket_directory', 'pgdata', 'psql', 'roles']);
  check(value.schema === 'awe.e1.pg-resource/1' && value.composition === 'AWE_E1', 'A2_RESOURCE_SCHEMA');
  check(value.resource_id === 'awe_e1_a2a3_20261108' && value.distro === 'Ubuntu', 'A2_RESOURCE_ID');
  check(value.port === 5433 && value.database === 'awe_e1_test', 'A2_RESOURCE_ENDPOINT');
  const root = '/var/lib/awe-e1-test/' + value.resource_id;
  check(value.pgdata === root + '/pgdata' && value.socket_directory === root + '/socket' && value.psql === '/usr/lib/postgresql/18/bin/psql', 'A2_RESOURCE_PATH');
  exact(value.roles, ['admin', 'coordinator', 'worker', 'qa']);
  const expected = {admin: 'awe_e1_test', coordinator: 'awe_e1_coord', worker: 'awe_e1_worker', qa: 'awe_e1_qa'};
  for (const [role, name] of Object.entries(expected)) { exact(value.roles[role], ['linux_user', 'database_role']); check(value.roles[role].linux_user === name && value.roles[role].database_role === name, 'A2_RESOURCE_ROLE'); }
  const copy = structuredClone(value);
  for (const item of Object.values(copy.roles)) Object.freeze(item);
  Object.freeze(copy.roles); return Object.freeze(copy);
}

export function psqlInvocation(input, role = 'coordinator') {
  const resource = validateResourceDescriptor(input);
  check(Object.hasOwn(resource.roles, role), 'A2_RESOURCE_ROLE');
  const principal = resource.roles[role];
  return {resource, executable: 'wsl.exe', args: ['--distribution', resource.distro, '--user', 'root', '--exec', '/usr/sbin/runuser', '--user', principal.linux_user, '--', resource.psql,
    '--no-psqlrc', '--no-password', '--quiet', '--tuples-only', '--no-align', '--set', 'ON_ERROR_STOP=on',
    '--host', resource.socket_directory, '--port', String(resource.port), '--dbname', resource.database, '--username', principal.database_role]};
}
