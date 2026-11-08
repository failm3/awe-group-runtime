import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {digest} from '../../contracts/canonical.mjs';
import {validateInfraConfig} from './config.mjs';
import {byteDigest} from './storage.mjs';
import {deepFreeze} from './errors.mjs';

// Text-only plan. Deliberately no SQL executor, PG import or connection method.
export function migrationPlan(input) {
  const config = validateInfraConfig(input);
  const files = ['0001-infra-expand.sql', '0001-infra-rollback.sql'].map(name => {
    const bytes = fs.readFileSync(fileURLToPath(new URL('./migrations/' + name, import.meta.url)));
    return {name, digest: byteDigest(bytes), bytes: bytes.byteLength};
  });
  const body = {schema: 'awe-e1.migration-plan.v1', composition: 'AWE_E1', migration_version: '0001',
    database_name: config.database.name, schema_name: config.database.schema, files,
    execution: 'BLOCKED', migration_test: 'NOT_RUN', postgres_restore_test: 'NOT_RUN',
    blockers: ['E1_POSTGRESQL_NOT_AUTHORIZED', 'REAL_DATABASE_GRANTS_NOT_PROVISIONED'],
    strategy: ['EXPAND_ONLY', 'DRAIN_BEFORE_BINARY_CHANGE', 'PRESERVE_D03_D09_AND_OUTBOX', 'NO_AUTOMATIC_DATA_DOWNGRADE', 'RESTORE_TO_NEW_FENCED_NAMESPACE_THEN_RECONCILE'],
    required_owner_scope: ['NEW_E1_DATABASE_AND_PGDATA', 'E1_MIGRATION_AND_RESTORE', 'SEPARATE_OS_AND_DB_PRINCIPALS'],
    runtime_database_connections: 0, live_ready: false};
  return deepFreeze({...body, plan_digest: digest(body)});
}
