-- AWE_E1 C1 proposal, NOT EXECUTED / PostgreSQL runtime BLOCKED.
-- The separately authorized runner must bind DATABASE/PROJECT/PGDATA and verify
-- an empty dedicated E1 database before opening a connection. This is NOT a
-- standalone bootstrap command and creates no roles, database, queue or ledger.
BEGIN;
DO $guard$
BEGIN
  IF current_database() !~ '^awe_e1_[a-z0-9_]+$'
     OR current_setting('awe.composition', true) IS DISTINCT FROM 'AWE_E1'
     OR current_setting('awe.migration_authorized', true) IS DISTINCT FROM 'E1_ONLY'
  THEN RAISE EXCEPTION 'C1_E1_DATABASE_SCOPE_REQUIRED'; END IF;
END;
$guard$;
CREATE SCHEMA IF NOT EXISTS awe_e1_infra;
REVOKE ALL ON SCHEMA awe_e1_infra FROM PUBLIC;
CREATE TABLE IF NOT EXISTS awe_e1_infra.schema_history (
  migration_version text PRIMARY KEY CHECK (migration_version ~ '^[0-9]{4}$'),
  source_commit text NOT NULL CHECK (source_commit ~ '^[0-9a-f]{40}$'),
  migration_digest text NOT NULL CHECK (migration_digest ~ '^sha256:[0-9a-f]{64}$'),
  installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS awe_e1_infra.release_installations (
  release_digest text PRIMARY KEY CHECK (release_digest ~ '^sha256:[0-9a-f]{64}$'),
  source_commit text NOT NULL CHECK (source_commit ~ '^[0-9a-f]{40}$'),
  migration_version text NOT NULL REFERENCES awe_e1_infra.schema_history,
  state text NOT NULL CHECK (state IN ('STAGED', 'ACTIVE', 'DRAINED', 'ROLLED_BACK')),
  installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ALL TABLES IN SCHEMA awe_e1_infra FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA awe_e1_infra REVOKE ALL ON TABLES FROM PUBLIC;
-- No application roles/grants are invented here. Missing roles remain denied.
-- The authorized migration adapter records its externally pinned digest; this
-- template cannot self-sign a release or infer its own bytes' digest.
COMMIT;
