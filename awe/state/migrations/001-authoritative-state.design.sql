-- D-03 DESIGN ONLY / E0. NOT EXECUTED OR SQL-VALIDATED. No connection/runner.
-- Select/review the PostgreSQL version, migration identity and D-02 roles first.
-- No policy/approval/ledger/artifact tables owned by other packages are created here.
BEGIN;
CREATE SCHEMA awe_state_d03;

CREATE TABLE awe_state_d03.projects (
  project_id text PRIMARY KEY CHECK (project_id ~ '^prj_[a-z0-9][a-z0-9_-]{0,63}$'),
  name text NOT NULL, config_owner text NOT NULL,
  status text NOT NULL CHECK (status IN ('PROVISIONING','READY','PAUSED','ARCHIVED','ERROR')),
  revision bigint NOT NULL DEFAULT 0 CHECK (revision BETWEEN 0 AND 9007199254740991),
  config_revision bigint NOT NULL CHECK (config_revision > 0),
  policy_epoch bigint NOT NULL CHECK (policy_epoch > 0),
  auth_epoch bigint NOT NULL CHECK (auth_epoch > 0),
  stop_epoch bigint NOT NULL CHECK (stop_epoch >= 0),
  owner_epoch bigint NOT NULL CHECK (owner_epoch > 0),
  stream_id text NOT NULL, sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
  creation_hash text NOT NULL, qa02_receipt text,
  CHECK (status <> 'READY' OR qa02_receipt IS NOT NULL),
  UNIQUE (project_id, stream_id)
);
CREATE TABLE awe_state_d03.config_versions (
  project_id text NOT NULL REFERENCES awe_state_d03.projects(project_id),
  config_revision bigint NOT NULL, config_owner text NOT NULL,
  content_hash text NOT NULL, content jsonb NOT NULL,
  PRIMARY KEY (project_id, config_revision)
);
ALTER TABLE awe_state_d03.projects ADD CONSTRAINT current_config_fk
  FOREIGN KEY (project_id, config_revision) REFERENCES awe_state_d03.config_versions
  DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE awe_state_d03.provision_ops (
  project_id text PRIMARY KEY REFERENCES awe_state_d03.projects(project_id),
  operation_id text NOT NULL, phase text NOT NULL, recovery_required boolean NOT NULL DEFAULT false,
  resource_manifest jsonb NOT NULL, UNIQUE (project_id, operation_id)
);
CREATE TABLE awe_state_d03.spec_revisions (
  project_id text NOT NULL REFERENCES awe_state_d03.projects(project_id),
  spec_id text NOT NULL, spec_revision bigint NOT NULL CHECK (spec_revision > 0),
  content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[a-f0-9]{64}$'),
  content jsonb NOT NULL, dto jsonb NOT NULL,
  PRIMARY KEY (project_id, spec_id, spec_revision),
  UNIQUE (project_id, spec_id, spec_revision, content_hash)
);
CREATE TABLE awe_state_d03.tasks (
  project_id text NOT NULL REFERENCES awe_state_d03.projects(project_id),
  task_id text NOT NULL CHECK (task_id ~ '^task_[a-z0-9][a-z0-9_-]{0,63}$'),
  name text NOT NULL, control_operation_id text NOT NULL,
  spec_id text NOT NULL, spec_revision bigint NOT NULL, spec_hash text NOT NULL,
  config_revision bigint NOT NULL,
  state text NOT NULL CHECK (state IN ('DRAFT','READY','RUNNING','QA_PENDING','REWORK','PERSISTING',
    'RECONCILING','WAITING_FOR_EVENT','WAITING_FOR_OWNER','BLOCKED','COMPLETE','CANCELLING','CANCELLED','FAILED')),
  revision bigint NOT NULL DEFAULT 0 CHECK (revision BETWEEN 0 AND 9007199254740991),
  lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
  fence bigint NOT NULL DEFAULT 0 CHECK (fence >= 0),
  lease_holder text, lease_expires_at timestamptz,
  cancel_requested boolean NOT NULL DEFAULT false, resume_state text,
  wait_subscription_id text, checkpoint_hash text,
  rework_count integer NOT NULL DEFAULT 0 CHECK (rework_count BETWEEN 0 AND 1),
  supersedes_task_id text, acceptance_stale boolean NOT NULL DEFAULT false,
  PRIMARY KEY (project_id, task_id),
  FOREIGN KEY (project_id, spec_id, spec_revision, spec_hash) REFERENCES awe_state_d03.spec_revisions
    (project_id, spec_id, spec_revision, content_hash),
  FOREIGN KEY (project_id, config_revision) REFERENCES awe_state_d03.config_versions,
  FOREIGN KEY (project_id, supersedes_task_id) REFERENCES awe_state_d03.tasks,
  CHECK ((lease_holder IS NULL) = (lease_expires_at IS NULL)),
  CHECK (NOT cancel_requested OR state IN ('CANCELLING','CANCELLED','RECONCILING'))
);
CREATE TABLE awe_state_d03.operation_scopes (
  project_id text NOT NULL, task_id text NOT NULL, operation_id text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('CONTROL','EFFECT')),
  PRIMARY KEY (project_id, operation_id), UNIQUE (project_id, task_id, operation_id),
  FOREIGN KEY (project_id, task_id) REFERENCES awe_state_d03.tasks
);
CREATE UNIQUE INDEX one_control_scope ON awe_state_d03.operation_scopes(project_id, task_id) WHERE kind = 'CONTROL';
ALTER TABLE awe_state_d03.tasks ADD CONSTRAINT control_scope_fk
  FOREIGN KEY (project_id, task_id, control_operation_id) REFERENCES awe_state_d03.operation_scopes
  (project_id, task_id, operation_id) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE awe_state_d03.dag_edges (
  project_id text NOT NULL, task_id text NOT NULL, dependency_id text NOT NULL,
  PRIMARY KEY (project_id, task_id, dependency_id), CHECK (task_id <> dependency_id),
  FOREIGN KEY (project_id, task_id) REFERENCES awe_state_d03.tasks,
  FOREIGN KEY (project_id, dependency_id) REFERENCES awe_state_d03.tasks
);
CREATE TABLE awe_state_d03.operations (
  project_id text NOT NULL, task_id text NOT NULL, operation_id text NOT NULL,
  payload_hash text NOT NULL, tool_id text NOT NULL, tool_digest text NOT NULL,
  action text NOT NULL, resource text NOT NULL, approval_ref text,
  spec_ref jsonb NOT NULL, epochs jsonb NOT NULL,
  effect_class text NOT NULL CHECK (effect_class IN ('READ_ONLY','IDEMPOTENT_WRITE','NON_IDEMPOTENT')),
  status text NOT NULL CHECK (status IN ('INTENT','DISPATCHED','CONFIRMED','OUTCOME_UNKNOWN','RECONCILED','ABORTED')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 2),
  retry_authorized boolean NOT NULL DEFAULT false,
  retained_reservation boolean NOT NULL DEFAULT false,
  reservation_micros numeric(30,0), resolution jsonb,
  PRIMARY KEY (project_id, operation_id),
  FOREIGN KEY (project_id, task_id, operation_id) REFERENCES awe_state_d03.operation_scopes
    (project_id, task_id, operation_id),
  UNIQUE (project_id, task_id, action, resource, payload_hash, tool_id, tool_digest),
  CHECK (status <> 'OUTCOME_UNKNOWN' OR (retained_reservation AND NOT retry_authorized)),
  CHECK (effect_class <> 'NON_IDEMPOTENT' OR NOT retry_authorized)
);
CREATE TABLE awe_state_d03.effect_receipts (
  project_id text NOT NULL, operation_id text NOT NULL, receipt_id text NOT NULL,
  body_hash text NOT NULL, dto jsonb NOT NULL,
  PRIMARY KEY (project_id, receipt_id),
  FOREIGN KEY (project_id, operation_id) REFERENCES awe_state_d03.operations
);
CREATE TABLE awe_state_d03.events (
  project_id text NOT NULL, stream_id text NOT NULL, sequence bigint NOT NULL CHECK (sequence > 0),
  event_id text NOT NULL, task_id text NOT NULL, operation_id text NOT NULL,
  dto jsonb NOT NULL, payload_hash text NOT NULL, payload jsonb NOT NULL,
  PRIMARY KEY (project_id, event_id), UNIQUE (project_id, stream_id, sequence),
  FOREIGN KEY (project_id, stream_id) REFERENCES awe_state_d03.projects (project_id, stream_id),
  FOREIGN KEY (project_id, task_id, operation_id) REFERENCES awe_state_d03.operation_scopes
    (project_id, task_id, operation_id),
  CHECK (dto->>'schema_version' = '1.0.0' AND dto->>'source_version' = '1.0.0')
);
CREATE TABLE awe_state_d03.transitions (
  project_id text NOT NULL, task_id text NOT NULL, from_revision bigint NOT NULL,
  event_id text NOT NULL, dto jsonb NOT NULL,
  PRIMARY KEY (project_id, task_id, from_revision), UNIQUE (project_id, event_id),
  FOREIGN KEY (project_id, task_id) REFERENCES awe_state_d03.tasks,
  FOREIGN KEY (project_id, event_id) REFERENCES awe_state_d03.events DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE awe_state_d03.idempotency_keys (
  project_id text NOT NULL REFERENCES awe_state_d03.projects(project_id),
  key text NOT NULL, payload_hash text NOT NULL, result jsonb NOT NULL,
  PRIMARY KEY (project_id, key)
);
CREATE TABLE awe_state_d03.owner_actions (
  project_id text NOT NULL, task_id text NOT NULL, operation_id text NOT NULL, owner_action_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('OPEN','SUBMITTED','VERIFYING','VERIFIED','REJECTED','EXPIRED','REVOKED')),
  uses integer NOT NULL CHECK (uses BETWEEN 0 AND 1), expires_at timestamptz NOT NULL,
  dto jsonb NOT NULL,
  PRIMARY KEY (project_id, owner_action_id),
  FOREIGN KEY (project_id, task_id, operation_id) REFERENCES awe_state_d03.operation_scopes
    (project_id, task_id, operation_id)
);
CREATE TABLE awe_state_d03.subscriptions (
  project_id text NOT NULL, task_id text NOT NULL, operation_id text NOT NULL, subscription_id text NOT NULL,
  owner_action_id text, event_id text, deadline timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE','SIGNALLED','CONSUMED','CANCELLED','EXPIRED','REVOKED')),
  dto jsonb NOT NULL,
  PRIMARY KEY (project_id, subscription_id),
  FOREIGN KEY (project_id, task_id, operation_id) REFERENCES awe_state_d03.operation_scopes
    (project_id, task_id, operation_id),
  FOREIGN KEY (project_id, owner_action_id) REFERENCES awe_state_d03.owner_actions,
  FOREIGN KEY (project_id, event_id) REFERENCES awe_state_d03.events
);
CREATE UNIQUE INDEX one_active_wait ON awe_state_d03.subscriptions(project_id, task_id) WHERE status IN ('ACTIVE','SIGNALLED');
CREATE TABLE awe_state_d03.inbox (
  project_id text NOT NULL REFERENCES awe_state_d03.projects(project_id),
  consumer_key text NOT NULL, event_id text NOT NULL, body_hash text NOT NULL,
  status text NOT NULL, accepted_revision bigint,
  PRIMARY KEY (project_id, consumer_key, event_id)
);
CREATE TABLE awe_state_d03.checkpoints (
  project_id text NOT NULL, task_id text NOT NULL, content_hash text NOT NULL,
  revision bigint NOT NULL, fence bigint NOT NULL, body jsonb NOT NULL,
  PRIMARY KEY (project_id, content_hash), UNIQUE (project_id, task_id, content_hash),
  FOREIGN KEY (project_id, task_id) REFERENCES awe_state_d03.tasks
);
ALTER TABLE awe_state_d03.tasks ADD CONSTRAINT checkpoint_fk
  FOREIGN KEY (project_id, task_id, checkpoint_hash) REFERENCES awe_state_d03.checkpoints
    (project_id, task_id, content_hash) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE awe_state_d03.outbox (
  project_id text NOT NULL REFERENCES awe_state_d03.projects(project_id),
  key text NOT NULL, task_id text, kind text NOT NULL, body jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('PENDING','SENT','ACKNOWLEDGED','CANCELLED')),
  checkpoint_hash text, delivery_fence bigint NOT NULL DEFAULT 0, attempts bigint NOT NULL DEFAULT 0,
  lease_holder text, lease_expires_at timestamptz,
  PRIMARY KEY (project_id, key),
  FOREIGN KEY (project_id, task_id, checkpoint_hash) REFERENCES awe_state_d03.checkpoints
    (project_id, task_id, content_hash),
  CHECK (kind <> 'final-report' OR (checkpoint_hash IS NOT NULL AND task_id IS NOT NULL))
);

CREATE FUNCTION awe_state_d03.reject_history_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'immutable authoritative history'; END;
$$;
DO $$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['config_versions','spec_revisions','events','transitions','effect_receipts','checkpoints'] LOOP
    EXECUTE format('CREATE TRIGGER immutable_history BEFORE UPDATE OR DELETE ON awe_state_d03.%I FOR EACH ROW EXECUTE FUNCTION awe_state_d03.reject_history_mutation()', table_name);
  END LOOP;
END $$;

-- Template only. D-02 must select service roles and prove current context cannot be forged.
-- Workers get no SQL access. A project_id setting alone is NOT authentication.
DO $$ DECLARE table_name text; BEGIN
  FOR table_name IN SELECT tablename FROM pg_tables WHERE schemaname = 'awe_state_d03' LOOP
    EXECUTE format('ALTER TABLE awe_state_d03.%I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE awe_state_d03.%I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format('CREATE POLICY project_scope ON awe_state_d03.%I USING (project_id = current_setting(''awe.project_id'', true)) WITH CHECK (project_id = current_setting(''awe.project_id'', true))', table_name);
  END LOOP;
END $$;
REVOKE ALL ON SCHEMA awe_state_d03 FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA awe_state_d03 FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA awe_state_d03 FROM PUBLIC;
COMMIT;
