-- PostgreSQL 16+. Execute only in a fresh disposable database as its bootstrap admin.
-- Roles are cluster objects: collisions intentionally fail rather than reusing unknown roles.
BEGIN;
SET LOCAL lock_timeout = '5s';
CREATE ROLE awe_d09_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE awe_d09_api NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE awe_d09_reconciler NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE awe_d09_issuer NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE awe_d09_reader NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE SCHEMA awe_d09 AUTHORIZATION awe_d09_owner;
SET LOCAL ROLE awe_d09_owner;
REVOKE ALL ON SCHEMA awe_d09 FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA awe_d09 REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
CREATE TABLE awe_d09.schema_version(version integer PRIMARY KEY CHECK(version=1));
INSERT INTO awe_d09.schema_version VALUES (1);
-- These two control-plane tables have no client privileges. Only the trusted issuer
-- importer/DBA provisions them. A caller-set tenant/actor GUC is never consulted.
CREATE TABLE awe_d09.principals (
  login name PRIMARY KEY, actor_id text NOT NULL UNIQUE,
  issuer_ref text NOT NULL CHECK(length(issuer_ref)>0),
  valid_until timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false
);
CREATE TABLE awe_d09.projects (
  project_id text PRIMARY KEY CHECK(project_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  auth_epoch bigint NOT NULL DEFAULT 1 CHECK(auth_epoch>0),
  policy_epoch bigint NOT NULL DEFAULT 1 CHECK(policy_epoch>0),
  owner_epoch bigint NOT NULL DEFAULT 1 CHECK(owner_epoch>0),
  stop_epoch bigint NOT NULL DEFAULT 1 CHECK(stop_epoch>0),
  halted boolean NOT NULL DEFAULT false, restore_pending boolean NOT NULL DEFAULT false
);
CREATE TABLE awe_d09.memberships (
  project_id text REFERENCES awe_d09.projects, login name REFERENCES awe_d09.principals,
  permissions text[] NOT NULL CHECK(permissions <@ ARRAY['READ','EXECUTE','RECONCILE','ISSUE']),
  PRIMARY KEY(project_id,login)
);
CREATE TABLE awe_d09.origins (
  project_id text REFERENCES awe_d09.projects, origin_id text NOT NULL,
  quarantined boolean NOT NULL DEFAULT false, PRIMARY KEY(project_id,origin_id)
);
CREATE TABLE awe_d09.tasks (
  project_id text NOT NULL, task_id text NOT NULL, origin_id text NOT NULL,
  revision bigint NOT NULL CHECK(revision>0), fence bigint NOT NULL CHECK(fence>0),
  lease_holder name NOT NULL REFERENCES awe_d09.principals(login), lease_until timestamptz NOT NULL,
  cancelled boolean NOT NULL DEFAULT false,
  PRIMARY KEY(project_id,task_id),
  UNIQUE(project_id,task_id,origin_id),
  FOREIGN KEY(project_id,origin_id) REFERENCES awe_d09.origins
);
CREATE TABLE awe_d09.budgets (
  project_id text REFERENCES awe_d09.projects, budget_id text NOT NULL,
  kind text NOT NULL CHECK(kind IN ('PROJECT','TASK','ORIGIN','DAY','MONTH','ACCOUNT','ANCESTOR')),
  currency text NOT NULL CHECK(currency='RUB'),
  cap_micros numeric(30,0) NOT NULL CHECK(cap_micros>=0),
  balance_micros numeric(30,0) NOT NULL CHECK(balance_micros>=0),
  spent_micros numeric(30,0) NOT NULL DEFAULT 0 CHECK(spent_micros>=0),
  reserved_micros numeric(30,0) NOT NULL DEFAULT 0 CHECK(reserved_micros>=0),
  attempt_limit bigint NOT NULL CHECK(attempt_limit>=0),
  attempts_used bigint NOT NULL DEFAULT 0 CHECK(attempts_used>=0),
  valid_until timestamptz NOT NULL,
  PRIMARY KEY(project_id,budget_id),
  CHECK(spent_micros+reserved_micros<=cap_micros),
  CHECK(reserved_micros<=balance_micros), CHECK(attempts_used<=attempt_limit)
);
CREATE TABLE awe_d09.task_budgets (
  project_id text NOT NULL, task_id text NOT NULL, budget_id text NOT NULL,
  PRIMARY KEY(project_id,task_id,budget_id),
  FOREIGN KEY(project_id,task_id) REFERENCES awe_d09.tasks,
  FOREIGN KEY(project_id,budget_id) REFERENCES awe_d09.budgets
);
CREATE TABLE awe_d09.approvals (
  project_id text NOT NULL, approval_id text NOT NULL, task_id text NOT NULL,
  actor_id text NOT NULL REFERENCES awe_d09.principals(actor_id), operation_id text NOT NULL,
  effect_slot text NOT NULL, payload_hash text NOT NULL CHECK(payload_hash ~ '^sha256:[a-f0-9]{64}$'),
  plan_hash text NOT NULL CHECK(plan_hash ~ '^sha256:[a-f0-9]{64}$'),
  cap_micros numeric(30,0) NOT NULL CHECK(cap_micros>=0),
  expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false, used_by text,
  PRIMARY KEY(project_id,approval_id), FOREIGN KEY(project_id,task_id) REFERENCES awe_d09.tasks
);
CREATE TABLE awe_d09.grants (
  project_id text NOT NULL, grant_id text NOT NULL, approval_id text NOT NULL,
  actor_id text NOT NULL REFERENCES awe_d09.principals(actor_id),
  auth_epoch bigint NOT NULL, policy_epoch bigint NOT NULL, owner_epoch bigint NOT NULL, stop_epoch bigint NOT NULL,
  task_revision bigint NOT NULL, task_fence bigint NOT NULL,
  expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false,
  PRIMARY KEY(project_id,grant_id),
  FOREIGN KEY(project_id,approval_id) REFERENCES awe_d09.approvals
);
CREATE TABLE awe_d09.operations (
  project_id text NOT NULL, operation_id text NOT NULL, task_id text NOT NULL, origin_id text NOT NULL,
  effect_slot text NOT NULL, plan_hash text NOT NULL, payload_hash text NOT NULL,
  PRIMARY KEY(project_id,operation_id), UNIQUE(project_id,origin_id,effect_slot),
  FOREIGN KEY(project_id,task_id,origin_id) REFERENCES awe_d09.tasks(project_id,task_id,origin_id)
);
CREATE TABLE awe_d09.attempts (
  project_id text NOT NULL, attempt_id text NOT NULL, operation_id text NOT NULL,
  idempotency_key text NOT NULL, request jsonb NOT NULL, owner_login name NOT NULL REFERENCES awe_d09.principals,
  grant_id text NOT NULL,
  status text NOT NULL CHECK(status IN ('PROPOSED','ADMITTED','SENT','SETTLED','NOT_SENT','OUTCOME_UNKNOWN')),
  accounting_status text NOT NULL DEFAULT 'RESERVED' CHECK(accounting_status IN ('RESERVED','SETTLED','RELEASED','DISPUTED')),
  reserve_micros numeric(30,0) NOT NULL CHECK(reserve_micros>=0),
  actual_micros numeric(30,0) CHECK(actual_micros>=0),
  delivery_fence bigint NOT NULL DEFAULT 0 CHECK(delivery_fence>=0),
  delivery_holder name, delivery_until timestamptz, deadline timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(project_id,attempt_id), UNIQUE(project_id,idempotency_key), UNIQUE(project_id,operation_id),
  FOREIGN KEY(project_id,operation_id) REFERENCES awe_d09.operations,
  FOREIGN KEY(project_id,grant_id) REFERENCES awe_d09.grants,
  CHECK(accounting_status<>'SETTLED' OR actual_micros IS NOT NULL),
  CHECK(status<>'NOT_SENT' OR accounting_status='RELEASED')
);
ALTER TABLE awe_d09.approvals ADD CONSTRAINT approval_attempt_fk
  FOREIGN KEY(project_id,used_by) REFERENCES awe_d09.attempts DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE awe_d09.allocations (
  project_id text NOT NULL, attempt_id text NOT NULL, budget_id text NOT NULL,
  reserve_micros numeric(30,0) NOT NULL CHECK(reserve_micros>=0), closed boolean NOT NULL DEFAULT false,
  PRIMARY KEY(project_id,attempt_id,budget_id),
  FOREIGN KEY(project_id,attempt_id) REFERENCES awe_d09.attempts,
  FOREIGN KEY(project_id,budget_id) REFERENCES awe_d09.budgets
);
CREATE TABLE awe_d09.outbox (
  project_id text NOT NULL, attempt_id text NOT NULL,
  state text NOT NULL CHECK(state IN ('READY','CLAIMED','COMMITTED','QUARANTINED','CANCELLED')),
  PRIMARY KEY(project_id,attempt_id), FOREIGN KEY(project_id,attempt_id) REFERENCES awe_d09.attempts
);
CREATE TABLE awe_d09.invoices (
  project_id text NOT NULL, attempt_id text NOT NULL, provider text NOT NULL, invoice_id text NOT NULL,
  actual_micros numeric(30,0) NOT NULL CHECK(actual_micros>=0),
  input_tokens bigint NOT NULL CHECK(input_tokens>=0), output_tokens bigint NOT NULL CHECK(output_tokens>=0),
  evidence_hash text NOT NULL CHECK(evidence_hash ~ '^sha256:[a-f0-9]{64}$'), body jsonb NOT NULL,
  PRIMARY KEY(provider,invoice_id), UNIQUE(project_id,attempt_id),
  FOREIGN KEY(project_id,attempt_id) REFERENCES awe_d09.attempts
);
CREATE TABLE awe_d09.results (
  project_id text NOT NULL, attempt_id text NOT NULL, result text NOT NULL CHECK(result IN ('SUCCEEDED','FAILED','CANCELLED')),
  evidence_hash text NOT NULL CHECK(evidence_hash ~ '^sha256:[a-f0-9]{64}$'),
  PRIMARY KEY(project_id,attempt_id), FOREIGN KEY(project_id,attempt_id) REFERENCES awe_d09.attempts
);
CREATE TABLE awe_d09.events (
  project_id text REFERENCES awe_d09.projects, sequence bigint GENERATED ALWAYS AS IDENTITY,
  attempt_id text, kind text NOT NULL, body jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(project_id,sequence), FOREIGN KEY(project_id,attempt_id) REFERENCES awe_d09.attempts
);
CREATE FUNCTION awe_d09.can_access(p text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
  SELECT EXISTS(SELECT 1 FROM awe_d09.principals a JOIN awe_d09.memberships m USING(login)
    WHERE a.login=session_user AND NOT a.revoked AND a.valid_until>statement_timestamp() AND m.project_id=p)
$$;
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['projects','origins','tasks','budgets','task_budgets','approvals','grants','operations','attempts','allocations','outbox','invoices','results','events'] LOOP
    EXECUTE format('ALTER TABLE awe_d09.%I ENABLE ROW LEVEL SECURITY',t);
    EXECUTE format('ALTER TABLE awe_d09.%I FORCE ROW LEVEL SECURITY',t);
    EXECUTE format('CREATE POLICY tenant_isolation ON awe_d09.%I USING (awe_d09.can_access(project_id)) WITH CHECK (awe_d09.can_access(project_id))',t);
  END LOOP;
END $$;
CREATE FUNCTION awe_d09.immutable_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'D09_IMMUTABLE_HISTORY'; END $$;
CREATE TRIGGER events_immutable BEFORE UPDATE OR DELETE ON awe_d09.events FOR EACH ROW EXECUTE FUNCTION awe_d09.immutable_history();
CREATE TRIGGER invoices_immutable BEFORE UPDATE OR DELETE ON awe_d09.invoices FOR EACH ROW EXECUTE FUNCTION awe_d09.immutable_history();
CREATE TRIGGER results_immutable BEFORE UPDATE OR DELETE ON awe_d09.results FOR EACH ROW EXECUTE FUNCTION awe_d09.immutable_history();
CREATE FUNCTION awe_d09.transition_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status<>NEW.status AND NOT (
    (OLD.status='PROPOSED' AND NEW.status='ADMITTED') OR
    (OLD.status='ADMITTED' AND NEW.status IN ('SENT','NOT_SENT')) OR
    (OLD.status='SENT' AND NEW.status IN ('SETTLED','NOT_SENT','OUTCOME_UNKNOWN')))
  THEN RAISE EXCEPTION 'D09_STICKY_OR_INVALID_TRANSITION'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER attempt_transition BEFORE UPDATE ON awe_d09.attempts FOR EACH ROW EXECUTE FUNCTION awe_d09.transition_guard();
CREATE FUNCTION awe_d09.origin_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN IF OLD.quarantined AND NOT NEW.quarantined THEN RAISE EXCEPTION 'D09_STICKY_QUARANTINE'; END IF; RETURN NEW; END $$;
CREATE TRIGGER quarantine_sticky BEFORE UPDATE ON awe_d09.origins FOR EACH ROW EXECUTE FUNCTION awe_d09.origin_guard();
CREATE FUNCTION awe_d09.check_command(j jsonb, keys text[]) RETURNS void LANGUAGE plpgsql AS $$
DECLARE k text; v text;
BEGIN
  IF jsonb_typeof(j)<>'object' OR (SELECT array_agg(x ORDER BY x) FROM jsonb_object_keys(j) x) IS DISTINCT FROM
    (SELECT array_agg(x ORDER BY x) FROM unnest(keys) x) THEN RAISE EXCEPTION 'D09_COMMAND_INVALID'; END IF;
  FOREACH k IN ARRAY keys LOOP
    v:=j->>k;
    IF v IS NULL THEN RAISE EXCEPTION 'D09_NULL_FIELD'; END IF;
    IF k IN ('project_id','task_id','operation_id','attempt_id','effect_slot','approval_id','grant_id','idempotency_key','provider','invoice_id')
      AND (jsonb_typeof(j->k)<>'string' OR v !~ '^[A-Za-z0-9_.:-]{1,128}$') THEN RAISE EXCEPTION 'D09_ID_INVALID'; END IF;
    IF k IN ('plan_hash','payload_hash','evidence_hash') AND (jsonb_typeof(j->k)<>'string' OR v !~ '^sha256:[a-f0-9]{64}$') THEN RAISE EXCEPTION 'D09_HASH_INVALID'; END IF;
    IF k IN ('reserve_micros','actual_micros') AND (jsonb_typeof(j->k)<>'string' OR v !~ '^(0|[1-9][0-9]{0,29})$') THEN RAISE EXCEPTION 'D09_MICROS_INVALID'; END IF;
    IF k IN ('fence','input_tokens','output_tokens') AND (jsonb_typeof(j->k)<>'number' OR v !~ '^(0|[1-9][0-9]{0,15})$' OR v::numeric>9007199254740991) THEN RAISE EXCEPTION 'D09_INTEGER_INVALID'; END IF;
  END LOOP;
END $$;
CREATE FUNCTION awe_d09.lock_project(p text, permission text) RETURNS awe_d09.projects
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE a awe_d09.principals; m awe_d09.memberships; pr awe_d09.projects;
BEGIN
  IF (SELECT version FROM awe_d09.schema_version) IS DISTINCT FROM 1 THEN RAISE EXCEPTION 'D09_SCHEMA_VERSION'; END IF;
  SELECT * INTO a FROM awe_d09.principals WHERE login=session_user FOR SHARE;
  SELECT * INTO m FROM awe_d09.memberships WHERE project_id=p AND login=session_user FOR SHARE;
  IF a.login IS NULL OR a.revoked OR a.valid_until<=clock_timestamp() OR m.login IS NULL OR NOT permission=ANY(m.permissions)
    THEN RAISE EXCEPTION 'D09_ACCESS_DENIED'; END IF;
  IF permission='RECONCILE' AND NOT pg_has_role(session_user,'awe_d09_reconciler','MEMBER') THEN RAISE EXCEPTION 'D09_ROLE_DENIED'; END IF;
  IF permission='ISSUE' AND NOT pg_has_role(session_user,'awe_d09_issuer','MEMBER') THEN RAISE EXCEPTION 'D09_ROLE_DENIED'; END IF;
  SELECT * INTO pr FROM awe_d09.projects WHERE project_id=p FOR UPDATE;
  IF pr.project_id IS NULL THEN RAISE EXCEPTION 'D09_ACCESS_DENIED'; END IF;
  RETURN pr;
END $$;
CREATE FUNCTION awe_d09.live_authority(p text, gid text, aid text DEFAULT NULL) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE pr awe_d09.projects; g awe_d09.grants; ap awe_d09.approvals; t awe_d09.tasks;
BEGIN
  SELECT * INTO pr FROM awe_d09.projects WHERE project_id=p;
  SELECT * INTO g FROM awe_d09.grants WHERE project_id=p AND grant_id=gid FOR UPDATE;
  SELECT * INTO ap FROM awe_d09.approvals WHERE project_id=p AND approval_id=g.approval_id FOR UPDATE;
  SELECT * INTO t FROM awe_d09.tasks WHERE project_id=p AND task_id=ap.task_id FOR UPDATE;
  IF pr.halted OR pr.restore_pending OR g.grant_id IS NULL OR ap.approval_id IS NULL OR t.task_id IS NULL
    OR g.revoked OR ap.revoked OR t.cancelled OR g.expires_at<=clock_timestamp() OR ap.expires_at<=clock_timestamp()
    OR t.lease_until<=clock_timestamp() OR t.lease_holder<>session_user
    OR g.actor_id<>(SELECT actor_id FROM awe_d09.principals WHERE login=session_user) OR g.actor_id<>ap.actor_id
    OR (g.auth_epoch,g.policy_epoch,g.owner_epoch,g.stop_epoch) IS DISTINCT FROM (pr.auth_epoch,pr.policy_epoch,pr.owner_epoch,pr.stop_epoch)
    OR (g.task_revision,g.task_fence) IS DISTINCT FROM (t.revision,t.fence)
    OR ap.used_by IS DISTINCT FROM aid
    OR EXISTS(SELECT 1 FROM awe_d09.origins WHERE project_id=p AND origin_id=t.origin_id AND quarantined)
    THEN RAISE EXCEPTION 'D09_STALE_OR_INVALID_AUTHORITY'; END IF;
END $$;
CREATE FUNCTION awe_d09.view_attempt(p text,a text) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
 SELECT to_jsonb(t)||jsonb_build_object('physical_decision','DENY','dispatch_authorized',false,
   'reserve_micros',t.reserve_micros::text,'actual_micros',t.actual_micros::text,'delivery_fence',t.delivery_fence::text)
 FROM awe_d09.attempts t WHERE project_id=p AND attempt_id=a
$$;
CREATE FUNCTION awe_d09.audit(p text,a text,k text,b jsonb DEFAULT '{}'::jsonb) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
 INSERT INTO awe_d09.events(project_id,attempt_id,kind,body) VALUES(p,a,k,b||jsonb_build_object('login',session_user))
$$;
CREATE FUNCTION awe_d09.admit(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE p text:=j->>'project_id'; a text:=j->>'attempt_id'; old awe_d09.attempts; ap awe_d09.approvals;
  g awe_d09.grants; t awe_d09.tasks; b awe_d09.budgets; amount numeric; kinds text[];
BEGIN
  PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id','operation_id','attempt_id','effect_slot','approval_id','grant_id','idempotency_key','plan_hash','payload_hash','reserve_micros']);
  PERFORM awe_d09.lock_project(p,'EXECUTE');
  SELECT * INTO old FROM awe_d09.attempts WHERE project_id=p AND idempotency_key=j->>'idempotency_key';
  IF old.attempt_id IS NOT NULL THEN
    IF old.request<>j OR old.owner_login<>session_user THEN RAISE EXCEPTION 'D09_IDEMPOTENCY_CONFLICT'; END IF;
    RETURN awe_d09.view_attempt(p,old.attempt_id); -- readback only, never new dispatch permission
  END IF;
  PERFORM awe_d09.live_authority(p,j->>'grant_id');
  SELECT * INTO g FROM awe_d09.grants WHERE project_id=p AND grant_id=j->>'grant_id';
  SELECT * INTO ap FROM awe_d09.approvals WHERE project_id=p AND approval_id=g.approval_id;
  SELECT * INTO t FROM awe_d09.tasks WHERE project_id=p AND task_id=ap.task_id;
  amount:=(j->>'reserve_micros')::numeric;
  IF (ap.approval_id,ap.task_id,ap.operation_id,ap.effect_slot,ap.payload_hash,ap.plan_hash)
    IS DISTINCT FROM (j->>'approval_id',j->>'task_id',j->>'operation_id',j->>'effect_slot',j->>'payload_hash',j->>'plan_hash')
    OR amount>ap.cap_micros THEN RAISE EXCEPTION 'D09_APPROVAL_BINDING'; END IF;
  SELECT array_agg(bu.kind) INTO kinds FROM awe_d09.task_budgets tb JOIN awe_d09.budgets bu USING(project_id,budget_id)
    WHERE tb.project_id=p AND tb.task_id=t.task_id;
  IF kinds IS NULL OR NOT ARRAY['PROJECT','TASK','ORIGIN','DAY','MONTH','ACCOUNT'] <@ kinds THEN RAISE EXCEPTION 'D09_BUDGET_DIMENSIONS'; END IF;
  INSERT INTO awe_d09.operations VALUES(p,j->>'operation_id',t.task_id,t.origin_id,j->>'effect_slot',j->>'plan_hash',j->>'payload_hash');
  INSERT INTO awe_d09.attempts(project_id,attempt_id,operation_id,idempotency_key,request,owner_login,grant_id,status,reserve_micros,deadline)
    VALUES(p,a,j->>'operation_id',j->>'idempotency_key',j,session_user,g.grant_id,'PROPOSED',amount,LEAST(g.expires_at,ap.expires_at,t.lease_until));
  PERFORM awe_d09.audit(p,a,'PROPOSED');
  FOR b IN SELECT bu.* FROM awe_d09.task_budgets tb JOIN awe_d09.budgets bu USING(project_id,budget_id)
    WHERE tb.project_id=p AND tb.task_id=t.task_id ORDER BY bu.budget_id FOR UPDATE OF bu LOOP
    IF b.valid_until<=clock_timestamp() OR b.spent_micros+b.reserved_micros+amount>b.cap_micros
      OR b.reserved_micros+amount>b.balance_micros OR b.attempts_used>=b.attempt_limit THEN RAISE EXCEPTION 'D09_QUOTA_DENIED'; END IF;
    UPDATE awe_d09.budgets SET reserved_micros=reserved_micros+amount,attempts_used=attempts_used+1 WHERE project_id=p AND budget_id=b.budget_id;
    INSERT INTO awe_d09.allocations VALUES(p,a,b.budget_id,amount,false);
  END LOOP;
  UPDATE awe_d09.approvals SET used_by=a WHERE project_id=p AND approval_id=ap.approval_id;
  UPDATE awe_d09.attempts SET status='ADMITTED' WHERE project_id=p AND attempt_id=a;
  INSERT INTO awe_d09.outbox VALUES(p,a,'READY');
  PERFORM awe_d09.audit(p,a,'ADMITTED');
  RETURN awe_d09.view_attempt(p,a);
END $$;
CREATE FUNCTION awe_d09.inspect_attempt(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE r jsonb; BEGIN
  PERFORM awe_d09.check_command(j,ARRAY['project_id','attempt_id']);
  PERFORM awe_d09.lock_project(j->>'project_id','READ');
  r:=awe_d09.view_attempt(j->>'project_id',j->>'attempt_id');
  IF r IS NULL THEN RAISE EXCEPTION 'D09_ATTEMPT_MISSING'; END IF; RETURN r;
END $$;
CREATE FUNCTION awe_d09.claim_attempt(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE p text:=j->>'project_id'; a text:=j->>'attempt_id'; t awe_d09.attempts; BEGIN
  PERFORM awe_d09.check_command(j,ARRAY['project_id','attempt_id']); PERFORM awe_d09.lock_project(p,'EXECUTE');
  SELECT * INTO t FROM awe_d09.attempts WHERE project_id=p AND attempt_id=a FOR UPDATE;
  IF t.attempt_id IS NULL OR t.owner_login<>session_user OR t.status<>'ADMITTED' OR t.deadline<=clock_timestamp()
    OR t.delivery_until>clock_timestamp() THEN RAISE EXCEPTION 'D09_LEASE_DENIED'; END IF;
  PERFORM awe_d09.live_authority(p,t.grant_id,a);
  UPDATE awe_d09.attempts SET delivery_fence=delivery_fence+1,delivery_holder=session_user,
    delivery_until=LEAST(deadline,clock_timestamp()+interval '30 seconds') WHERE project_id=p AND attempt_id=a;
  UPDATE awe_d09.outbox SET state='CLAIMED' WHERE project_id=p AND attempt_id=a;
  PERFORM awe_d09.audit(p,a,'CLAIMED'); RETURN awe_d09.view_attempt(p,a);
END $$;
CREATE FUNCTION awe_d09.mark_sent(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE p text:=j->>'project_id'; a text:=j->>'attempt_id'; t awe_d09.attempts; BEGIN
  PERFORM awe_d09.check_command(j,ARRAY['project_id','attempt_id','fence']); PERFORM awe_d09.lock_project(p,'EXECUTE');
  SELECT * INTO t FROM awe_d09.attempts WHERE project_id=p AND attempt_id=a FOR UPDATE;
  IF t.attempt_id IS NULL OR t.owner_login<>session_user OR t.delivery_holder<>session_user
    OR t.delivery_fence<>(j->>'fence')::bigint OR t.delivery_until IS NULL OR t.delivery_until<=clock_timestamp()
    OR t.status NOT IN ('ADMITTED','SENT') THEN RAISE EXCEPTION 'D09_SEND_FENCE_DENIED'; END IF;
  PERFORM awe_d09.live_authority(p,t.grant_id,a);
  IF t.status='ADMITTED' THEN
    UPDATE awe_d09.attempts SET status='SENT' WHERE project_id=p AND attempt_id=a;
    UPDATE awe_d09.outbox SET state='COMMITTED' WHERE project_id=p AND attempt_id=a;
    PERFORM awe_d09.audit(p,a,'SENT_INTENT_ONLY');
  END IF; RETURN awe_d09.view_attempt(p,a);
END $$;
CREATE FUNCTION awe_d09.close_allocation(p text,a text,amount numeric) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE al awe_d09.allocations; BEGIN
  FOR al IN SELECT * FROM awe_d09.allocations WHERE project_id=p AND attempt_id=a AND NOT closed ORDER BY budget_id FOR UPDATE LOOP
    IF amount>al.reserve_micros THEN RAISE EXCEPTION 'D09_OVER_ENVELOPE'; END IF;
    UPDATE awe_d09.budgets SET reserved_micros=reserved_micros-al.reserve_micros,spent_micros=spent_micros+amount,
      balance_micros=balance_micros-amount WHERE project_id=p AND budget_id=al.budget_id;
    UPDATE awe_d09.allocations SET closed=true WHERE project_id=p AND attempt_id=a AND budget_id=al.budget_id;
  END LOOP;
END $$;
CREATE FUNCTION awe_d09.quarantine(p text,a text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
BEGIN
  UPDATE awe_d09.attempts SET status='OUTCOME_UNKNOWN' WHERE project_id=p AND attempt_id=a AND status='SENT';
  UPDATE awe_d09.origins SET quarantined=true WHERE project_id=p AND origin_id IN
    (SELECT o.origin_id FROM awe_d09.operations o JOIN awe_d09.attempts t USING(project_id,operation_id) WHERE t.project_id=p AND t.attempt_id=a);
  UPDATE awe_d09.outbox SET state='QUARANTINED' WHERE project_id=p AND attempt_id=a;
  PERFORM awe_d09.audit(p,a,'OUTCOME_UNKNOWN');
END $$;
CREATE FUNCTION awe_d09.cancel_attempt(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE p text:=j->>'project_id'; a text:=j->>'attempt_id'; t awe_d09.attempts; BEGIN
  PERFORM awe_d09.check_command(j,ARRAY['project_id','attempt_id']); PERFORM awe_d09.lock_project(p,'EXECUTE');
  SELECT * INTO t FROM awe_d09.attempts WHERE project_id=p AND attempt_id=a FOR UPDATE;
  IF t.attempt_id IS NULL OR t.owner_login<>session_user THEN RAISE EXCEPTION 'D09_ACCESS_DENIED'; END IF;
  IF t.status='ADMITTED' THEN
    PERFORM awe_d09.close_allocation(p,a,0);
    UPDATE awe_d09.attempts SET status='NOT_SENT',accounting_status='RELEASED' WHERE project_id=p AND attempt_id=a;
    UPDATE awe_d09.outbox SET state='CANCELLED' WHERE project_id=p AND attempt_id=a;
  ELSIF t.status='SENT' THEN PERFORM awe_d09.quarantine(p,a); END IF;
  PERFORM awe_d09.audit(p,a,'CANCEL_REQUESTED'); RETURN awe_d09.view_attempt(p,a);
END $$;
CREATE FUNCTION awe_d09.record_result(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE p text:=j->>'project_id'; a text:=j->>'attempt_id'; t awe_d09.attempts; r awe_d09.results; BEGIN
  PERFORM awe_d09.check_command(j,ARRAY['project_id','attempt_id','result','evidence_hash']); PERFORM awe_d09.lock_project(p,'EXECUTE');
  SELECT * INTO t FROM awe_d09.attempts WHERE project_id=p AND attempt_id=a;
  IF t.attempt_id IS NULL OR t.owner_login<>session_user OR t.status NOT IN ('SENT','SETTLED','OUTCOME_UNKNOWN') THEN RAISE EXCEPTION 'D09_RESULT_DENIED'; END IF;
  SELECT * INTO r FROM awe_d09.results WHERE project_id=p AND attempt_id=a;
  IF r.attempt_id IS NOT NULL THEN
    IF (r.result,r.evidence_hash) IS DISTINCT FROM (j->>'result',j->>'evidence_hash') THEN RAISE EXCEPTION 'D09_RESULT_CONFLICT'; END IF;
  ELSE
    INSERT INTO awe_d09.results VALUES(p,a,j->>'result',j->>'evidence_hash'); PERFORM awe_d09.audit(p,a,'UNTRUSTED_TASK_RESULT');
  END IF;
  RETURN awe_d09.view_attempt(p,a); -- never settles money or clears quarantine
END $$;
CREATE FUNCTION awe_d09.reconcile_charge(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE p text:=j->>'project_id'; a text:=j->>'attempt_id'; t awe_d09.attempts; inv awe_d09.invoices; amount numeric; BEGIN
  PERFORM awe_d09.check_command(j,ARRAY['project_id','attempt_id','provider','invoice_id','actual_micros','input_tokens','output_tokens','evidence_hash']);
  PERFORM awe_d09.lock_project(p,'RECONCILE');
  SELECT * INTO t FROM awe_d09.attempts WHERE project_id=p AND attempt_id=a FOR UPDATE;
  IF t.attempt_id IS NULL THEN RAISE EXCEPTION 'D09_ATTEMPT_MISSING'; END IF;
  SELECT * INTO inv FROM awe_d09.invoices WHERE provider=j->>'provider' AND invoice_id=j->>'invoice_id';
  IF inv.invoice_id IS NOT NULL THEN
    IF inv.body<>j THEN RAISE EXCEPTION 'D09_INVOICE_CONFLICT'; END IF; RETURN awe_d09.view_attempt(p,a);
  END IF;
  IF t.status NOT IN ('SENT','OUTCOME_UNKNOWN') OR t.accounting_status<>'RESERVED' THEN RAISE EXCEPTION 'D09_SETTLEMENT_DENIED'; END IF;
  amount:=(j->>'actual_micros')::numeric;
  BEGIN
    INSERT INTO awe_d09.invoices VALUES(p,a,j->>'provider',j->>'invoice_id',amount,(j->>'input_tokens')::bigint,(j->>'output_tokens')::bigint,j->>'evidence_hash',j);
  EXCEPTION WHEN unique_violation THEN
    -- Global invoice uniqueness must not expose a different project's constraint detail.
    RAISE EXCEPTION 'D09_INVOICE_CONFLICT';
  END;
  IF amount>t.reserve_micros THEN
    UPDATE awe_d09.projects SET halted=true WHERE project_id=p;
    PERFORM awe_d09.quarantine(p,a);
    UPDATE awe_d09.attempts SET accounting_status='DISPUTED' WHERE project_id=p AND attempt_id=a;
    PERFORM awe_d09.audit(p,a,'INVOICE_OVER_ENVELOPE',jsonb_build_object('observed_micros',amount::text));
  ELSE
    PERFORM awe_d09.close_allocation(p,a,amount);
    UPDATE awe_d09.attempts SET accounting_status='SETTLED',actual_micros=amount,
      status=CASE WHEN status='SENT' THEN 'SETTLED' ELSE status END WHERE project_id=p AND attempt_id=a;
    PERFORM awe_d09.audit(p,a,'CHARGE_SETTLED');
  END IF;
  RETURN awe_d09.view_attempt(p,a);
END $$;
CREATE FUNCTION awe_d09.prove_not_sent(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE p text:=j->>'project_id'; a text:=j->>'attempt_id'; t awe_d09.attempts; BEGIN
  PERFORM awe_d09.check_command(j,ARRAY['project_id','attempt_id','evidence_hash']); PERFORM awe_d09.lock_project(p,'RECONCILE');
  SELECT * INTO t FROM awe_d09.attempts WHERE project_id=p AND attempt_id=a FOR UPDATE;
  -- UNKNOWN stays sticky; no administrative JSON can re-arm it through this API.
  IF t.attempt_id IS NULL OR t.status NOT IN ('ADMITTED','SENT') OR t.accounting_status<>'RESERVED' THEN RAISE EXCEPTION 'D09_NOT_SENT_DENIED'; END IF;
  PERFORM awe_d09.close_allocation(p,a,0);
  UPDATE awe_d09.attempts SET status='NOT_SENT',accounting_status='RELEASED' WHERE project_id=p AND attempt_id=a;
  UPDATE awe_d09.outbox SET state='CANCELLED' WHERE project_id=p AND attempt_id=a;
  PERFORM awe_d09.audit(p,a,'TRUSTED_NOT_SENT_PROOF',jsonb_build_object('evidence_hash',j->>'evidence_hash'));
  RETURN awe_d09.view_attempt(p,a);
END $$;
CREATE FUNCTION awe_d09.recover_project(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE p text:=j->>'project_id'; t awe_d09.attempts; n integer:=0; BEGIN
  PERFORM awe_d09.check_command(j,ARRAY['project_id']); PERFORM awe_d09.lock_project(p,'RECONCILE');
  FOR t IN SELECT * FROM awe_d09.attempts WHERE project_id=p AND status IN ('ADMITTED','SENT')
    AND LEAST(deadline,COALESCE(delivery_until,deadline))<=clock_timestamp() ORDER BY attempt_id FOR UPDATE LOOP
    IF t.status='SENT' THEN PERFORM awe_d09.quarantine(p,t.attempt_id);
    ELSE
      PERFORM awe_d09.close_allocation(p,t.attempt_id,0);
      UPDATE awe_d09.attempts SET status='NOT_SENT',accounting_status='RELEASED' WHERE project_id=p AND attempt_id=t.attempt_id;
      UPDATE awe_d09.outbox SET state='CANCELLED' WHERE project_id=p AND attempt_id=t.attempt_id;
      PERFORM awe_d09.audit(p,t.attempt_id,'RECOVERED_BEFORE_SEND');
    END IF; n:=n+1;
  END LOOP;
  RETURN jsonb_build_object('recovered',n,'physical_decision','DENY');
END $$;
CREATE FUNCTION awe_d09.advance_epoch(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE p text:=j->>'project_id'; e text:=j->>'epoch'; BEGIN
  PERFORM awe_d09.check_command(j,ARRAY['project_id','epoch']); PERFORM awe_d09.lock_project(p,'ISSUE');
  IF e NOT IN ('auth','policy','owner','stop') THEN RAISE EXCEPTION 'D09_EPOCH_INVALID'; END IF;
  EXECUTE format('UPDATE awe_d09.projects SET %I=%I+1 WHERE project_id=$1',e||'_epoch',e||'_epoch') USING p;
  PERFORM awe_d09.audit(p,NULL,'EPOCH_ADVANCED',jsonb_build_object('epoch',e));
  RETURN jsonb_build_object('physical_decision','DENY','epoch',e);
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA awe_d09 FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA awe_d09 FROM PUBLIC;
GRANT USAGE ON SCHEMA awe_d09 TO awe_d09_api,awe_d09_reconciler,awe_d09_reader,awe_d09_issuer;
GRANT EXECUTE ON FUNCTION awe_d09.can_access(text) TO awe_d09_reader;
GRANT SELECT ON awe_d09.projects,awe_d09.origins,awe_d09.tasks,awe_d09.budgets,awe_d09.task_budgets,
  awe_d09.approvals,awe_d09.grants,awe_d09.operations,awe_d09.attempts,awe_d09.allocations,
  awe_d09.outbox,awe_d09.invoices,awe_d09.results,awe_d09.events TO awe_d09_reader;
GRANT EXECUTE ON FUNCTION awe_d09.admit(jsonb),awe_d09.inspect_attempt(jsonb),awe_d09.claim_attempt(jsonb),
  awe_d09.mark_sent(jsonb),awe_d09.cancel_attempt(jsonb),awe_d09.record_result(jsonb) TO awe_d09_api;
GRANT EXECUTE ON FUNCTION awe_d09.reconcile_charge(jsonb),awe_d09.prove_not_sent(jsonb),awe_d09.recover_project(jsonb) TO awe_d09_reconciler;
GRANT EXECUTE ON FUNCTION awe_d09.advance_epoch(jsonb) TO awe_d09_issuer;
COMMIT;
