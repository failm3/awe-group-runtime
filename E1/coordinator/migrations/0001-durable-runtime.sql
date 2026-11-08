-- Native PostgreSQL 18 E1 only. Additive migration; no down migration of outbox.
BEGIN;
CREATE SCHEMA IF NOT EXISTS awe_e1_runtime AUTHORIZATION awe_e1_test;
REVOKE ALL ON SCHEMA awe_e1_runtime FROM PUBLIC;
SET LOCAL search_path = pg_catalog, awe_e1_runtime;
CREATE TABLE IF NOT EXISTS awe_e1_runtime.schema_migration(version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE IF NOT EXISTS awe_e1_runtime.resource_marker(resource_id text PRIMARY KEY, pgdata text NOT NULL, socket_directory text NOT NULL);
INSERT INTO awe_e1_runtime.resource_marker VALUES ('awe_e1_a2a3_20261108',current_setting('data_directory'),current_setting('unix_socket_directories')) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS awe_e1_runtime.project(
  project_id text PRIMARY KEY, owner_id text NOT NULL, budget_cap bigint NOT NULL CHECK(budget_cap>=0),
  spent bigint NOT NULL DEFAULT 0 CHECK(spent>=0), reserved bigint NOT NULL DEFAULT 0 CHECK(reserved>=0),
  quota_cap bigint NOT NULL CHECK(quota_cap>0), quota_used bigint NOT NULL DEFAULT 0 CHECK(quota_used>=0),
  max_parallel integer NOT NULL CHECK(max_parallel BETWEEN 1 AND 32),
  CHECK(spent+reserved<=budget_cap), CHECK(quota_used<=quota_cap));
CREATE TABLE IF NOT EXISTS awe_e1_runtime.mission(
  mission_id text PRIMARY KEY, project_id text NOT NULL REFERENCES awe_e1_runtime.project, owner_id text NOT NULL,
  state text NOT NULL CHECK(state IN('ACTIVE','HOLD','CANCELLED','REVOKED','COMPLETE')),
  spec_digest text NOT NULL, grant_digest text NOT NULL, plan_digest text NOT NULL, revision integer NOT NULL,
  spec jsonb NOT NULL, deadline timestamptz NOT NULL, budget_cap bigint NOT NULL CHECK(budget_cap>=0),
  spent bigint NOT NULL DEFAULT 0 CHECK(spent>=0), reserved bigint NOT NULL DEFAULT 0 CHECK(reserved>=0),
  reason text, CHECK(spent+reserved<=budget_cap));
CREATE TABLE IF NOT EXISTS awe_e1_runtime.mission_grant(
  mission_id text PRIMARY KEY REFERENCES awe_e1_runtime.mission, grant_id text NOT NULL, version integer NOT NULL,
  digest text NOT NULL, document jsonb NOT NULL, issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
  revoked_at timestamptz, CHECK(issued_at<expires_at));
CREATE TABLE IF NOT EXISTS awe_e1_runtime.plan_revision(
  mission_id text NOT NULL REFERENCES awe_e1_runtime.mission, revision integer NOT NULL, digest text NOT NULL UNIQUE,
  publication jsonb NOT NULL, document jsonb NOT NULL, admitted_by text NOT NULL, admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(mission_id,revision));
CREATE TABLE IF NOT EXISTS awe_e1_runtime.resource_pool(
  project_id text NOT NULL REFERENCES awe_e1_runtime.project, resource_key text NOT NULL, capacity integer NOT NULL CHECK(capacity BETWEEN 1 AND 32), PRIMARY KEY(project_id,resource_key));
CREATE TABLE IF NOT EXISTS awe_e1_runtime.capability_binding(project_id text NOT NULL REFERENCES awe_e1_runtime.project, capability_id text NOT NULL, version text NOT NULL, manifest_digest text NOT NULL, state text NOT NULL CHECK(state IN('ACTIVE','REVOKED')),health_until timestamptz NOT NULL,descriptor jsonb NOT NULL,PRIMARY KEY(project_id,capability_id,version));
CREATE SEQUENCE IF NOT EXISTS awe_e1_runtime.fence_sequence AS bigint;
CREATE TABLE IF NOT EXISTS awe_e1_runtime.task(
  mission_id text NOT NULL REFERENCES awe_e1_runtime.mission, task_id text NOT NULL, project_id text NOT NULL REFERENCES awe_e1_runtime.project,
  state text NOT NULL CHECK(state IN('READY','RUNNING','WAIT_QA','ACCEPTED','FAILED','HOLD','CANCELLED')),
  document jsonb NOT NULL, capability_id text NOT NULL, capability_version text NOT NULL, executor_kind text NOT NULL,
  priority integer NOT NULL DEFAULT 0, resource_keys jsonb NOT NULL, model_routes jsonb NOT NULL,
  deadline timestamptz NOT NULL, reserve_cap bigint NOT NULL CHECK(reserve_cap>=0),
  max_claims integer NOT NULL CHECK(max_claims BETWEEN 1 AND 16), claims integer NOT NULL DEFAULT 0,
  fence bigint NOT NULL DEFAULT 0, producer_id text, result_hash text, result jsonb, reason text,
  PRIMARY KEY(mission_id,task_id));
ALTER TABLE awe_e1_runtime.task ADD COLUMN IF NOT EXISTS output_schema jsonb;
ALTER TABLE awe_e1_runtime.task ADD COLUMN IF NOT EXISTS plan_digest text;
ALTER TABLE awe_e1_runtime.task ADD COLUMN IF NOT EXISTS is_current boolean NOT NULL DEFAULT true;
CREATE TABLE IF NOT EXISTS awe_e1_runtime.task_revision(mission_id text NOT NULL REFERENCES awe_e1_runtime.mission,plan_digest text NOT NULL,task_id text NOT NULL,body jsonb NOT NULL,archived_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(mission_id,plan_digest,task_id));
CREATE INDEX IF NOT EXISTS task_ready ON awe_e1_runtime.task(project_id,state,priority DESC);
CREATE TABLE IF NOT EXISTS awe_e1_runtime.task_dependency(
  mission_id text NOT NULL, task_id text NOT NULL, dependency_id text NOT NULL,
  PRIMARY KEY(mission_id,task_id,dependency_id), FOREIGN KEY(mission_id,task_id) REFERENCES awe_e1_runtime.task,
  FOREIGN KEY(mission_id,dependency_id) REFERENCES awe_e1_runtime.task, CHECK(task_id<>dependency_id));
CREATE TABLE IF NOT EXISTS awe_e1_runtime.lease(
  mission_id text NOT NULL, task_id text NOT NULL, project_id text NOT NULL REFERENCES awe_e1_runtime.project,
  worker_id text NOT NULL, fence bigint NOT NULL UNIQUE, expires_at timestamptz NOT NULL, held boolean NOT NULL DEFAULT false,
  PRIMARY KEY(mission_id,task_id), FOREIGN KEY(mission_id,task_id) REFERENCES awe_e1_runtime.task);
ALTER TABLE awe_e1_runtime.lease ADD COLUMN IF NOT EXISTS execution_deadline timestamptz;
CREATE TABLE IF NOT EXISTS awe_e1_runtime.lease_slot(
  project_id text NOT NULL, resource_key text NOT NULL, mission_id text NOT NULL, task_id text NOT NULL, fence bigint NOT NULL,
  PRIMARY KEY(mission_id,task_id,resource_key), FOREIGN KEY(project_id,resource_key) REFERENCES awe_e1_runtime.resource_pool,
  FOREIGN KEY(mission_id,task_id) REFERENCES awe_e1_runtime.lease ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS awe_e1_runtime.task_reservation(
  mission_id text NOT NULL, task_id text NOT NULL, amount bigint NOT NULL CHECK(amount>=0), allocated bigint NOT NULL DEFAULT 0 CHECK(allocated>=0),
  PRIMARY KEY(mission_id,task_id), FOREIGN KEY(mission_id,task_id) REFERENCES awe_e1_runtime.task, CHECK(allocated<=amount));
CREATE TABLE IF NOT EXISTS awe_e1_runtime.effect_intent(
  intent_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, owner_id text NOT NULL, business_key text NOT NULL,
  project_id text NOT NULL REFERENCES awe_e1_runtime.project, mission_id text NOT NULL, task_id text NOT NULL,
  payload_digest text NOT NULL, destination text NOT NULL, effect_class text NOT NULL,
  state text NOT NULL CHECK(state IN('RESERVED','SENDING','CONFIRMED','FAILED','OUTCOME_UNKNOWN')),
  fence bigint NOT NULL, provider_ref text, receipt jsonb, reason text,
  UNIQUE(owner_id,business_key), FOREIGN KEY(mission_id,task_id) REFERENCES awe_e1_runtime.task);
CREATE TABLE IF NOT EXISTS awe_e1_runtime.model_attempt(
  attempt_id text PRIMARY KEY, project_id text NOT NULL REFERENCES awe_e1_runtime.project, mission_id text NOT NULL, task_id text NOT NULL,
  logical_request_id text NOT NULL, worker_id text NOT NULL, fence bigint NOT NULL,
  route_id text NOT NULL, request_hash text NOT NULL, reserved bigint NOT NULL CHECK(reserved>=0), quota_units bigint NOT NULL CHECK(quota_units>0),
  state text NOT NULL CHECK(state IN('RESERVED','SENDING','CONFIRMED','FAILED','OUTCOME_UNKNOWN')),
  actual_cost bigint CHECK(actual_cost>=0), usage jsonb, provider_ref text, reason text,
  UNIQUE(mission_id,logical_request_id,attempt_id), FOREIGN KEY(mission_id,task_id) REFERENCES awe_e1_runtime.task);
-- A logical request cannot acquire a fresh attempt while one may have reached a provider.
CREATE UNIQUE INDEX IF NOT EXISTS model_unknown_guard ON awe_e1_runtime.model_attempt(mission_id,logical_request_id) WHERE state IN('RESERVED','SENDING','OUTCOME_UNKNOWN');
CREATE UNIQUE INDEX IF NOT EXISTS model_one_active_per_task ON awe_e1_runtime.model_attempt(mission_id,task_id) WHERE state IN('RESERVED','SENDING','OUTCOME_UNKNOWN');
CREATE TABLE IF NOT EXISTS awe_e1_runtime.event(
  sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, project_id text NOT NULL, mission_id text, task_id text,
  kind text NOT NULL, body jsonb NOT NULL, at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE INDEX IF NOT EXISTS event_scope ON awe_e1_runtime.event(project_id,sequence);
CREATE TABLE IF NOT EXISTS awe_e1_runtime.event_cursor(project_id text NOT NULL REFERENCES awe_e1_runtime.project, consumer_id text NOT NULL, sequence bigint NOT NULL DEFAULT 0 CHECK(sequence>=0), PRIMARY KEY(project_id,consumer_id));
CREATE TABLE IF NOT EXISTS awe_e1_runtime.inbox_event(project_id text NOT NULL REFERENCES awe_e1_runtime.project, source_id text NOT NULL, event_id text NOT NULL, payload_hash text NOT NULL, body jsonb NOT NULL, sequence bigint NOT NULL REFERENCES awe_e1_runtime.event, PRIMARY KEY(project_id,source_id,event_id));
CREATE TABLE IF NOT EXISTS awe_e1_runtime.qa_result(mission_id text NOT NULL, task_id text NOT NULL, result_hash text NOT NULL, evaluator_id text NOT NULL, verdict text NOT NULL, checks jsonb NOT NULL, at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(mission_id,task_id,result_hash), FOREIGN KEY(mission_id,task_id) REFERENCES awe_e1_runtime.task);
CREATE TABLE IF NOT EXISTS awe_e1_runtime.qa_revision(mission_id text NOT NULL,plan_digest text NOT NULL,task_id text NOT NULL,result_hash text NOT NULL,evaluator_id text NOT NULL,verdict text NOT NULL,checks jsonb NOT NULL,at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(mission_id,plan_digest,task_id,result_hash));

CREATE OR REPLACE FUNCTION awe_e1_runtime.resource_info() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,awe_e1_runtime AS $$ SELECT to_jsonb(r) FROM awe_e1_runtime.resource_marker r WHERE resource_id='awe_e1_a2a3_20261108' $$;
CREATE OR REPLACE FUNCTION awe_e1_runtime.emit(p text,m text,t text,k text,b jsonb) RETURNS void LANGUAGE sql SET search_path=pg_catalog,awe_e1_runtime AS $$ INSERT INTO awe_e1_runtime.event(project_id,mission_id,task_id,kind,body) VALUES(p,m,t,k,b) $$;

CREATE OR REPLACE FUNCTION awe_e1_runtime.assert_active(p text,m text) RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE mm awe_e1_runtime.mission%ROWTYPE; gg awe_e1_runtime.mission_grant%ROWTYPE;
BEGIN
  SELECT * INTO mm FROM awe_e1_runtime.mission WHERE mission_id=m AND project_id=p FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'A2_PROJECT_SCOPE'; END IF;
  SELECT * INTO gg FROM awe_e1_runtime.mission_grant WHERE mission_id=m FOR UPDATE;
  IF mm.state<>'ACTIVE' THEN RAISE EXCEPTION 'A2_MISSION_NOT_ACTIVE'; END IF;
  IF gg.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'A2_GRANT_REVOKED'; END IF;
  IF clock_timestamp()<gg.issued_at OR clock_timestamp()>=gg.expires_at OR clock_timestamp()>=mm.deadline THEN RAISE EXCEPTION 'A2_GRANT_EXPIRED'; END IF;
END $$;
CREATE OR REPLACE FUNCTION awe_e1_runtime.assert_fence(p text,m text,t text,w text,f bigint) RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,awe_e1_runtime AS $$
BEGIN
  PERFORM awe_e1_runtime.assert_active(p,m);
  PERFORM 1 FROM awe_e1_runtime.lease l JOIN awe_e1_runtime.task tt USING(mission_id,task_id)
    WHERE l.project_id=p AND l.mission_id=m AND l.task_id=t AND l.worker_id=w AND l.fence=f AND tt.fence=f AND tt.state='RUNNING' AND tt.is_current AND clock_timestamp()<l.expires_at AND clock_timestamp()<tt.deadline FOR UPDATE OF l,tt;
  IF NOT FOUND THEN RAISE EXCEPTION 'A2_STALE_FENCE'; END IF;
  PERFORM 1 FROM awe_e1_runtime.mission_grant WHERE mission_id=m AND document->'allowed_principals' ? w;
  IF NOT FOUND THEN RAISE EXCEPTION 'A2_WORKER_GRANT'; END IF;
  PERFORM 1 FROM awe_e1_runtime.task tt JOIN awe_e1_runtime.capability_binding c ON c.project_id=tt.project_id AND c.capability_id=tt.capability_id AND c.version=tt.capability_version WHERE tt.mission_id=m AND tt.task_id=t AND c.state='ACTIVE' AND c.health_until>clock_timestamp();
  IF NOT FOUND THEN RAISE EXCEPTION 'A2_CAPABILITY_REVOKED'; END IF;
END $$;
CREATE OR REPLACE FUNCTION awe_e1_runtime.release_task(p text,m text,t text) RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE n bigint; released_quota bigint;
BEGIN
  SELECT amount INTO n FROM awe_e1_runtime.task_reservation WHERE mission_id=m AND task_id=t FOR UPDATE;
  IF FOUND THEN
    IF EXISTS(SELECT 1 FROM awe_e1_runtime.model_attempt WHERE mission_id=m AND task_id=t AND state IN('SENDING','OUTCOME_UNKNOWN')) OR EXISTS(SELECT 1 FROM awe_e1_runtime.effect_intent WHERE mission_id=m AND task_id=t AND state IN('SENDING','OUTCOME_UNKNOWN')) THEN RAISE EXCEPTION 'A2_UNKNOWN_REQUIRES_HOLD'; END IF;
    UPDATE awe_e1_runtime.project SET reserved=reserved-n WHERE project_id=p;
    UPDATE awe_e1_runtime.mission SET reserved=reserved-n WHERE mission_id=m;
    DELETE FROM awe_e1_runtime.task_reservation WHERE mission_id=m AND task_id=t;
  END IF;
  SELECT COALESCE(sum(quota_units),0) INTO released_quota FROM awe_e1_runtime.model_attempt WHERE mission_id=m AND task_id=t AND state='RESERVED';
  UPDATE awe_e1_runtime.project SET quota_used=quota_used-released_quota WHERE project_id=p;
  UPDATE awe_e1_runtime.model_attempt SET state='FAILED',reason='PROVEN_NO_SEND_RELEASE' WHERE mission_id=m AND task_id=t AND state='RESERVED';
  UPDATE awe_e1_runtime.effect_intent SET state='FAILED',reason='PROVEN_NO_SEND_RELEASE' WHERE mission_id=m AND task_id=t AND state='RESERVED';
  DELETE FROM awe_e1_runtime.lease WHERE mission_id=m AND task_id=t;
END $$;

CREATE OR REPLACE FUNCTION awe_e1_runtime.command(op text,p jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE
  projectid text:=p->>'project_id'; missionid text:=p->>'mission_id'; taskid text:=p->>'task_id'; workerid text:=p->>'worker_id';
  nowat timestamptz:=clock_timestamp(); f bigint; reserve_value bigint; quota_value bigint; actual_value bigint; seq_value bigint;
  pp awe_e1_runtime.project%ROWTYPE; mm awe_e1_runtime.mission%ROWTYPE; tt awe_e1_runtime.task%ROWTYPE;
  aa awe_e1_runtime.model_attempt%ROWTYPE; ii awe_e1_runtime.effect_intent%ROWTYPE; rr record;
  item jsonb; dep jsonb; key text; spec jsonb; grantdoc jsonb; plan jsonb; result jsonb;
BEGIN
  IF projectid IS NULL OR projectid !~ '^[a-z][a-z0-9_.-]{0,79}$' THEN RAISE EXCEPTION 'A2_PROJECT_SCOPE'; END IF;
  IF session_user NOT IN('awe_e1_test','awe_e1_coord','awe_e1_qa') THEN RAISE EXCEPTION 'A2_ROLE_DENIED'; END IF;
  IF session_user='awe_e1_qa' AND op NOT IN('snapshot','events','qa_evaluate','get_cursor') THEN RAISE EXCEPTION 'A2_QA_WRITE_DENIED'; END IF;
  IF op='qa_evaluate' AND session_user NOT IN('awe_e1_test','awe_e1_qa') THEN RAISE EXCEPTION 'A2_INDEPENDENT_QA_REQUIRED'; END IF;

  IF op='admit' THEN
    spec:=p->'spec'; grantdoc:=p->'grant'; plan:=p->'plan'; missionid:=spec->>'mission_id';
    IF spec->>'project_id'<>projectid OR grantdoc->>'project_id'<>projectid OR plan->>'project_id'<>projectid OR grantdoc->>'mission_id'<>missionid OR plan->>'mission_id'<>missionid OR spec->>'owner_id'<>grantdoc->>'owner_id' OR spec->>'owner_id'<>grantdoc->>'issued_by' THEN RAISE EXCEPTION 'A2_ADMISSION_SCOPE'; END IF;
    IF grantdoc->>'revoked_at' IS NOT NULL OR nowat<(grantdoc->>'issued_at')::timestamptz OR nowat>=(grantdoc->>'expires_at')::timestamptz OR nowat>=(spec->>'deadline')::timestamptz THEN RAISE EXCEPTION 'A2_GRANT_EXPIRED'; END IF;
    IF (p->'publication'->>'decision')<>'PUBLISHED_PREFLIGHT_ONLY' OR (p->'publication'->>'plan_digest')<>p->>'plan_digest' OR plan->>'spec_digest'<>p->>'spec_digest' OR plan->>'grant_digest'<>p->>'grant_digest' THEN RAISE EXCEPTION 'A2_PUBLICATION_REQUIRED'; END IF;
    INSERT INTO awe_e1_runtime.project(project_id,owner_id,budget_cap,quota_cap,max_parallel) VALUES(projectid,spec->>'owner_id',(p->'policy'->>'budget_cap_micros')::bigint,(p->'policy'->>'quota_cap')::bigint,(p->'policy'->>'max_parallel')::integer) ON CONFLICT DO NOTHING;
    SELECT * INTO pp FROM awe_e1_runtime.project WHERE project_id=projectid FOR UPDATE;
    IF pp.owner_id<>spec->>'owner_id' OR pp.budget_cap<>(p->'policy'->>'budget_cap_micros')::bigint OR pp.quota_cap<>(p->'policy'->>'quota_cap')::bigint OR pp.max_parallel<>(p->'policy'->>'max_parallel')::integer THEN RAISE EXCEPTION 'A2_PROJECT_POLICY_IMMUTABLE'; END IF;
    SELECT * INTO mm FROM awe_e1_runtime.mission WHERE mission_id=missionid FOR UPDATE;
    IF FOUND THEN
      IF mm.project_id<>projectid THEN RAISE EXCEPTION 'A2_PROJECT_SCOPE'; END IF;
      IF mm.state IN('CANCELLED','REVOKED','HOLD') OR EXISTS(SELECT 1 FROM awe_e1_runtime.mission_grant WHERE mission_id=missionid AND revoked_at IS NOT NULL) THEN RAISE EXCEPTION 'A2_MISSION_NOT_ACTIVE'; END IF;
      IF mm.spec_digest=p->>'spec_digest' AND mm.grant_digest=p->>'grant_digest' AND mm.plan_digest=p->>'plan_digest' THEN RETURN jsonb_build_object('status','ADMITTED','mission_id',missionid,'repeated',true); END IF;
      -- Replanning is bounded by the SAME owner grant/spec and never refreshes
      -- money/quota. A changed grant requires a separately authorized mission.
      IF mm.spec_digest<>p->>'spec_digest' OR mm.grant_digest<>p->>'grant_digest' THEN RAISE EXCEPTION 'A2_REVISION_SCOPE'; END IF;
      IF mm.state NOT IN('ACTIVE','COMPLETE') THEN RAISE EXCEPTION 'A2_MISSION_NOT_ACTIVE'; END IF;
      IF (plan->>'revision')::int<>mm.revision+1 OR plan->>'previous_digest'<>mm.plan_digest OR (plan->>'revision')::int>LEAST((spec->>'max_replans')::int,(grantdoc->>'max_replans')::int)+1 OR plan->>'plan_id'<>(SELECT document->>'plan_id' FROM awe_e1_runtime.plan_revision WHERE digest=mm.plan_digest) THEN RAISE EXCEPTION 'A2_PLAN_REVISION'; END IF;
      IF EXISTS(SELECT 1 FROM awe_e1_runtime.lease WHERE mission_id=missionid) OR EXISTS(SELECT 1 FROM awe_e1_runtime.task_reservation WHERE mission_id=missionid) OR EXISTS(SELECT 1 FROM awe_e1_runtime.task WHERE mission_id=missionid AND state IN('RUNNING','WAIT_QA','HOLD')) OR EXISTS(SELECT 1 FROM awe_e1_runtime.model_attempt WHERE mission_id=missionid AND state IN('RESERVED','SENDING','OUTCOME_UNKNOWN')) OR EXISTS(SELECT 1 FROM awe_e1_runtime.effect_intent WHERE mission_id=missionid AND state IN('RESERVED','SENDING','OUTCOME_UNKNOWN')) THEN RAISE EXCEPTION 'A2_REVISION_REQUIRES_DRAIN'; END IF;
      INSERT INTO awe_e1_runtime.task_revision(mission_id,plan_digest,task_id,body) SELECT missionid,mm.plan_digest,t.task_id,to_jsonb(t) FROM awe_e1_runtime.task t WHERE t.mission_id=missionid AND t.is_current;
      UPDATE awe_e1_runtime.task SET is_current=false WHERE mission_id=missionid;
      DELETE FROM awe_e1_runtime.task_dependency WHERE mission_id=missionid;
      UPDATE awe_e1_runtime.mission SET plan_digest=p->>'plan_digest',revision=(plan->>'revision')::int,state='ACTIVE',reason=NULL WHERE mission_id=missionid;
    ELSE
      INSERT INTO awe_e1_runtime.mission VALUES(missionid,projectid,spec->>'owner_id','ACTIVE',p->>'spec_digest',p->>'grant_digest',p->>'plan_digest',(plan->>'revision')::int,spec,(spec->>'deadline')::timestamptz,(spec->'budget'->>'amount_micros')::bigint,0,0,NULL);
      INSERT INTO awe_e1_runtime.mission_grant VALUES(missionid,grantdoc->>'grant_id',(grantdoc->>'grant_version')::int,p->>'grant_digest',grantdoc,(grantdoc->>'issued_at')::timestamptz,(grantdoc->>'expires_at')::timestamptz,NULL);
    END IF;
    INSERT INTO awe_e1_runtime.plan_revision(mission_id,revision,digest,publication,document,admitted_by) VALUES(missionid,(plan->>'revision')::int,p->>'plan_digest',p->'publication',plan,p->>'admitted_by');
    FOR key,item IN SELECT * FROM jsonb_each(p->'policy'->'resource_limits') LOOP
      INSERT INTO awe_e1_runtime.resource_pool VALUES(projectid,key,(item#>>'{}')::integer) ON CONFLICT DO NOTHING;
      IF NOT EXISTS(SELECT 1 FROM awe_e1_runtime.resource_pool WHERE project_id=projectid AND resource_key=key AND capacity=(item#>>'{}')::integer) THEN RAISE EXCEPTION 'A2_RESOURCE_POLICY_IMMUTABLE'; END IF;
    END LOOP;
    FOR item IN SELECT * FROM jsonb_array_elements(p->'capabilities') LOOP
      INSERT INTO awe_e1_runtime.capability_binding VALUES(projectid,item->'ref'->>'capability_id',item->'ref'->>'version',item->'ref'->>'manifest_digest',item->>'state',(item->>'health_until')::timestamptz,item) ON CONFLICT DO NOTHING;
      IF NOT EXISTS(SELECT 1 FROM awe_e1_runtime.capability_binding WHERE project_id=projectid AND capability_id=item->'ref'->>'capability_id' AND version=item->'ref'->>'version' AND manifest_digest=item->'ref'->>'manifest_digest' AND state='ACTIVE') THEN RAISE EXCEPTION 'A2_CAPABILITY_REVOKED'; END IF;
    END LOOP;
    FOR item IN SELECT * FROM jsonb_array_elements(p->'tasks') LOOP
      INSERT INTO awe_e1_runtime.task(mission_id,task_id,project_id,state,document,capability_id,capability_version,executor_kind,priority,resource_keys,model_routes,deadline,reserve_cap,max_claims,output_schema,plan_digest)
        VALUES(missionid,item->'spec'->>'task_id',projectid,'READY',item->'spec',item->'spec'->'capability'->>'capability_id',item->'spec'->'capability'->>'version',item->>'executor_kind',(item->>'priority')::int,item->'resource_keys',item->'model_routes',(item->'spec'->>'deadline')::timestamptz,(item->'spec'->'budget'->>'amount_micros')::bigint,(item->>'max_claims')::int,item->'output_schema',p->>'plan_digest')
        ON CONFLICT(mission_id,task_id) DO UPDATE SET state='READY',document=EXCLUDED.document,capability_id=EXCLUDED.capability_id,capability_version=EXCLUDED.capability_version,executor_kind=EXCLUDED.executor_kind,priority=EXCLUDED.priority,resource_keys=EXCLUDED.resource_keys,model_routes=EXCLUDED.model_routes,deadline=EXCLUDED.deadline,reserve_cap=EXCLUDED.reserve_cap,max_claims=EXCLUDED.max_claims,claims=0,producer_id=NULL,result_hash=NULL,result=NULL,reason=NULL,output_schema=EXCLUDED.output_schema,plan_digest=EXCLUDED.plan_digest,is_current=true;
    END LOOP;
    FOR item IN SELECT * FROM jsonb_array_elements(p->'tasks') LOOP FOR dep IN SELECT * FROM jsonb_array_elements(item->'spec'->'depends_on') LOOP
      INSERT INTO awe_e1_runtime.task_dependency VALUES(missionid,item->'spec'->>'task_id',dep#>>'{}');
    END LOOP; END LOOP;
    PERFORM awe_e1_runtime.emit(projectid,missionid,NULL,'MISSION_ADMITTED',jsonb_build_object('plan_digest',p->>'plan_digest'));
    RETURN jsonb_build_object('status','ADMITTED','mission_id',missionid,'repeated',false);
  END IF;

  SELECT * INTO pp FROM awe_e1_runtime.project WHERE project_id=projectid FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'A2_PROJECT_SCOPE'; END IF;

  IF op='recover' OR op='claim' THEN
    FOR rr IN SELECT l.mission_id,l.task_id FROM awe_e1_runtime.lease l WHERE l.project_id=projectid AND NOT l.held AND l.expires_at<=clock_timestamp() ORDER BY l.mission_id,l.task_id FOR UPDATE SKIP LOCKED LOOP
      IF EXISTS(SELECT 1 FROM awe_e1_runtime.model_attempt WHERE mission_id=rr.mission_id AND task_id=rr.task_id AND state IN('SENDING','OUTCOME_UNKNOWN')) OR EXISTS(SELECT 1 FROM awe_e1_runtime.effect_intent WHERE mission_id=rr.mission_id AND task_id=rr.task_id AND state IN('SENDING','OUTCOME_UNKNOWN')) THEN
        UPDATE awe_e1_runtime.model_attempt SET state='OUTCOME_UNKNOWN',reason='LEASE_EXPIRED_AFTER_SENDING' WHERE mission_id=rr.mission_id AND task_id=rr.task_id AND state='SENDING';
        UPDATE awe_e1_runtime.effect_intent SET state='OUTCOME_UNKNOWN',reason='LEASE_EXPIRED_AFTER_SENDING' WHERE mission_id=rr.mission_id AND task_id=rr.task_id AND state='SENDING';
        UPDATE awe_e1_runtime.task SET state='HOLD',reason='OUTCOME_UNKNOWN' WHERE mission_id=rr.mission_id AND task_id=rr.task_id;
        UPDATE awe_e1_runtime.mission SET state='HOLD',reason='OUTCOME_UNKNOWN' WHERE mission_id=rr.mission_id;
        UPDATE awe_e1_runtime.lease SET held=true WHERE mission_id=rr.mission_id AND task_id=rr.task_id;
      ELSE
        PERFORM awe_e1_runtime.release_task(projectid,rr.mission_id,rr.task_id);
        UPDATE awe_e1_runtime.task SET state=CASE WHEN claims<max_claims THEN 'READY' ELSE 'FAILED' END,reason='LEASE_EXPIRED' WHERE mission_id=rr.mission_id AND task_id=rr.task_id;
      END IF;
      PERFORM awe_e1_runtime.emit(projectid,rr.mission_id,rr.task_id,'LEASE_RECOVERED','{}');
    END LOOP;
    IF op='recover' THEN RETURN jsonb_build_object('status','RECOVERED'); END IF;
    SELECT * INTO pp FROM awe_e1_runtime.project WHERE project_id=projectid;
    IF workerid IS NULL OR NOT(p->'capabilities' IS NOT NULL) OR (p->>'lease_ms')::int NOT BETWEEN 100 AND 600000 THEN RAISE EXCEPTION 'A2_CLAIM_INPUT'; END IF;
    IF (SELECT count(*) FROM awe_e1_runtime.lease WHERE project_id=projectid)>=pp.max_parallel THEN RETURN jsonb_build_object('status','WAIT','reason','SLOTS'); END IF;
    FOR tt IN SELECT * FROM awe_e1_runtime.task t WHERE t.project_id=projectid AND t.is_current AND t.state='READY' AND t.claims<t.max_claims AND t.deadline>clock_timestamp()
      AND (missionid IS NULL OR t.mission_id=missionid) AND (taskid IS NULL OR t.task_id=taskid) AND p->'capabilities' ? t.capability_id
      AND EXISTS(SELECT 1 FROM awe_e1_runtime.capability_binding c WHERE c.project_id=projectid AND c.capability_id=t.capability_id AND c.version=t.capability_version AND c.state='ACTIVE' AND c.health_until>clock_timestamp())
      AND NOT EXISTS(SELECT 1 FROM awe_e1_runtime.task_dependency d JOIN awe_e1_runtime.task upstream ON upstream.mission_id=d.mission_id AND upstream.task_id=d.dependency_id WHERE d.mission_id=t.mission_id AND d.task_id=t.task_id AND upstream.state<>'ACCEPTED')
      AND EXISTS(SELECT 1 FROM awe_e1_runtime.mission m JOIN awe_e1_runtime.mission_grant g USING(mission_id) WHERE m.mission_id=t.mission_id AND m.state='ACTIVE' AND g.revoked_at IS NULL AND g.issued_at<=clock_timestamp() AND g.expires_at>clock_timestamp() AND m.deadline>clock_timestamp() AND g.document->'allowed_principals' ? workerid)
      ORDER BY t.priority DESC,t.deadline,t.task_id FOR UPDATE OF t SKIP LOCKED LOOP
      SELECT * INTO mm FROM awe_e1_runtime.mission WHERE mission_id=tt.mission_id FOR UPDATE;
      IF pp.spent+pp.reserved+tt.reserve_cap>pp.budget_cap OR mm.spent+mm.reserved+tt.reserve_cap>mm.budget_cap THEN CONTINUE; END IF;
      IF EXISTS(SELECT 1 FROM jsonb_array_elements_text(tt.resource_keys) r(k) LEFT JOIN awe_e1_runtime.resource_pool pool ON pool.project_id=projectid AND pool.resource_key=r.k WHERE pool.capacity IS NULL OR (SELECT count(*) FROM awe_e1_runtime.lease_slot s WHERE s.project_id=projectid AND s.resource_key=r.k)>=pool.capacity) THEN CONTINUE; END IF;
      f:=nextval('awe_e1_runtime.fence_sequence');
      item:=tt.document->'effect';
      IF item->>'effect_class'<>'NONE' THEN
        IF EXISTS(SELECT 1 FROM awe_e1_runtime.effect_intent WHERE owner_id=mm.owner_id AND business_key=item->>'business_key') THEN
          UPDATE awe_e1_runtime.task SET state='HOLD',reason='BUSINESS_KEY_EXISTS' WHERE mission_id=tt.mission_id AND task_id=tt.task_id;
          PERFORM awe_e1_runtime.emit(projectid,tt.mission_id,tt.task_id,'DUPLICATE_INTENT_BLOCKED','{}'); CONTINUE;
        END IF;
        INSERT INTO awe_e1_runtime.effect_intent(owner_id,business_key,project_id,mission_id,task_id,payload_digest,destination,effect_class,state,fence) VALUES(mm.owner_id,item->>'business_key',projectid,tt.mission_id,tt.task_id,item->>'payload_digest',item->>'destination',item->>'effect_class','RESERVED',f) ON CONFLICT(owner_id,business_key) DO NOTHING;
        IF NOT FOUND THEN UPDATE awe_e1_runtime.task SET state='HOLD',reason='BUSINESS_KEY_EXISTS' WHERE mission_id=tt.mission_id AND task_id=tt.task_id; CONTINUE; END IF;
      END IF;
      UPDATE awe_e1_runtime.project SET reserved=reserved+tt.reserve_cap WHERE project_id=projectid;
      UPDATE awe_e1_runtime.mission SET reserved=reserved+tt.reserve_cap WHERE mission_id=tt.mission_id;
      INSERT INTO awe_e1_runtime.task_reservation VALUES(tt.mission_id,tt.task_id,tt.reserve_cap,0);
      INSERT INTO awe_e1_runtime.lease(mission_id,task_id,project_id,worker_id,fence,expires_at,execution_deadline) VALUES(tt.mission_id,tt.task_id,projectid,workerid,f,LEAST(clock_timestamp()+((p->>'lease_ms')::int * interval '1 millisecond'),clock_timestamp()+((tt.document->>'timeout_ms')::int * interval '1 millisecond'),tt.deadline,mm.deadline),LEAST(clock_timestamp()+((tt.document->>'timeout_ms')::int * interval '1 millisecond'),tt.deadline,mm.deadline));
      INSERT INTO awe_e1_runtime.lease_slot SELECT projectid,r.k,tt.mission_id,tt.task_id,f FROM jsonb_array_elements_text(tt.resource_keys) r(k);
      UPDATE awe_e1_runtime.task SET state='RUNNING',fence=f,claims=claims+1,producer_id=workerid,reason=NULL WHERE mission_id=tt.mission_id AND task_id=tt.task_id;
      PERFORM awe_e1_runtime.emit(projectid,tt.mission_id,tt.task_id,'TASK_CLAIMED',jsonb_build_object('worker_id',workerid,'fence',f));
      RETURN jsonb_build_object('status','CLAIMED','project_id',projectid,'mission_id',tt.mission_id,'task_id',tt.task_id,'worker_id',workerid,'fence',f,'plan_digest',tt.plan_digest,'task',tt.document,'executor_kind',tt.executor_kind);
    END LOOP;
    RETURN jsonb_build_object('status','WAIT','reason','NO_ADMISSIBLE_READY_TASK');
  END IF;

  IF op IN('heartbeat','complete','reserve','mark_sending','effect_sending') THEN PERFORM awe_e1_runtime.assert_fence(projectid,missionid,taskid,workerid,(p->>'fence')::bigint); END IF;
  IF op='heartbeat' THEN
    IF (p->>'lease_ms')::int NOT BETWEEN 100 AND 600000 THEN RAISE EXCEPTION 'A2_LEASE_LIMIT'; END IF;
    UPDATE awe_e1_runtime.lease l SET expires_at=LEAST(clock_timestamp()+((p->>'lease_ms')::int * interval '1 millisecond'),l.execution_deadline,t.deadline,m.deadline) FROM awe_e1_runtime.task t,awe_e1_runtime.mission m WHERE l.mission_id=missionid AND l.task_id=taskid AND t.mission_id=l.mission_id AND t.task_id=l.task_id AND m.mission_id=l.mission_id;
    RETURN jsonb_build_object('status','RENEWED');
  ELSIF op='complete' THEN
    IF EXISTS(SELECT 1 FROM awe_e1_runtime.model_attempt WHERE mission_id=missionid AND task_id=taskid AND state IN('RESERVED','SENDING','OUTCOME_UNKNOWN')) OR EXISTS(SELECT 1 FROM awe_e1_runtime.effect_intent WHERE mission_id=missionid AND task_id=taskid AND state<>'CONFIRMED') THEN RAISE EXCEPTION 'A2_UNSETTLED_ATTEMPT'; END IF;
    PERFORM awe_e1_runtime.release_task(projectid,missionid,taskid);
    UPDATE awe_e1_runtime.task SET state='WAIT_QA',result=p->'result',result_hash=p->>'result_hash' WHERE mission_id=missionid AND task_id=taskid;
    PERFORM awe_e1_runtime.emit(projectid,missionid,taskid,'RESULT_PROPOSED',jsonb_build_object('result_hash',p->>'result_hash'));
    RETURN jsonb_build_object('status','WAIT_QA','result_hash',p->>'result_hash');
  ELSIF op='reserve' THEN
    SELECT * INTO tt FROM awe_e1_runtime.task WHERE mission_id=missionid AND task_id=taskid;
    IF tt.executor_kind<>'llm' OR tt.capability_id<>p->>'capability_id' OR tt.capability_version<>p->>'capability_version' OR NOT(tt.model_routes ? (p->>'route_id')) THEN RAISE EXCEPTION 'A2_MODEL_ROUTE_SCOPE'; END IF;
    reserve_value:=(p->>'reserve_micros')::bigint; quota_value:=(p->>'quota_units')::bigint;
    IF reserve_value<0 OR quota_value<1 THEN RAISE EXCEPTION 'A2_RESERVE_LIMIT'; END IF;
    SELECT * INTO aa FROM awe_e1_runtime.model_attempt WHERE attempt_id=p->>'attempt_id' FOR UPDATE;
    IF FOUND THEN
      IF aa.project_id<>projectid OR aa.mission_id<>missionid OR aa.task_id<>taskid OR aa.logical_request_id<>p->>'logical_request_id' OR aa.worker_id<>workerid OR aa.fence<>(p->>'fence')::bigint OR aa.route_id<>p->>'route_id' OR aa.request_hash<>p->>'request_hash' OR aa.reserved<>reserve_value OR aa.quota_units<>quota_value THEN RAISE EXCEPTION 'A2_ATTEMPT_ID_CONFLICT'; END IF;
      RETURN jsonb_build_object('status',aa.state,'attempt_id',aa.attempt_id,'reserve_micros',aa.reserved,'repeated',true);
    END IF;
    IF EXISTS(SELECT 1 FROM awe_e1_runtime.model_attempt WHERE mission_id=missionid AND logical_request_id=p->>'logical_request_id' AND state IN('RESERVED','SENDING','OUTCOME_UNKNOWN','CONFIRMED')) THEN RAISE EXCEPTION 'A2_NO_BLIND_RETRY'; END IF;
    IF EXISTS(SELECT 1 FROM awe_e1_runtime.model_attempt WHERE mission_id=missionid AND task_id=taskid AND state IN('RESERVED','SENDING','OUTCOME_UNKNOWN')) THEN RAISE EXCEPTION 'A2_NO_BLIND_RETRY'; END IF;
    IF (SELECT count(*) FROM awe_e1_runtime.model_attempt WHERE mission_id=missionid AND task_id=taskid)>=(tt.document->'retry'->>'max_attempts')::int THEN RAISE EXCEPTION 'A2_ATTEMPT_LIMIT'; END IF;
    IF pp.quota_used+quota_value>pp.quota_cap THEN RAISE EXCEPTION 'A2_QUOTA_EXHAUSTED'; END IF;
    UPDATE awe_e1_runtime.task_reservation SET allocated=allocated+reserve_value WHERE mission_id=missionid AND task_id=taskid AND allocated+reserve_value<=amount;
    IF NOT FOUND THEN RAISE EXCEPTION 'A2_RESERVE_EXHAUSTED'; END IF;
    INSERT INTO awe_e1_runtime.model_attempt(attempt_id,project_id,mission_id,task_id,logical_request_id,worker_id,fence,route_id,request_hash,reserved,quota_units,state) VALUES(p->>'attempt_id',projectid,missionid,taskid,p->>'logical_request_id',workerid,(p->>'fence')::bigint,p->>'route_id',p->>'request_hash',reserve_value,quota_value,'RESERVED');
    UPDATE awe_e1_runtime.project SET quota_used=quota_used+quota_value WHERE project_id=projectid;
    PERFORM awe_e1_runtime.emit(projectid,missionid,taskid,'MODEL_RESERVED',jsonb_build_object('attempt_id',p->>'attempt_id','reserve_micros',reserve_value,'quota_units',quota_value));
    RETURN jsonb_build_object('status','RESERVED','attempt_id',p->>'attempt_id','reserve_micros',reserve_value);
  ELSIF op IN('mark_sending','settle','unknown','fail_before_send') THEN
    SELECT * INTO aa FROM awe_e1_runtime.model_attempt WHERE attempt_id=p->>'attempt_id' FOR UPDATE;
    IF NOT FOUND OR aa.project_id<>projectid OR aa.mission_id<>missionid OR aa.task_id<>taskid OR aa.worker_id<>workerid OR aa.fence<>(p->>'fence')::bigint OR aa.logical_request_id<>p->>'logical_request_id' THEN RAISE EXCEPTION 'A2_ATTEMPT_SCOPE'; END IF;
    IF op='mark_sending' THEN
      IF aa.state<>'RESERVED' THEN RAISE EXCEPTION 'A2_NO_BLIND_RETRY'; END IF;
      UPDATE awe_e1_runtime.model_attempt SET state='SENDING' WHERE attempt_id=aa.attempt_id;
      PERFORM awe_e1_runtime.emit(projectid,missionid,taskid,'MODEL_SENDING',jsonb_build_object('attempt_id',aa.attempt_id));
      RETURN jsonb_build_object('status','SENDING','attempt_id',aa.attempt_id);
    ELSIF op='unknown' THEN
      IF aa.state NOT IN('RESERVED','SENDING','OUTCOME_UNKNOWN') THEN RAISE EXCEPTION 'A2_ATTEMPT_STATE'; END IF;
      UPDATE awe_e1_runtime.model_attempt SET state='OUTCOME_UNKNOWN',reason=p->>'reason' WHERE attempt_id=aa.attempt_id;
      UPDATE awe_e1_runtime.task SET state='HOLD',reason='MODEL_OUTCOME_UNKNOWN' WHERE mission_id=missionid AND task_id=taskid;
      UPDATE awe_e1_runtime.mission SET state='HOLD',reason='MODEL_OUTCOME_UNKNOWN' WHERE mission_id=missionid;
      UPDATE awe_e1_runtime.lease SET held=true WHERE mission_id=missionid AND task_id=taskid;
      PERFORM awe_e1_runtime.emit(projectid,missionid,taskid,'MODEL_OUTCOME_UNKNOWN',jsonb_build_object('attempt_id',aa.attempt_id));
      RETURN jsonb_build_object('status','OUTCOME_UNKNOWN','hold',true);
    ELSIF op='fail_before_send' THEN
      IF aa.state='FAILED' AND aa.reason IN('PROVEN_NO_SEND','PROVEN_NO_SEND_RELEASE') THEN RETURN jsonb_build_object('status','FAILED','repeated',true,'quota_released',true); END IF;
      IF aa.state<>'RESERVED' THEN RAISE EXCEPTION 'A2_NO_BLIND_RETRY'; END IF;
      UPDATE awe_e1_runtime.model_attempt SET state='FAILED',reason='PROVEN_NO_SEND' WHERE attempt_id=aa.attempt_id;
      UPDATE awe_e1_runtime.task_reservation SET allocated=allocated-aa.reserved WHERE mission_id=missionid AND task_id=taskid;
      UPDATE awe_e1_runtime.project SET quota_used=quota_used-aa.quota_units WHERE project_id=projectid;
      PERFORM awe_e1_runtime.release_task(projectid,missionid,taskid);
      UPDATE awe_e1_runtime.task SET state=CASE WHEN claims<max_claims AND EXISTS(SELECT 1 FROM awe_e1_runtime.mission m JOIN awe_e1_runtime.mission_grant g USING(mission_id) WHERE m.mission_id=missionid AND m.state='ACTIVE' AND g.revoked_at IS NULL AND g.expires_at>clock_timestamp() AND m.deadline>clock_timestamp()) THEN 'READY' ELSE 'FAILED' END,reason='PROVEN_NO_SEND' WHERE mission_id=missionid AND task_id=taskid AND fence=aa.fence;
      PERFORM awe_e1_runtime.emit(projectid,missionid,taskid,'MODEL_PROVEN_NO_SEND',jsonb_build_object('attempt_id',aa.attempt_id,'quota_released',aa.quota_units));
      RETURN jsonb_build_object('status','FAILED','quota_released',true);
    ELSE
      actual_value:=(p->>'actual_cost_micros')::bigint;
      IF aa.state='CONFIRMED' THEN
        IF aa.actual_cost=actual_value AND aa.provider_ref=p->>'provider_ref' AND aa.usage=p->'usage' THEN RETURN jsonb_build_object('status','CONFIRMED','repeated',true); END IF;
        RAISE EXCEPTION 'A2_SETTLEMENT_CONFLICT';
      END IF;
      IF aa.state NOT IN('SENDING','OUTCOME_UNKNOWN') OR actual_value<0 OR actual_value>aa.reserved OR p->>'provider_ref' IS NULL OR p->'usage' IS NULL THEN RAISE EXCEPTION 'A2_SETTLEMENT_LIMIT'; END IF;
      UPDATE awe_e1_runtime.model_attempt SET state='CONFIRMED',actual_cost=actual_value,usage=p->'usage',provider_ref=p->>'provider_ref' WHERE attempt_id=aa.attempt_id;
      UPDATE awe_e1_runtime.task_reservation SET amount=amount-actual_value,allocated=allocated-aa.reserved WHERE mission_id=missionid AND task_id=taskid;
      UPDATE awe_e1_runtime.project SET spent=spent+actual_value,reserved=reserved-actual_value WHERE project_id=projectid;
      UPDATE awe_e1_runtime.mission SET spent=spent+actual_value,reserved=reserved-actual_value WHERE mission_id=missionid;
      PERFORM awe_e1_runtime.emit(projectid,missionid,taskid,'MODEL_SETTLED',jsonb_build_object('attempt_id',aa.attempt_id,'actual_cost_micros',actual_value));
      RETURN jsonb_build_object('status','CONFIRMED','actual_cost_micros',actual_value);
    END IF;
  ELSIF op IN('effect_sending','effect_confirm','effect_unknown') THEN
    SELECT * INTO ii FROM awe_e1_runtime.effect_intent WHERE project_id=projectid AND mission_id=missionid AND task_id=taskid FOR UPDATE;
    IF NOT FOUND OR ii.fence<>(p->>'fence')::bigint THEN RAISE EXCEPTION 'A2_INTENT_SCOPE'; END IF;
    IF op='effect_sending' THEN
      IF ii.state<>'RESERVED' THEN RAISE EXCEPTION 'A2_NO_BLIND_RETRY'; END IF;
      UPDATE awe_e1_runtime.effect_intent SET state='SENDING' WHERE intent_id=ii.intent_id;
      PERFORM awe_e1_runtime.emit(projectid,missionid,taskid,'EFFECT_SENDING',jsonb_build_object('intent_id',ii.intent_id));
      RETURN jsonb_build_object('status','SENDING','intent_id',ii.intent_id,'business_key',ii.business_key,'payload_digest',ii.payload_digest,'destination',ii.destination);
    ELSIF op='effect_unknown' THEN
      IF ii.state NOT IN('RESERVED','SENDING','OUTCOME_UNKNOWN') THEN RAISE EXCEPTION 'A2_INTENT_STATE'; END IF;
      UPDATE awe_e1_runtime.effect_intent SET state='OUTCOME_UNKNOWN',reason=p->>'reason' WHERE intent_id=ii.intent_id;
      UPDATE awe_e1_runtime.task SET state='HOLD',reason='EFFECT_OUTCOME_UNKNOWN' WHERE mission_id=missionid AND task_id=taskid;
      UPDATE awe_e1_runtime.mission SET state='HOLD',reason='EFFECT_OUTCOME_UNKNOWN' WHERE mission_id=missionid;
      UPDATE awe_e1_runtime.lease SET held=true WHERE mission_id=missionid AND task_id=taskid;
      RETURN jsonb_build_object('status','OUTCOME_UNKNOWN','hold',true);
    ELSE
      IF ii.state='CONFIRMED' AND ii.provider_ref=p->>'provider_ref' AND ii.receipt=p->'receipt' THEN RETURN jsonb_build_object('status','CONFIRMED','repeated',true); END IF;
      IF ii.state NOT IN('SENDING','OUTCOME_UNKNOWN') OR p->>'provider_ref' IS NULL OR p->'receipt' IS NULL THEN RAISE EXCEPTION 'A2_RECONCILIATION_PROOF_REQUIRED'; END IF;
      UPDATE awe_e1_runtime.effect_intent SET state='CONFIRMED',provider_ref=p->>'provider_ref',receipt=p->'receipt' WHERE intent_id=ii.intent_id;
      PERFORM awe_e1_runtime.emit(projectid,missionid,taskid,'EFFECT_CONFIRMED',jsonb_build_object('intent_id',ii.intent_id));
      RETURN jsonb_build_object('status','CONFIRMED');
    END IF;
  ELSIF op='revoke_capability' THEN
    IF pp.owner_id<>p->>'owner_id' THEN RAISE EXCEPTION 'A2_OWNER_REQUIRED'; END IF;
    UPDATE awe_e1_runtime.capability_binding SET state='REVOKED' WHERE project_id=projectid AND capability_id=p->>'capability_id';
    PERFORM awe_e1_runtime.emit(projectid,NULL,NULL,'CAPABILITY_REVOKED',jsonb_build_object('capability_id',p->>'capability_id'));
    RETURN jsonb_build_object('status','REVOKED');
  ELSIF op IN('cancel','revoke') THEN
    SELECT * INTO mm FROM awe_e1_runtime.mission WHERE project_id=projectid AND mission_id=missionid FOR UPDATE;
    IF NOT FOUND OR mm.owner_id<>p->>'owner_id' THEN RAISE EXCEPTION 'A2_OWNER_REQUIRED'; END IF;
    UPDATE awe_e1_runtime.mission SET state=CASE WHEN op='revoke' THEN 'REVOKED' ELSE 'CANCELLED' END,reason=p->>'reason' WHERE mission_id=missionid;
    IF op='revoke' THEN UPDATE awe_e1_runtime.mission_grant SET revoked_at=nowat WHERE mission_id=missionid; END IF;
    FOR tt IN SELECT * FROM awe_e1_runtime.task WHERE mission_id=missionid AND state NOT IN('ACCEPTED','FAILED','CANCELLED') FOR UPDATE LOOP
      IF EXISTS(SELECT 1 FROM awe_e1_runtime.model_attempt WHERE mission_id=missionid AND task_id=tt.task_id AND state IN('SENDING','OUTCOME_UNKNOWN')) OR EXISTS(SELECT 1 FROM awe_e1_runtime.effect_intent WHERE mission_id=missionid AND task_id=tt.task_id AND state IN('SENDING','OUTCOME_UNKNOWN')) THEN
        UPDATE awe_e1_runtime.task SET state='HOLD',reason='CANCELLED_WITH_UNKNOWN' WHERE mission_id=missionid AND task_id=tt.task_id;
        UPDATE awe_e1_runtime.model_attempt SET state='OUTCOME_UNKNOWN' WHERE mission_id=missionid AND task_id=tt.task_id AND state='SENDING';
        UPDATE awe_e1_runtime.effect_intent SET state='OUTCOME_UNKNOWN' WHERE mission_id=missionid AND task_id=tt.task_id AND state='SENDING';
        UPDATE awe_e1_runtime.lease SET held=true WHERE mission_id=missionid AND task_id=tt.task_id;
      ELSE
        PERFORM awe_e1_runtime.release_task(projectid,missionid,tt.task_id);
        UPDATE awe_e1_runtime.task SET state='CANCELLED' WHERE mission_id=missionid AND task_id=tt.task_id;
      END IF;
    END LOOP;
    PERFORM awe_e1_runtime.emit(projectid,missionid,NULL,upper(op),'{}');
    RETURN jsonb_build_object('status',CASE WHEN op='revoke' THEN 'REVOKED' ELSE 'CANCELLED' END);
  ELSIF op='qa_evaluate' THEN
    SELECT * INTO tt FROM awe_e1_runtime.task WHERE project_id=projectid AND mission_id=missionid AND task_id=taskid FOR UPDATE;
    IF NOT FOUND OR NOT tt.is_current OR tt.plan_digest IS DISTINCT FROM p->>'plan_digest' OR tt.state<>'WAIT_QA' OR tt.result_hash<>p->>'result_hash' OR tt.producer_id=p->>'evaluator_id' THEN RAISE EXCEPTION 'A2_QA_BINDING'; END IF;
    IF p->>'verdict' NOT IN('PASS','FAIL') OR jsonb_typeof(p->'checks')<>'array' OR jsonb_array_length(p->'checks')=0 THEN RAISE EXCEPTION 'A2_QA_CHECKS'; END IF;
    IF p->>'verdict'='PASS' AND (EXISTS(SELECT 1 FROM jsonb_array_elements(p->'checks') ch WHERE ch->>'passed' IS DISTINCT FROM 'true') OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(tt.document->'qa'->'required_checks') k WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p->'checks') ch WHERE ch->>'check_id'=k))) THEN RAISE EXCEPTION 'A2_QA_CHECKS'; END IF;
    INSERT INTO awe_e1_runtime.qa_revision VALUES(missionid,tt.plan_digest,taskid,tt.result_hash,p->>'evaluator_id',p->>'verdict',p->'checks',nowat);
    UPDATE awe_e1_runtime.task SET state=CASE WHEN p->>'verdict'='PASS' THEN 'ACCEPTED' ELSE 'FAILED' END WHERE mission_id=missionid AND task_id=taskid;
    IF NOT EXISTS(SELECT 1 FROM awe_e1_runtime.task WHERE mission_id=missionid AND is_current AND state<>'ACCEPTED') THEN UPDATE awe_e1_runtime.mission SET state='COMPLETE' WHERE mission_id=missionid AND state='ACTIVE'; END IF;
    PERFORM awe_e1_runtime.emit(projectid,missionid,taskid,'QA_'||(p->>'verdict'),jsonb_build_object('result_hash',tt.result_hash,'evaluator_id',p->>'evaluator_id'));
    RETURN jsonb_build_object('status',CASE WHEN p->>'verdict'='PASS' THEN 'ACCEPTED' ELSE 'FAILED' END);
  ELSIF op='snapshot' THEN
    RETURN jsonb_build_object('project',to_jsonb(pp),'missions',COALESCE((SELECT jsonb_agg(to_jsonb(m)) FROM awe_e1_runtime.mission m WHERE project_id=projectid),'[]'::jsonb),'tasks',COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY mission_id,task_id) FROM awe_e1_runtime.task t WHERE project_id=projectid),'[]'::jsonb),'task_history',COALESCE((SELECT jsonb_agg(to_jsonb(h)) FROM awe_e1_runtime.task_revision h JOIN awe_e1_runtime.mission m USING(mission_id) WHERE m.project_id=projectid),'[]'::jsonb),'plans',COALESCE((SELECT jsonb_agg(to_jsonb(r)) FROM awe_e1_runtime.plan_revision r JOIN awe_e1_runtime.mission m USING(mission_id) WHERE m.project_id=projectid),'[]'::jsonb),'leases',COALESCE((SELECT jsonb_agg(to_jsonb(l)) FROM awe_e1_runtime.lease l WHERE project_id=projectid),'[]'::jsonb),'attempts',COALESCE((SELECT jsonb_agg(to_jsonb(a)) FROM awe_e1_runtime.model_attempt a WHERE project_id=projectid),'[]'::jsonb),'intents',COALESCE((SELECT jsonb_agg(to_jsonb(i)) FROM awe_e1_runtime.effect_intent i WHERE project_id=projectid),'[]'::jsonb));
  ELSIF op='events' THEN
    RETURN COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY sequence) FROM (SELECT * FROM awe_e1_runtime.event WHERE project_id=projectid AND sequence>COALESCE((p->>'after')::bigint,0) ORDER BY sequence LIMIT 256)e),'[]'::jsonb);
  ELSIF op='get_cursor' THEN
    RETURN jsonb_build_object('sequence',COALESCE((SELECT sequence FROM awe_e1_runtime.event_cursor WHERE project_id=projectid AND consumer_id=p->>'consumer_id'),0));
  ELSIF op='ack_cursor' THEN
    seq_value:=(p->>'sequence')::bigint;
    IF seq_value<0 OR seq_value>COALESCE((SELECT max(sequence) FROM awe_e1_runtime.event WHERE project_id=projectid),0) THEN RAISE EXCEPTION 'A2_CURSOR_RANGE'; END IF;
    IF NOT EXISTS(SELECT 1 FROM awe_e1_runtime.event_cursor WHERE project_id=projectid AND consumer_id=p->>'consumer_id') AND (p->>'expected_sequence')::bigint<>0 THEN RAISE EXCEPTION 'A2_CURSOR_CAS'; END IF;
    INSERT INTO awe_e1_runtime.event_cursor VALUES(projectid,p->>'consumer_id',seq_value) ON CONFLICT(project_id,consumer_id) DO UPDATE SET sequence=EXCLUDED.sequence WHERE awe_e1_runtime.event_cursor.sequence=(p->>'expected_sequence')::bigint AND EXCLUDED.sequence>=awe_e1_runtime.event_cursor.sequence;
    IF NOT FOUND THEN RAISE EXCEPTION 'A2_CURSOR_CAS'; END IF;
    RETURN jsonb_build_object('sequence',seq_value);
  ELSIF op='inbox' THEN
    SELECT * INTO rr FROM awe_e1_runtime.inbox_event WHERE project_id=projectid AND source_id=p->>'source_id' AND event_id=p->>'event_id';
    IF FOUND THEN IF rr.payload_hash<>p->>'payload_hash' THEN RAISE EXCEPTION 'A2_INBOX_CONFLICT'; END IF; RETURN jsonb_build_object('sequence',rr.sequence,'repeated',true); END IF;
    INSERT INTO awe_e1_runtime.event(project_id,kind,body) VALUES(projectid,'INBOX',p->'body') RETURNING sequence INTO seq_value;
    INSERT INTO awe_e1_runtime.inbox_event VALUES(projectid,p->>'source_id',p->>'event_id',p->>'payload_hash',p->'body',seq_value);
    RETURN jsonb_build_object('sequence',seq_value,'repeated',false);
  END IF;
  RAISE EXCEPTION 'A2_UNKNOWN_OPERATION';
EXCEPTION WHEN OTHERS THEN
  -- Exception subtransaction rolls back every mutation in the rejected command.
  RETURN jsonb_build_object('error',CASE WHEN SQLERRM ~ '^A2_[A-Z_]+$' THEN SQLERRM ELSE 'A2_DATABASE_REJECT' END);
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA awe_e1_runtime FROM PUBLIC,awe_e1_coord,awe_e1_worker,awe_e1_qa;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA awe_e1_runtime FROM PUBLIC,awe_e1_coord,awe_e1_worker,awe_e1_qa;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA awe_e1_runtime FROM PUBLIC,awe_e1_coord,awe_e1_worker,awe_e1_qa;
GRANT USAGE ON SCHEMA awe_e1_runtime TO awe_e1_coord,awe_e1_qa;
GRANT EXECUTE ON FUNCTION awe_e1_runtime.command(text,jsonb),awe_e1_runtime.resource_info() TO awe_e1_coord,awe_e1_qa;
INSERT INTO awe_e1_runtime.schema_migration VALUES(1,clock_timestamp()) ON CONFLICT DO NOTHING;
COMMIT;
