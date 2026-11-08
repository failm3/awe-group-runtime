-- MASTER01 E0 candidate. Real PostgreSQL validation NOT_RUN.
-- Additive producer for OWNER02's local consumer, in the SAME D09 ledger.
-- Prerequisites: D09 SQL001, INT03 SQL001-004, MASTER01 SQL005, owner enrollment.
-- No enrollment, credentials, role memberships, budget topups or dispatch here.
BEGIN;
CREATE ROLE awe_d09_local_master01 NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE awe_d09_local_issuer_master01 NOLOGIN NOSUPERUSER NOBYPASSRLS;
SET LOCAL ROLE awe_d09_owner;
ALTER TABLE awe_d09.projects ADD COLUMN local_policy_master01 jsonb;
ALTER TABLE awe_d09.principals ADD COLUMN local_generation_master01 bigint CHECK(local_generation_master01>0),
 ADD COLUMN local_subject_master01 text,ADD COLUMN local_role_master01 text;
ALTER TABLE awe_d09.approvals ADD COLUMN local_plan_master01 jsonb;
ALTER TABLE awe_d09.grants ADD COLUMN local_body_master01 jsonb,ADD COLUMN local_token_hash_master01 text;
ALTER TABLE awe_d09.results ADD COLUMN local_output_master01 jsonb;

CREATE FUNCTION awe_d09.local_hash_master01(v jsonb) RETURNS text LANGUAGE sql IMMUTABLE
 SET search_path=pg_catalog,awe_int03 AS $$ SELECT awe_int03.hash(awe_int03.native_canonical_cr01(v)) $$;
CREATE FUNCTION awe_d09.local_role_master01(issuer boolean DEFAULT false) RETURNS void LANGUAGE plpgsql
 SET search_path=pg_catalog,awe_d09 AS $$ BEGIN
 IF issuer THEN
  IF NOT pg_has_role(session_user,'awe_d09_local_issuer_master01','MEMBER')
   OR NOT pg_has_role(session_user,'awe_d09_issuer','MEMBER')
   OR pg_has_role(session_user,'awe_d09_local_master01','MEMBER')
   OR pg_has_role(session_user,'awe_d09_api','MEMBER') THEN RAISE EXCEPTION 'LOCAL_ISSUER_ROLE'; END IF;
 ELSE
  IF NOT pg_has_role(session_user,'awe_d09_local_master01','MEMBER')
   OR pg_has_role(session_user,'awe_d09_local_issuer_master01','MEMBER')
   OR pg_has_role(session_user,'awe_d09_issuer','MEMBER') OR pg_has_role(session_user,'awe_d09_api','MEMBER')
   OR pg_has_role(session_user,'awe_d09_reconciler','MEMBER') OR pg_has_role(session_user,'awe_d03_writer_master01','MEMBER') THEN RAISE EXCEPTION 'LOCAL_WORKER_ROLE'; END IF;
 END IF;
END $$;
CREATE FUNCTION awe_d09.local_state_master01(pr awe_d09.projects,r jsonb) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,awe_d09,awe_int03 AS $$
DECLARE dp jsonb;dt jsonb;sp jsonb;op jsonb;policy jsonb:=pr.local_policy_master01;ep jsonb; BEGIN
 IF pr.halted OR pr.restore_pending OR pr.d03_body_master01 IS NULL
  OR encode(sha256(convert_to(pr.d03_body_master01,'UTF8')),'hex') IS DISTINCT FROM pr.d03_hash_master01
  THEN RAISE EXCEPTION 'LOCAL_DURABLE_STATE_REQUIRED'; END IF;
 dp:=pr.d03_body_master01::jsonb#>ARRAY['data','projects',pr.project_id];dt:=dp#>ARRAY['tasks',r->>'task_id'];
 ep:=jsonb_build_object('auth',pr.auth_epoch,'policy',pr.policy_epoch,'owner',pr.owner_epoch,'stop',pr.stop_epoch-1);
 -- Explicit vocabulary mapping: D03 stop starts at 0; legacy D09 starts at 1.
 -- Any drift closes execution. This function never changes either epoch owner.
 IF dp->>'status' IS DISTINCT FROM 'READY' OR dt IS NULL OR dt->>'state' IS DISTINCT FROM 'RUNNING'
  OR dt->'cancel_requested' IS DISTINCT FROM 'false'::jsonb OR dt->'restore_pending' IS DISTINCT FROM 'false'::jsonb
  OR dt->'acceptance_stale' IS DISTINCT FROM 'false'::jsonb OR dt->'spec' IS DISTINCT FROM r#>'{local,spec}'
  OR dp->'epochs' IS DISTINCT FROM ep OR r->'epochs' IS DISTINCT FROM ep
  OR dt->'revision' IS DISTINCT FROM r->'revision' OR dt->'fence' IS DISTINCT FROM r->'fence'
  OR dt->'lease' IS DISTINCT FROM r#>'{local,lease}'
  OR (dt#>>'{lease,expires_at}')::timestamptz<=clock_timestamp()
  OR r->>'project_id' IS DISTINCT FROM pr.project_id THEN RAISE EXCEPTION 'LOCAL_D03_BINDING'; END IF;
 sp:=dp#>ARRAY['specs',(dt#>>'{spec,spec_id}')||':'||(dt#>>'{spec,revision}'),'content'];op:=dp#>ARRAY['operations',r->>'operation_id'];
 IF sp->>'dialect' IS DISTINCT FROM 'MASTER01_LITERAL_TEXT_V1' OR sp->'input' IS DISTINCT FROM r->'payload'
  OR sp->>'capability' IS DISTINCT FROM 'fs.write' OR sp->>'write_semantics' IS DISTINCT FROM 'CREATE_EXCLUSIVE'
  OR awe_d09.local_hash_master01(sp) IS DISTINCT FROM dt#>>'{spec,content_hash}'
  OR awe_d09.local_hash_master01(r->'payload') IS DISTINCT FROM r->>'payload_hash'
  OR op->>'status' IS DISTINCT FROM 'INTENT' OR op->>'effect_class' IS DISTINCT FROM 'IDEMPOTENT_WRITE'
  OR op#>>'{binding,payload_hash}' IS DISTINCT FROM r->>'payload_hash'
  OR op#>>'{binding,tool_id}' IS DISTINCT FROM r->>'tool_id'
  OR op#>>'{binding,tool_digest}' IS DISTINCT FROM r->>'tool_digest'
  OR op->'spec' IS DISTINCT FROM dt->'spec' OR op->'epochs' IS DISTINCT FROM ep
  THEN RAISE EXCEPTION 'LOCAL_EXACT_SPEC_OPERATION'; END IF;
 IF policy->>'profile' IS DISTINCT FROM 'MASTER01_LITERAL_TEXT_ONLY' OR policy->'active' IS DISTINCT FROM 'true'::jsonb
  OR policy->>'physical_decision' IS DISTINCT FROM 'DENY' OR policy->>'external_network' IS DISTINCT FROM '0'
  OR policy->>'cost_micros' IS DISTINCT FROM '0' OR policy->>'tool_id' IS DISTINCT FROM 'tool_fs_write'
  OR policy->>'manifest_hash' IS DISTINCT FROM r->>'manifest_hash'
  OR policy->>'code_digest' IS DISTINCT FROM r->>'tool_digest'
  OR policy->>'schema_hash' IS DISTINCT FROM r->>'schema_hash'
  OR policy->>'execution_binding_digest' IS DISTINCT FROM r#>>'{local,execution_binding_digest}'
  OR COALESCE((policy->>'expires_at')::bigint,0)<=floor(extract(epoch FROM clock_timestamp())*1000)
  OR r->>'reserve_micros' IS DISTINCT FROM '0' OR r->>'tool_id' IS DISTINCT FROM 'tool_fs_write'
  OR r#>>'{local,profile}' IS DISTINCT FROM 'E0_LOCAL_REVIEWED_ONLY'
  OR r#>'{local,limits,external_network}' IS DISTINCT FROM '0'::jsonb
  OR r->'approval_token' IS DISTINCT FROM 'null'::jsonb
  OR r#>'{local,deadline}' IS DISTINCT FROM r->'expires_at'
  OR (r#>>'{local,lease_until}')::bigint IS DISTINCT FROM floor(extract(epoch FROM (dt#>>'{lease,expires_at}')::timestamptz)*1000)::bigint
  OR COALESCE((r->>'expires_at')::bigint,0)<=floor(extract(epoch FROM clock_timestamp())*1000)
  OR (r->>'expires_at')::bigint>floor(extract(epoch FROM (dt#>>'{lease,expires_at}')::timestamptz)*1000)
  THEN RAISE EXCEPTION 'LOCAL_OWNER_POLICY_NOT_ENROLLED'; END IF;
END $$;

CREATE FUNCTION awe_d09.register_local_master01(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09,awe_int03 AS $$
DECLARE r jsonb:=j->'request';au jsonb:=j->'authorization';pr awe_d09.projects;who awe_d09.principals;
 ap awe_d09.approvals;old awe_d09.grants;g jsonb;entry jsonb;parent jsonb;subject awe_d09.principals;issuer awe_d09.principals;
 budget awe_d09.budgets;local_budget_id text;gid text;aid text;tid text;origin text:='master01_local_origin';idx integer:=0;lineage jsonb:=j->'lineage';stored_plan jsonb;
BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['profile','request','authorization','lineage','binding','plan_hash']);
 PERFORM awe_d09.local_role_master01(true);pr:=awe_d09.lock_project(r->>'project_id','ISSUE');PERFORM awe_d09.local_state_master01(pr,r);
 IF j->>'profile' IS DISTINCT FROM 'E0_LOCAL_REVIEWED_ONLY'
  OR j->>'binding' IS DISTINCT FROM awe_d09.local_hash_master01(r-'approval_token')
  OR j->>'plan_hash' IS DISTINCT FROM awe_d09.local_hash_master01(jsonb_build_object('profile',j->'profile','request',r,'authorization',au,'binding',j->'binding'))
  OR jsonb_typeof(lineage) IS DISTINCT FROM 'array' OR jsonb_array_length(lineage) NOT BETWEEN 1 AND 3
  OR jsonb_typeof(au->'lineage') IS DISTINCT FROM 'array' OR jsonb_array_length(au->'lineage')<>jsonb_array_length(lineage)
  OR lineage#>>'{0,token_hash}' IS DISTINCT FROM awe_int03.hash(r->>'grant_token')
  OR au->>'max_cost_micros' IS DISTINCT FROM '0' THEN RAISE EXCEPTION 'LOCAL_REGISTRATION_BINDING'; END IF;
 SELECT * INTO who FROM awe_d09.principals WHERE login=(au->>'database_login')::name FOR SHARE;
 IF who.login IS NULL OR who.revoked OR who.valid_until<=clock_timestamp() OR who.actor_id IS DISTINCT FROM au->>'actor_id'
  OR who.local_subject_master01 IS DISTINCT FROM au->>'subject' OR who.local_role_master01 IS DISTINCT FROM 'WORKER'
  OR who.login=session_user OR NOT EXISTS(SELECT 1 FROM awe_d09.memberships WHERE project_id=pr.project_id AND login=who.login AND 'EXECUTE'=ANY(permissions))
  THEN RAISE EXCEPTION 'LOCAL_WORKER_ENROLLMENT'; END IF;
 tid:=r->>'task_id';aid:=r#>>'{local,d09_approval_id}';
 -- Persist only the grant hash; a table reader must not receive a raw capability.
 stored_plan:=jsonb_set(j,'{request}',(r-'grant_token')||jsonb_build_object('grant_token_hash',awe_int03.hash(r->>'grant_token')));
 IF aid IS NULL OR aid !~ '^[A-Za-z0-9_.:-]{1,128}$' THEN RAISE EXCEPTION 'LOCAL_APPROVAL_ID'; END IF;
 SELECT * INTO ap FROM awe_d09.approvals WHERE project_id=pr.project_id AND approval_id=aid FOR UPDATE;
 IF ap.approval_id IS NOT NULL THEN
  IF ap.local_plan_master01 IS DISTINCT FROM stored_plan OR ap.used_by IS NOT NULL OR ap.revoked THEN RAISE EXCEPTION 'LOCAL_REGISTRATION_REPLAY_OR_CONFLICT'; END IF;
  RAISE EXCEPTION 'LOCAL_REGISTRATION_REPLAY_REQUIRES_RECONCILIATION';
 END IF;
 INSERT INTO awe_d09.origins(project_id,origin_id) VALUES(pr.project_id,origin) ON CONFLICT DO NOTHING;
 IF EXISTS(SELECT 1 FROM awe_d09.origins WHERE project_id=pr.project_id AND origin_id=origin AND quarantined) THEN RAISE EXCEPTION 'LOCAL_ORIGIN_QUARANTINED'; END IF;
 IF EXISTS(SELECT 1 FROM awe_d09.tasks WHERE project_id=pr.project_id AND task_id=tid) THEN RAISE EXCEPTION 'LOCAL_TASK_ALREADY_REGISTERED'; END IF;
 INSERT INTO awe_d09.tasks(project_id,task_id,origin_id,revision,fence,lease_holder,lease_until,cancelled)
 VALUES(pr.project_id,tid,origin,(r->>'revision')::bigint,(r->>'fence')::bigint,who.login,(r#>>'{local,lease,expires_at}')::timestamptz,false);
 INSERT INTO awe_d09.approvals(project_id,approval_id,task_id,actor_id,operation_id,effect_slot,payload_hash,plan_hash,cap_micros,expires_at,local_plan_master01)
 VALUES(pr.project_id,aid,tid,who.actor_id,r->>'operation_id',r->>'effect_slot',r->>'payload_hash',j->>'plan_hash',0,to_timestamp((r->>'expires_at')::numeric/1000),stored_plan);
 -- Shared project/origin/day/month/account budgets must already be owner funded.
 -- A new task ID never resets any of those counters. Attach every live shared cap.
 INSERT INTO awe_d09.task_budgets(project_id,task_id,budget_id)
 SELECT pr.project_id,tid,b.budget_id FROM awe_d09.budgets b WHERE b.project_id=pr.project_id
  AND b.kind IN ('PROJECT','ORIGIN','DAY','MONTH','ACCOUNT') AND b.valid_until>clock_timestamp();
 IF (SELECT count(DISTINCT b.kind) FROM awe_d09.task_budgets tb JOIN awe_d09.budgets b USING(project_id,budget_id)
  WHERE tb.project_id=pr.project_id AND tb.task_id=tid)<>5 THEN RAISE EXCEPTION 'LOCAL_SHARED_BUDGETS_NOT_ENROLLED'; END IF;
 local_budget_id:='master01-task:'||tid;
 INSERT INTO awe_d09.budgets(project_id,budget_id,kind,currency,cap_micros,balance_micros,attempt_limit,valid_until)
 VALUES(pr.project_id,local_budget_id,'TASK','RUB',0,0,1,to_timestamp((r->>'expires_at')::numeric/1000));
 INSERT INTO awe_d09.task_budgets VALUES(pr.project_id,tid,local_budget_id);
 FOR entry IN SELECT value FROM jsonb_array_elements(lineage) LOOP
  g:=entry->'body';gid:=g->>'grant_id';parent:=lineage->(idx+1)->'body';
  IF g->>'kind' IS DISTINCT FROM 'grant' OR g->>'v' IS DISTINCT FROM 'sec01.v1' OR g->>'aud' IS DISTINCT FROM 'sec01.execution'
   OR g->>'project_id' IS DISTINCT FROM pr.project_id OR g->>'task_id' IS DISTINCT FROM tid
   OR g->'epochs' IS DISTINCT FROM r->'epochs' OR g->'revision' IS DISTINCT FROM r->'revision' OR g->'fence' IS DISTINCT FROM r->'fence'
   OR g->>'max_cost_micros' IS DISTINCT FROM '0' OR COALESCE((g->>'max_attempts')::integer,0) NOT BETWEEN 1 AND 2
   OR (g->>'exp')::bigint<(r->>'expires_at')::bigint OR NOT (g->'tools' @> jsonb_build_array(r->>'manifest_hash'))
   OR NOT (g->'resources' @> jsonb_build_array(r->>'resource_id')) OR g->'risks' IS DISTINCT FROM '["PROJECT_WRITE"]'::jsonb
   OR g->'domains' IS DISTINCT FROM '[]'::jsonb OR gid IS DISTINCT FROM au#>>ARRAY['lineage',idx::text,'grant_id']
   OR g->'max_attempts' IS DISTINCT FROM au#>ARRAY['lineage',idx::text,'max_attempts']
   OR g->'max_cost_micros' IS DISTINCT FROM au#>ARRAY['lineage',idx::text,'max_cost_micros']
   OR COALESCE(entry->>'token_hash','') !~ '^sha256:[a-f0-9]{64}$'
   THEN RAISE EXCEPTION 'LOCAL_SIGNED_LINEAGE_BINDING'; END IF;
  IF idx=0 AND (gid IS DISTINCT FROM au->>'grant_id' OR g->>'subject_id' IS DISTINCT FROM who.actor_id) THEN RAISE EXCEPTION 'LOCAL_LEAF_SUBJECT'; END IF;
  IF parent IS NULL THEN
   IF g->'parent_id' IS DISTINCT FROM 'null'::jsonb OR g->>'depth' IS DISTINCT FROM '0' OR g->>'issuer_id' IS DISTINCT FROM r#>>'{local,lease,holder}' THEN RAISE EXCEPTION 'LOCAL_ROOT_LINEAGE'; END IF;
  ELSIF g->>'parent_id' IS DISTINCT FROM parent->>'grant_id' OR g->>'issuer_id' IS DISTINCT FROM parent->>'subject_id'
   OR (g->>'depth')::integer<>(parent->>'depth')::integer+1 OR (g->>'exp')::bigint>(parent->>'exp')::bigint
   OR (g->>'max_attempts')::integer>(parent->>'max_attempts')::integer THEN RAISE EXCEPTION 'LOCAL_PARENT_LINEAGE'; END IF;
  SELECT * INTO subject FROM awe_d09.principals WHERE actor_id=g->>'subject_id' FOR SHARE;
  SELECT * INTO issuer FROM awe_d09.principals WHERE actor_id=g->>'issuer_id' FOR SHARE;
  IF subject.login IS NULL OR issuer.login IS NULL OR subject.revoked OR issuer.revoked
   OR subject.valid_until<=clock_timestamp() OR issuer.valid_until<=clock_timestamp()
   OR subject.local_generation_master01 IS DISTINCT FROM (g->>'subject_generation')::bigint
   OR issuer.local_generation_master01 IS DISTINCT FROM (g->>'issuer_generation')::bigint
   OR subject.local_role_master01 IS DISTINCT FROM 'WORKER'
   OR issuer.local_role_master01 IS DISTINCT FROM (CASE WHEN parent IS NULL THEN 'SUPERVISOR' ELSE 'WORKER' END)
   THEN RAISE EXCEPTION 'LOCAL_PRINCIPAL_GENERATION'; END IF;
  SELECT * INTO old FROM awe_d09.grants WHERE project_id=pr.project_id AND grant_id=gid FOR UPDATE;
  IF old.grant_id IS NULL THEN
   INSERT INTO awe_d09.grants(project_id,grant_id,approval_id,actor_id,auth_epoch,policy_epoch,owner_epoch,stop_epoch,task_revision,task_fence,expires_at,local_body_master01,local_token_hash_master01)
   VALUES(pr.project_id,gid,aid,subject.actor_id,pr.auth_epoch,pr.policy_epoch,pr.owner_epoch,pr.stop_epoch,(r->>'revision')::bigint,(r->>'fence')::bigint,to_timestamp((g->>'exp')::numeric/1000),g,entry->>'token_hash');
  ELSIF old.local_body_master01 IS DISTINCT FROM g OR old.local_token_hash_master01 IS DISTINCT FROM entry->>'token_hash' OR old.revoked
   THEN RAISE EXCEPTION 'LOCAL_GRANT_IMMUTABLE_OR_REVOKED'; END IF;
  local_budget_id:='master01-grant:'||gid;
  SELECT * INTO budget FROM awe_d09.budgets WHERE project_id=pr.project_id AND budget_id=local_budget_id FOR UPDATE;
  IF budget.budget_id IS NULL THEN
   INSERT INTO awe_d09.budgets(project_id,budget_id,kind,currency,cap_micros,balance_micros,attempt_limit,valid_until)
   VALUES(pr.project_id,local_budget_id,'ANCESTOR','RUB',0,0,(g->>'max_attempts')::bigint,to_timestamp((g->>'exp')::numeric/1000));
  ELSIF budget.kind<>'ANCESTOR' OR budget.cap_micros<>0 OR budget.attempt_limit<>(g->>'max_attempts')::bigint THEN RAISE EXCEPTION 'LOCAL_ANCESTOR_CAP_CONFLICT'; END IF;
  INSERT INTO awe_d09.task_budgets VALUES(pr.project_id,tid,local_budget_id) ON CONFLICT DO NOTHING;idx:=idx+1;
 END LOOP;
 PERFORM awe_d09.audit(pr.project_id,NULL,'LOCAL_EXACT_PLAN_REGISTERED',jsonb_build_object('task_id',tid,'plan_hash',j->>'plan_hash','binding',j->>'binding'));
 RETURN jsonb_build_object('status','REGISTERED','project_id',pr.project_id,'task_id',tid,'plan_hash',j->>'plan_hash','local_binding',j->>'binding','lineage_enforced',true,'physical_decision','DENY');
END $$;

CREATE FUNCTION awe_d09.local_assert_master01(p text,aid text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE ap awe_d09.approvals;pr awe_d09.projects;j jsonb;r jsonb;entry jsonb;g awe_d09.grants;s awe_d09.principals;i awe_d09.principals; BEGIN
 SELECT * INTO pr FROM awe_d09.projects WHERE project_id=p FOR UPDATE;
 SELECT * INTO ap FROM awe_d09.approvals WHERE project_id=p AND approval_id=aid FOR UPDATE;j:=ap.local_plan_master01;r:=j->'request';
 IF j IS NULL OR ap.revoked OR ap.expires_at<=clock_timestamp() OR r->>'project_id' IS DISTINCT FROM p
  OR EXISTS(SELECT 1 FROM awe_d09.origins WHERE project_id=p AND origin_id='master01_local_origin' AND quarantined)
  OR j#>>'{authorization,database_login}' IS DISTINCT FROM session_user::text THEN RAISE EXCEPTION 'LOCAL_AUTHORITY_NOT_BOUND'; END IF;
 PERFORM awe_d09.local_state_master01(pr,r);
 FOR entry IN SELECT value FROM jsonb_array_elements(j->'lineage') LOOP
  SELECT * INTO g FROM awe_d09.grants WHERE project_id=p AND grant_id=entry#>>'{body,grant_id}' FOR UPDATE;
  SELECT * INTO s FROM awe_d09.principals WHERE actor_id=entry#>>'{body,subject_id}' FOR SHARE;
  SELECT * INTO i FROM awe_d09.principals WHERE actor_id=entry#>>'{body,issuer_id}' FOR SHARE;
  IF g.grant_id IS NULL OR g.revoked OR g.expires_at<=clock_timestamp() OR g.local_body_master01 IS DISTINCT FROM entry->'body'
   OR g.local_token_hash_master01 IS DISTINCT FROM entry->>'token_hash' OR s.login IS NULL OR i.login IS NULL OR s.revoked OR i.revoked
   OR s.valid_until<=clock_timestamp() OR i.valid_until<=clock_timestamp()
   OR s.local_generation_master01 IS DISTINCT FROM (entry#>>'{body,subject_generation}')::bigint
   OR i.local_generation_master01 IS DISTINCT FROM (entry#>>'{body,issuer_generation}')::bigint
   THEN RAISE EXCEPTION 'LOCAL_LINEAGE_REVOKED_OR_EXPIRED'; END IF;
 END LOOP;RETURN j;
END $$;
CREATE FUNCTION awe_d09.local_receipt_master01(p text,a text,stage text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE t awe_d09.attempts;ap awe_d09.approvals;op awe_d09.operations;res awe_d09.results;j jsonb;r jsonb; BEGIN
 SELECT * INTO t FROM awe_d09.attempts WHERE project_id=p AND attempt_id=a;
 SELECT * INTO ap FROM awe_d09.approvals WHERE project_id=p AND approval_id=t.request->>'approval_id';
 SELECT * INTO op FROM awe_d09.operations WHERE project_id=p AND operation_id=t.operation_id;
 SELECT * INTO res FROM awe_d09.results WHERE project_id=p AND attempt_id=a;j:=ap.local_plan_master01;r:=j->'request';
 IF t.attempt_id IS NULL OR j IS NULL OR t.owner_login<>session_user OR t.delivery_fence>9007199254740991 THEN RAISE EXCEPTION 'LOCAL_RECEIPT_SCOPE'; END IF;
 RETURN jsonb_build_object('schema','master01.local.receipt/1','status',stage,'stage',stage,'accounting_status',t.accounting_status,
  'attempt_status',t.status,'project_id',p,'task_id',op.task_id,'operation_id',t.operation_id,'attempt_id',a,'delivery_fence',t.delivery_fence,
  'local_profile','E0_LOCAL_REVIEWED_ONLY','local_execution_authorized',stage IN ('ADMITTED','CLAIMED','SENT','SUCCEEDED'),'local_binding',j->>'binding','lineage_enforced',true,
  'plan_hash',ap.plan_hash,'dynamic_plan_hash',r->>'plan_hash','payload_hash',r->>'payload_hash','spec_hash',awe_d09.local_hash_master01(r#>'{local,spec}'),
  'task_revision',(r->>'revision')::bigint,'task_fence',(r->>'fence')::bigint,
  'epochs',r->'epochs','output_hash',CASE WHEN res.local_output_master01 IS NULL THEN NULL ELSE awe_d09.local_hash_master01(res.local_output_master01->'output') END,
  'evidence_hash',res.evidence_hash,'reserve_micros',t.reserve_micros::text,'actual_micros',t.actual_micros::text,
  'physical_decision','DENY','dispatch_authorized',false);
END $$;
CREATE FUNCTION awe_d09.recover_local_master01(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE ap awe_d09.approvals; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id']);PERFORM awe_d09.local_role_master01(false);PERFORM awe_d09.lock_project(j->>'project_id','EXECUTE');
 SELECT * INTO ap FROM awe_d09.approvals WHERE project_id=j->>'project_id' AND task_id=j->>'task_id' AND local_plan_master01 IS NOT NULL AND NOT revoked AND used_by IS NULL;
 IF ap.approval_id IS NULL OR EXISTS(SELECT 1 FROM awe_d09.origins WHERE project_id=j->>'project_id' AND origin_id='master01_local_origin' AND quarantined)
  OR EXISTS(SELECT 1 FROM awe_d09.attempts WHERE project_id=j->>'project_id' AND status IN ('ADMITTED','SENT','OUTCOME_UNKNOWN')) THEN RAISE EXCEPTION 'LOCAL_RECOVERY_RECONCILIATION_REQUIRED'; END IF;
 PERFORM awe_d09.local_assert_master01(j->>'project_id',ap.approval_id);
 RETURN jsonb_build_object('status','READY','local_profile','E0_LOCAL_REVIEWED_ONLY','local_execution_authorized',true,'physical_decision','DENY');
END $$;
CREATE FUNCTION awe_d09.admit_local_master01(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE plan jsonb;r jsonb; BEGIN
 PERFORM awe_d09.local_role_master01(false);PERFORM awe_d09.lock_project(j->>'project_id','EXECUTE');
 plan:=awe_d09.local_assert_master01(j->>'project_id',j->>'approval_id');r:=plan->'request';
 IF j IS DISTINCT FROM jsonb_build_object('project_id',r->'project_id','task_id',r->'task_id','operation_id',r->'operation_id','attempt_id',r->'attempt_id','effect_slot',r->'effect_slot','approval_id',r#>'{local,d09_approval_id}','grant_id',plan#>'{authorization,grant_id}','idempotency_key',r->'idempotency_key','plan_hash',plan->'plan_hash','payload_hash',r->'payload_hash','reserve_micros','0')
  OR EXISTS(SELECT 1 FROM awe_d09.attempts WHERE project_id=j->>'project_id' AND (attempt_id=j->>'attempt_id' OR idempotency_key=j->>'idempotency_key')) THEN RAISE EXCEPTION 'LOCAL_ADMISSION_REPLAY_OR_BINDING'; END IF;
 PERFORM awe_d09.admit(j);RETURN awe_d09.local_receipt_master01(j->>'project_id',j->>'attempt_id','ADMITTED');
END $$;
CREATE FUNCTION awe_d09.claim_local_master01(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE t awe_d09.attempts; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','attempt_id']);PERFORM awe_d09.local_role_master01(false);PERFORM awe_d09.lock_project(j->>'project_id','EXECUTE');
 SELECT * INTO t FROM awe_d09.attempts WHERE project_id=j->>'project_id' AND attempt_id=j->>'attempt_id' FOR UPDATE;
 IF t.attempt_id IS NULL OR t.owner_login<>session_user OR t.status<>'ADMITTED' OR t.delivery_fence<>0 THEN RAISE EXCEPTION 'LOCAL_CLAIM_REPLAY'; END IF;
 PERFORM awe_d09.local_assert_master01(t.project_id,t.request->>'approval_id');PERFORM awe_d09.claim_attempt(j);
 RETURN awe_d09.local_receipt_master01(t.project_id,t.attempt_id,'CLAIMED');
END $$;
CREATE FUNCTION awe_d09.sent_local_master01(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE t awe_d09.attempts; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','attempt_id','fence']);PERFORM awe_d09.local_role_master01(false);PERFORM awe_d09.lock_project(j->>'project_id','EXECUTE');
 SELECT * INTO t FROM awe_d09.attempts WHERE project_id=j->>'project_id' AND attempt_id=j->>'attempt_id' FOR UPDATE;
 IF t.attempt_id IS NULL OR t.owner_login<>session_user OR t.status<>'ADMITTED' OR t.delivery_fence<>1 THEN RAISE EXCEPTION 'LOCAL_SEND_REPLAY'; END IF;
 PERFORM awe_d09.local_assert_master01(t.project_id,t.request->>'approval_id');PERFORM awe_d09.mark_sent(j);
 RETURN awe_d09.local_receipt_master01(t.project_id,t.attempt_id,'SENT');
END $$;
CREATE FUNCTION awe_d09.result_local_master01(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE t awe_d09.attempts;plan jsonb;r jsonb;out jsonb:=j->'output';expected jsonb; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','attempt_id','result','evidence_hash','output']);PERFORM awe_d09.local_role_master01(false);PERFORM awe_d09.lock_project(j->>'project_id','EXECUTE');
 SELECT * INTO t FROM awe_d09.attempts WHERE project_id=j->>'project_id' AND attempt_id=j->>'attempt_id' FOR UPDATE;
 IF t.attempt_id IS NULL OR t.owner_login<>session_user OR t.status<>'SENT' OR t.accounting_status<>'RESERVED' OR t.reserve_micros<>0
  OR EXISTS(SELECT 1 FROM awe_d09.results WHERE project_id=t.project_id AND attempt_id=t.attempt_id) THEN RAISE EXCEPTION 'LOCAL_RESULT_REPLAY_OR_UNKNOWN'; END IF;
 plan:=awe_d09.local_assert_master01(t.project_id,t.request->>'approval_id');r:=plan->'request';
 expected:=jsonb_build_object('path',r#>'{payload,path}','bytes',octet_length(convert_to(r#>>'{payload,text}','UTF8')),'sha256','sha256:'||encode(sha256(convert_to(r#>>'{payload,text}','UTF8')),'hex'));
 IF j->>'result' IS DISTINCT FROM 'SUCCEEDED' OR out->'output' IS DISTINCT FROM expected
  OR out->>'profile' IS DISTINCT FROM 'E0_LOCAL_REVIEWED_ONLY' OR out->>'attempt_id' IS DISTINCT FROM t.attempt_id
  OR out->>'payload_hash' IS DISTINCT FROM r->>'payload_hash' OR out->>'output_hash' IS DISTINCT FROM awe_d09.local_hash_master01(expected)
  OR out->>'physical_decision' IS DISTINCT FROM 'DENY' OR out->'authoritative_complete' IS DISTINCT FROM 'false'::jsonb
  OR out#>>'{evidence,write_semantics}' IS DISTINCT FROM 'CREATE_EXCLUSIVE' OR out#>'{evidence,external_requests}' IS DISTINCT FROM '0'::jsonb
  OR out#>>'{evidence,readback_hash}' IS DISTINCT FROM expected->>'sha256'
  OR j->>'evidence_hash' IS DISTINCT FROM awe_d09.local_hash_master01(out) THEN RAISE EXCEPTION 'LOCAL_RESULT_BINDING'; END IF;
 INSERT INTO awe_d09.results(project_id,attempt_id,result,evidence_hash,local_output_master01) VALUES(t.project_id,t.attempt_id,'SUCCEEDED',j->>'evidence_hash',out);
 -- Explicit zero-price local policy only. Same allocations and same ledger.
 -- Monetary settlement is separate from semantic QA/OWNER acceptance.
 PERFORM awe_d09.close_allocation(t.project_id,t.attempt_id,0);
 UPDATE awe_d09.attempts SET status='SETTLED',accounting_status='SETTLED',actual_micros=0 WHERE project_id=t.project_id AND attempt_id=t.attempt_id;
 PERFORM awe_d09.audit(t.project_id,t.attempt_id,'LOCAL_ZERO_COST_SETTLED_RESULT_UNTRUSTED',jsonb_build_object('evidence_hash',j->>'evidence_hash'));
 RETURN awe_d09.local_receipt_master01(t.project_id,t.attempt_id,'SUCCEEDED');
END $$;
CREATE FUNCTION awe_d09.cancel_local_master01(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE r jsonb; BEGIN
 PERFORM awe_d09.local_role_master01(false);r:=awe_d09.cancel_attempt(j);
 RETURN awe_d09.local_receipt_master01(j->>'project_id',j->>'attempt_id',CASE WHEN r->>'status'='NOT_SENT' THEN 'NOT_SENT' ELSE 'OUTCOME_UNKNOWN' END);
END $$;
CREATE FUNCTION awe_d09.inspect_local_master01(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$ BEGIN
 PERFORM awe_d09.local_role_master01(false);PERFORM awe_d09.inspect_attempt(j);
 RETURN awe_d09.local_receipt_master01(j->>'project_id',j->>'attempt_id','INSPECT_ONLY');
END $$;
CREATE FUNCTION awe_d09.unknown_local_master01(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE t awe_d09.attempts; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','attempt_id']);PERFORM awe_d09.local_role_master01(false);PERFORM awe_d09.lock_project(j->>'project_id','EXECUTE');
 SELECT * INTO t FROM awe_d09.attempts WHERE project_id=j->>'project_id' AND attempt_id=j->>'attempt_id' FOR UPDATE;
 IF t.attempt_id IS NOT NULL AND t.owner_login<>session_user THEN RAISE EXCEPTION 'LOCAL_UNKNOWN_SCOPE'; END IF;
 IF t.attempt_id IS NOT NULL THEN PERFORM awe_d09.quarantine(t.project_id,t.attempt_id); END IF;
 UPDATE awe_d09.origins SET quarantined=true WHERE project_id=j->>'project_id' AND origin_id='master01_local_origin';
 RETURN jsonb_build_object('status','OUTCOME_UNKNOWN','retry_allowed',false,'physical_decision','DENY');
END $$;
REVOKE ALL ON FUNCTION awe_d09.local_hash_master01(jsonb),awe_d09.local_role_master01(boolean),awe_d09.local_state_master01(awe_d09.projects,jsonb),
 awe_d09.register_local_master01(jsonb),awe_d09.local_assert_master01(text,text),awe_d09.local_receipt_master01(text,text,text),
 awe_d09.recover_local_master01(jsonb),awe_d09.admit_local_master01(jsonb),awe_d09.claim_local_master01(jsonb),awe_d09.sent_local_master01(jsonb),
 awe_d09.result_local_master01(jsonb),awe_d09.cancel_local_master01(jsonb),awe_d09.inspect_local_master01(jsonb),awe_d09.unknown_local_master01(jsonb) FROM PUBLIC;
GRANT USAGE ON SCHEMA awe_d09 TO awe_d09_local_master01,awe_d09_local_issuer_master01;
GRANT EXECUTE ON FUNCTION awe_d09.register_local_master01(jsonb) TO awe_d09_local_issuer_master01;
GRANT EXECUTE ON FUNCTION awe_d09.recover_local_master01(jsonb),awe_d09.admit_local_master01(jsonb),awe_d09.claim_local_master01(jsonb),awe_d09.sent_local_master01(jsonb),
 awe_d09.result_local_master01(jsonb),awe_d09.cancel_local_master01(jsonb),awe_d09.inspect_local_master01(jsonb),awe_d09.unknown_local_master01(jsonb) TO awe_d09_local_master01;
COMMIT;
