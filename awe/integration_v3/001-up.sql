-- Additive E0-only migration. Reviewed D09 and frozen D01-D07 stay byte-identical.
-- Bootstrap ONLY in a fresh disposable cluster already migrated with D09.
BEGIN;
CREATE ROLE awe_int03_host NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE awe_int03_verifier NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE awe_int03_evaluator NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE awe_int03_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE SCHEMA awe_int03 AUTHORIZATION awe_d09_owner;
SET LOCAL ROLE awe_d09_owner;
REVOKE ALL ON SCHEMA awe_int03 FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA awe_int03 REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
CREATE TABLE awe_int03.runtime (
 project_id text, task_id text, worker_login name NOT NULL,
 plan jsonb NOT NULL, plan_hash text NOT NULL,
 state text NOT NULL DEFAULT 'CREATED' CHECK(state IN ('CREATED','ADMITTED','RUNNING','WORK_COMPLETED','OUTCOME_UNKNOWN','CANCELLED')),
 revision bigint NOT NULL DEFAULT 1, attempt_id text, admission jsonb, epochs jsonb,
 head bigint NOT NULL DEFAULT 0, qa text NOT NULL DEFAULT 'QA_NOT_RUN'
 CHECK(qa IN ('QA_NOT_RUN','QA_PENDING','QA_PASS','QA_FAIL','QA_INCONCLUSIVE')),
 qa_run text, qa_key text, qa_login name, qa_grant text, proof_hash text,
 acceptance text NOT NULL DEFAULT 'REJECTED' CHECK(acceptance IN ('REJECTED','OWNER_ACCEPTED')),
 owner_login name, owner_grant text, acceptance_key text, uncertain boolean NOT NULL DEFAULT false,
 PRIMARY KEY(project_id,task_id), FOREIGN KEY(project_id,task_id) REFERENCES awe_d09.tasks
);
CREATE TABLE awe_int03.bundles (
 project_id text, task_id text, version bigint, body text NOT NULL, bundle_hash text NOT NULL,
 file_hash text NOT NULL, PRIMARY KEY(project_id,task_id,version),
 FOREIGN KEY(project_id,task_id) REFERENCES awe_int03.runtime
);
CREATE TABLE awe_int03.dependencies (
 project_id text, task_id text, parent_id text, PRIMARY KEY(project_id,task_id,parent_id),
 CHECK(task_id<>parent_id), FOREIGN KEY(project_id,task_id) REFERENCES awe_int03.runtime,
 FOREIGN KEY(project_id,parent_id) REFERENCES awe_int03.runtime(project_id,task_id)
);
CREATE TABLE awe_int03.authorities (
 project_id text, task_id text, grant_id text, login name NOT NULL REFERENCES awe_d09.principals,
 action text NOT NULL CHECK(action IN ('VERIFY','ACCEPT')), target_hash text NOT NULL, epochs jsonb NOT NULL,
 expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(project_id,task_id,grant_id), FOREIGN KEY(project_id,task_id) REFERENCES awe_int03.runtime
);
CREATE TABLE awe_int03.proofs (
 project_id text, task_id text, run_id text, proof text NOT NULL, proof_hash text NOT NULL,
 bundle_hash text NOT NULL, login name NOT NULL, PRIMARY KEY(project_id,task_id,run_id),
 evaluator_login name NOT NULL REFERENCES awe_d09.principals,
 evaluator_sha256 text NOT NULL, service_sha256 text NOT NULL,
 FOREIGN KEY(project_id,task_id) REFERENCES awe_int03.runtime
);
-- Trusted bootstrap provisions the service credential/pins. Verifier, worker,
-- owner and service itself cannot register or mutate this trust root.
CREATE TABLE awe_int03.evaluator_trust (
 project_id text REFERENCES awe_d09.projects, login name REFERENCES awe_d09.principals,
 evaluator_sha256 text NOT NULL CHECK(evaluator_sha256 ~ '^[a-f0-9]{64}$'),
 service_sha256 text NOT NULL CHECK(service_sha256 ~ '^[a-f0-9]{64}$'),
 policy_version text NOT NULL CHECK(policy_version='D08_E0_EXACT_ARTIFACT_V1'),
 expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(project_id,login)
);
CREATE TABLE awe_int03.events (
 project_id text, task_id text, sequence bigint GENERATED ALWAYS AS IDENTITY,
 kind text NOT NULL, body jsonb NOT NULL, PRIMARY KEY(project_id,task_id,sequence),
 FOREIGN KEY(project_id,task_id) REFERENCES awe_int03.runtime
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['runtime','dependencies','bundles','authorities','proofs','evaluator_trust','events'] LOOP
  EXECUTE format('ALTER TABLE awe_int03.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE awe_int03.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON awe_int03.%I USING (awe_d09.can_access(project_id)) WITH CHECK (awe_d09.can_access(project_id))',t);
 END LOOP;
END $$;
CREATE TRIGGER bundle_immutable BEFORE UPDATE OR DELETE ON awe_int03.bundles FOR EACH ROW EXECUTE FUNCTION awe_d09.immutable_history();
CREATE TRIGGER proof_immutable BEFORE UPDATE OR DELETE ON awe_int03.proofs FOR EACH ROW EXECUTE FUNCTION awe_d09.immutable_history();
CREATE TRIGGER event_immutable BEFORE UPDATE OR DELETE ON awe_int03.events FOR EACH ROW EXECUTE FUNCTION awe_d09.immutable_history();
CREATE FUNCTION awe_int03.hash(t text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(t,'UTF8')),'hex')
$$;
CREATE FUNCTION awe_int03.epochs(p text) RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT jsonb_build_array(auth_epoch,policy_epoch,owner_epoch,stop_epoch) FROM awe_d09.projects WHERE project_id=p
$$;
CREATE FUNCTION awe_int03.lock_runtime(j jsonb,role_name text DEFAULT NULL) RETURNS awe_int03.runtime
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; BEGIN
 PERFORM awe_d09.lock_project(j->>'project_id','READ');
 IF role_name IS NOT NULL AND NOT pg_has_role(session_user,role_name,'MEMBER') THEN RAISE EXCEPTION 'INT03_ROLE_DENIED'; END IF;
 SELECT * INTO r FROM awe_int03.runtime WHERE project_id=j->>'project_id' AND task_id=j->>'task_id' FOR UPDATE;
 IF r.task_id IS NULL THEN RAISE EXCEPTION 'INT03_SCOPE_DENIED'; END IF;
 IF role_name='awe_int03_host' AND r.worker_login<>session_user THEN RAISE EXCEPTION 'INT03_WORKER_DENIED'; END IF;
 RETURN r;
END $$;
CREATE FUNCTION awe_int03.audit(r awe_int03.runtime,k text,b jsonb DEFAULT '{}'::jsonb) RETURNS void
LANGUAGE sql AS $$ INSERT INTO awe_int03.events(project_id,task_id,kind,body)
 VALUES(r.project_id,r.task_id,k,b||jsonb_build_object('login',session_user)) $$;
CREATE FUNCTION awe_int03.live(r awe_int03.runtime) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT NOT r.uncertain AND r.state NOT IN ('OUTCOME_UNKNOWN','CANCELLED')
 AND r.epochs=awe_int03.epochs(r.project_id) AND NOT p.halted AND NOT p.restore_pending
 AND NOT t.cancelled AND NOT o.quarantined AND t.lease_until>statement_timestamp()
 AND (g.task_revision,g.task_fence)=(t.revision,t.fence) AND NOT g.revoked AND NOT ap.revoked
 AND (g.auth_epoch,g.policy_epoch,g.owner_epoch,g.stop_epoch)=(p.auth_epoch,p.policy_epoch,p.owner_epoch,p.stop_epoch)
 AND g.expires_at>statement_timestamp() AND ap.expires_at>statement_timestamp()
 AND EXISTS(SELECT 1 FROM awe_d09.principals w JOIN awe_d09.memberships m USING(login)
  WHERE w.login=r.worker_login AND NOT w.revoked AND w.valid_until>statement_timestamp()
  AND m.project_id=r.project_id AND 'EXECUTE'=ANY(m.permissions))
 FROM awe_d09.projects p JOIN awe_d09.tasks t USING(project_id)
 JOIN awe_d09.origins o USING(project_id,origin_id)
 JOIN awe_d09.attempts a ON a.project_id=t.project_id AND a.attempt_id=r.attempt_id
 JOIN awe_d09.grants g ON g.project_id=a.project_id AND g.grant_id=a.grant_id
 JOIN awe_d09.approvals ap ON ap.project_id=g.project_id AND ap.approval_id=g.approval_id
 WHERE t.project_id=r.project_id AND t.task_id=r.task_id
$$;
CREATE FUNCTION awe_int03.bundle(r awe_int03.runtime) RETURNS awe_int03.bundles LANGUAGE plpgsql AS $$
DECLARE b awe_int03.bundles; BEGIN
 SELECT * INTO b FROM awe_int03.bundles WHERE project_id=r.project_id AND task_id=r.task_id AND version=r.head;
 IF b.version IS NULL OR awe_int03.hash(b.body)<>b.bundle_hash
 OR 'sha256:'||encode(sha256(decode(b.body::jsonb->>'bytes_base64','base64')),'hex')<>b.file_hash
 OR b.body::jsonb#>>'{reference,file_hash}'<>b.file_hash THEN RAISE EXCEPTION 'INT03_ARTIFACT_CHANGED'; END IF;
 RETURN b;
END $$;
CREATE FUNCTION awe_int03.valid_grant(r awe_int03.runtime,gid text,who name,act text,target text) RETURNS boolean
LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM awe_int03.authorities g JOIN awe_d09.principals p ON p.login=g.login
 WHERE g.project_id=r.project_id AND g.task_id=r.task_id AND g.grant_id=gid AND g.login=who
 AND g.action=act AND g.target_hash=target AND g.epochs=awe_int03.epochs(r.project_id)
 AND NOT g.revoked AND g.expires_at>statement_timestamp() AND NOT p.revoked AND p.valid_until>statement_timestamp()
 AND EXISTS(SELECT 1 FROM awe_d09.memberships m WHERE m.project_id=r.project_id AND m.login=who AND 'READ'=ANY(m.permissions))
 AND who<>r.worker_login AND awe_d09.can_access(r.project_id))
$$;
CREATE FUNCTION awe_int03.evaluator_live(r awe_int03.runtime,who name,es text,ss text) RETURNS boolean
LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM awe_int03.evaluator_trust tr JOIN awe_d09.principals p USING(login)
 JOIN awe_d09.memberships m USING(project_id,login)
 WHERE tr.project_id=r.project_id AND tr.login=who AND tr.evaluator_sha256=es AND tr.service_sha256=ss
 AND NOT tr.revoked AND tr.expires_at>statement_timestamp() AND NOT p.revoked AND p.valid_until>statement_timestamp()
 AND 'READ'=ANY(m.permissions) AND who<>r.worker_login AND who IS DISTINCT FROM r.qa_login
 AND who IS DISTINCT FROM r.owner_login AND pg_has_role(who,'awe_int03_evaluator','MEMBER')
 AND NOT pg_has_role(who,'awe_int03_host','MEMBER') AND NOT pg_has_role(who,'awe_int03_verifier','MEMBER')
 AND NOT pg_has_role(who,'awe_int03_owner','MEMBER'))
$$;
CREATE FUNCTION awe_int03.inspect(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; b awe_int03.bundles; q awe_int03.proofs; good boolean:=false; accepted boolean:=false; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id']); r:=awe_int03.lock_runtime(j);
 IF r.head>0 THEN
  BEGIN b:=awe_int03.bundle(r);
   SELECT * INTO q FROM awe_int03.proofs WHERE project_id=r.project_id AND task_id=r.task_id AND run_id=r.qa_run;
   good:=COALESCE(awe_int03.live(r),false) AND r.state='WORK_COMPLETED' AND r.qa='QA_PASS'
    AND q.proof_hash=r.proof_hash AND awe_int03.hash(q.proof)=q.proof_hash AND q.bundle_hash=b.bundle_hash
    AND q.proof::jsonb#>>'{result,verdict}'='QA_PASS'
    AND awe_int03.evaluator_live(r,q.evaluator_login,q.evaluator_sha256,q.service_sha256)
    AND awe_int03.valid_grant(r,r.qa_grant,r.qa_login,'VERIFY',b.bundle_hash)
    AND EXISTS(SELECT 1 FROM awe_d09.attempts a WHERE a.project_id=r.project_id AND a.attempt_id=r.attempt_id
      AND a.status='SETTLED' AND a.accounting_status='SETTLED');
   accepted:=good AND r.acceptance='OWNER_ACCEPTED' AND r.owner_login<>r.qa_login
    AND awe_int03.valid_grant(r,r.owner_grant,r.owner_login,'ACCEPT',q.proof_hash);
  EXCEPTION WHEN OTHERS THEN good:=false; accepted:=false; END;
 END IF;
 RETURN jsonb_build_object('state',r.state,'revision',r.revision,'head',r.head,'qa',r.qa,
  'effective_qa',CASE WHEN good THEN 'QA_PASS' WHEN r.qa='QA_PASS' THEN 'QA_INCONCLUSIVE' ELSE r.qa END,
  'acceptance',CASE WHEN accepted THEN 'OWNER_ACCEPTED' ELSE 'REJECTED' END,'accepted',COALESCE(accepted,false),
  'published',false,'physical_decision','DENY','authoritative_complete',false,
  'plan_hash',r.plan_hash,'bundle_hash',b.bundle_hash,'proof_hash',r.proof_hash,'uncertain',r.uncertain,
  'completion',jsonb_build_object('work',CASE WHEN r.state='OUTCOME_UNKNOWN' THEN 'OUTCOME_UNKNOWN' WHEN r.state='WORK_COMPLETED' THEN 'WORK_COMPLETED' ELSE 'INCOMPLETE' END,
    'accepted',COALESCE(accepted,false),'published',false,'physical_decision','DENY'),
  'attempt_id',r.attempt_id,'durable_owner','POSTGRESQL','production_ready',false);
END $$;
CREATE FUNCTION awe_int03.admit(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; c jsonb; a jsonb; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id','command']); r:=awe_int03.lock_runtime(j,'awe_int03_host');
 c:=(j->'command')||jsonb_build_object('project_id',r.project_id,'task_id',r.task_id);
 IF j->'command' ?| ARRAY['project_id','task_id','actor','qa','accepted'] THEN RAISE EXCEPTION 'INT03_AGENT_AUTHORITY_DENIED'; END IF;
 IF r.uncertain OR r.state IN ('OUTCOME_UNKNOWN','CANCELLED') THEN RAISE EXCEPTION 'INT03_STICKY_UNKNOWN_OR_CANCEL'; END IF;
 IF r.admission IS NOT NULL THEN
  IF r.admission<>c THEN RAISE EXCEPTION 'INT03_IDEMPOTENCY_CONFLICT'; END IF;
  RETURN awe_int03.inspect(jsonb_build_object('project_id',r.project_id,'task_id',r.task_id));
 END IF;
 IF r.state<>'CREATED' OR c->>'plan_hash'<>r.plan->>'d06_plan_hash'
 OR c->>'payload_hash'<>r.plan->>'payload_hash' OR c->>'reserve_micros'<>r.plan->>'reserve_micros'
 THEN RAISE EXCEPTION 'INT03_PLAN_BINDING'; END IF;
 IF EXISTS(SELECT 1 FROM awe_int03.dependencies d WHERE d.project_id=r.project_id AND d.task_id=r.task_id
  AND NOT COALESCE((awe_int03.inspect(jsonb_build_object('project_id',d.project_id,'task_id',d.parent_id))->>'accepted')::boolean,false))
 THEN RAISE EXCEPTION 'INT03_DAG_PARENT_NOT_ACCEPTED'; END IF;
 -- D09 owns reserve, attempt uniqueness, epoch/approval/lease, mapped budgets.
 a:=awe_d09.admit(c);
 UPDATE awe_int03.runtime SET state='ADMITTED',revision=revision+1,attempt_id=c->>'attempt_id',admission=c,
  epochs=awe_int03.epochs(r.project_id) WHERE project_id=r.project_id AND task_id=r.task_id;
 PERFORM awe_int03.audit(r,'ADMITTED',jsonb_build_object('attempt_id',c->>'attempt_id'));
 RETURN awe_int03.inspect(jsonb_build_object('project_id',r.project_id,'task_id',r.task_id));
END $$;
CREATE FUNCTION awe_int03.begin_execution(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; a jsonb; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id']); r:=awe_int03.lock_runtime(j,'awe_int03_host');
 IF r.state<>'ADMITTED' OR NOT COALESCE(awe_int03.live(r),false) THEN RAISE EXCEPTION 'INT03_EXECUTION_DENIED'; END IF;
 a:=awe_d09.claim_attempt(jsonb_build_object('project_id',r.project_id,'attempt_id',r.attempt_id));
 a:=awe_d09.mark_sent(jsonb_build_object('project_id',r.project_id,'attempt_id',r.attempt_id,'fence',(a->>'delivery_fence')::bigint));
 UPDATE awe_int03.runtime SET state='RUNNING',revision=revision+1 WHERE project_id=r.project_id AND task_id=r.task_id;
 PERFORM awe_int03.audit(r,'SYNTHETIC_INTENT_ONLY'); RETURN awe_int03.inspect(j);
END $$;
CREATE FUNCTION awe_int03.store_bundle(r awe_int03.runtime,j jsonb,ver bigint) RETURNS awe_int03.bundles
LANGUAGE plpgsql SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE v jsonb:= (j->>'body')::jsonb; raw bytea; b awe_int03.bundles; original jsonb; BEGIN
 raw:=decode(v->>'bytes_base64','base64');
 IF awe_int03.hash(j->>'body') IS DISTINCT FROM j->>'bundle_hash' OR octet_length(j->>'body')>2097152 OR octet_length(raw)>32768
 OR v->'plan' IS DISTINCT FROM r.plan OR v->'requirements' IS DISTINCT FROM r.plan->'requirements'
 OR v#>>'{pin,scope,project_id}' IS DISTINCT FROM r.project_id OR v#>>'{pin,scope,task_id}' IS DISTINCT FROM r.task_id
 OR v#>'{pin,spec}' IS DISTINCT FROM r.plan#>'{requirements,spec}'
 OR v#>>'{reference,project_id}' IS DISTINCT FROM r.project_id OR v#>>'{reference,task_id}' IS DISTINCT FROM r.task_id
 OR (v#>>'{reference,version}')::bigint<>ver OR (v#>>'{reference,bytes}')::bigint<>octet_length(raw)
 OR v#>>'{reference,file_hash}' IS DISTINCT FROM 'sha256:'||encode(sha256(raw),'hex')
 OR v->>'physical_dispatches' IS DISTINCT FROM '0' OR v#>>'{evidence,completion,work}' IS DISTINCT FROM 'WORK_COMPLETED'
 OR v#>>'{evidence,completion,physical_decision}' IS DISTINCT FROM 'DENY'
 THEN RAISE EXCEPTION 'INT03_BUNDLE_BINDING'; END IF;
 IF ver>1 THEN
  SELECT body::jsonb INTO original FROM awe_int03.bundles WHERE project_id=r.project_id AND task_id=r.task_id AND version=1;
  IF v->'cost' IS DISTINCT FROM original->'cost' OR v->'pin' IS DISTINCT FROM original->'pin'
   OR v->'operations' IS DISTINCT FROM original->'operations' OR v->'checkpoint' IS DISTINCT FROM original->'checkpoint'
   OR v#>'{evidence,model_operation}' IS DISTINCT FROM original#>'{evidence,model_operation}'
  THEN RAISE EXCEPTION 'INT03_REVISION_CANNOT_REWRITE_EXECUTION'; END IF;
 END IF;
 INSERT INTO awe_int03.bundles VALUES(r.project_id,r.task_id,ver,j->>'body',j->>'bundle_hash',v#>>'{reference,file_hash}') RETURNING * INTO b;
 RETURN b;
END $$;
CREATE FUNCTION awe_int03.complete(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; b awe_int03.bundles; v jsonb:=(j->>'body')::jsonb; a jsonb; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id','body','bundle_hash']); r:=awe_int03.lock_runtime(j,'awe_int03_host');
 IF r.state<>'RUNNING' OR NOT COALESCE(awe_int03.live(r),false) THEN RAISE EXCEPTION 'INT03_COMPLETION_DENIED'; END IF;
 IF NOT EXISTS(SELECT 1 FROM awe_d09.attempts WHERE project_id=r.project_id AND attempt_id=r.attempt_id
   AND status='SENT' AND deadline>clock_timestamp() AND delivery_until>clock_timestamp()) THEN RAISE EXCEPTION 'INT03_LATE_CALLBACK'; END IF;
 b:=awe_int03.store_bundle(r,j,1);
 IF v#>>'{cost,actual_micros}' IS DISTINCT FROM v#>>'{evidence,model_operation,attempts,0,settledMicros}'
 OR v#>>'{cost,actual_micros}' IS DISTINCT FROM convert_from(decode(v->>'bytes_base64','base64'),'UTF8')::jsonb#>>'{model,costMicros}'
 THEN RAISE EXCEPTION 'INT03_COST_BINDING'; END IF;
 a:=awe_d09.record_result(jsonb_build_object('project_id',r.project_id,'attempt_id',r.attempt_id,'result','SUCCEEDED','evidence_hash',b.file_hash));
 a:=awe_d09.reconcile_charge(jsonb_build_object('project_id',r.project_id,'attempt_id',r.attempt_id,
  'provider','synthetic','invoice_id',r.project_id||':'||r.task_id||':'||r.attempt_id,'actual_micros',v#>>'{cost,actual_micros}',
  'input_tokens',(v#>>'{cost,input_tokens}')::bigint,'output_tokens',(v#>>'{cost,output_tokens}')::bigint,'evidence_hash',b.file_hash));
 IF a->>'status'<>'SETTLED' OR a->>'accounting_status'<>'SETTLED' THEN RAISE EXCEPTION 'INT03_UNSETTLED'; END IF;
 UPDATE awe_int03.runtime SET state='WORK_COMPLETED',head=1,revision=revision+1,qa='QA_NOT_RUN',acceptance='REJECTED'
 WHERE project_id=r.project_id AND task_id=r.task_id;
 PERFORM awe_int03.audit(r,'WORK_COMPLETED',jsonb_build_object('bundle_hash',b.bundle_hash));
 RETURN awe_int03.inspect(jsonb_build_object('project_id',r.project_id,'task_id',r.task_id));
END $$;
CREATE FUNCTION awe_int03.revise(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; b awe_int03.bundles; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id','body','bundle_hash','expected_revision']); r:=awe_int03.lock_runtime(j,'awe_int03_host');
 IF r.state<>'WORK_COMPLETED' OR r.revision<>(j->>'expected_revision')::bigint OR NOT COALESCE(awe_int03.live(r),false)
 THEN RAISE EXCEPTION 'INT03_REVISION_DENIED'; END IF;
 b:=awe_int03.store_bundle(r,j,r.head+1);
 UPDATE awe_int03.runtime SET head=head+1,revision=revision+1,qa='QA_NOT_RUN',acceptance='REJECTED',proof_hash=NULL,qa_run=NULL,
 qa_key=NULL,qa_login=NULL,qa_grant=NULL,owner_login=NULL,owner_grant=NULL WHERE project_id=r.project_id AND task_id=r.task_id;
 PERFORM awe_int03.audit(r,'ARTIFACT_REVISED',jsonb_build_object('bundle_hash',b.bundle_hash));
 RETURN awe_int03.inspect(jsonb_build_object('project_id',r.project_id,'task_id',r.task_id));
END $$;
CREATE FUNCTION awe_int03.issue(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; b awe_int03.bundles; target text; who name:=j->>'login'; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id','grant_id','login','action']);
 PERFORM awe_d09.lock_project(j->>'project_id','ISSUE'); r:=awe_int03.lock_runtime(j); b:=awe_int03.bundle(r);
 IF NOT COALESCE(awe_int03.live(r),false) OR r.state<>'WORK_COMPLETED' OR who=r.worker_login
 OR NOT EXISTS(SELECT 1 FROM awe_d09.memberships WHERE project_id=r.project_id AND login=who)
 OR (j->>'action'='VERIFY' AND NOT pg_has_role(who,'awe_int03_verifier','MEMBER'))
 OR (j->>'action'='ACCEPT' AND (r.qa<>'QA_PASS' OR who=r.qa_login OR NOT pg_has_role(who,'awe_int03_owner','MEMBER')))
 THEN RAISE EXCEPTION 'INT03_ISSUANCE_DENIED'; END IF;
 target:=CASE WHEN j->>'action'='VERIFY' THEN b.bundle_hash ELSE r.proof_hash END;
 INSERT INTO awe_int03.authorities VALUES(r.project_id,r.task_id,j->>'grant_id',who,j->>'action',target,
 awe_int03.epochs(r.project_id),clock_timestamp()+interval '10 minutes',false);
 RETURN jsonb_build_object('physical_decision','DENY','grant_id',j->>'grant_id');
END $$;
CREATE FUNCTION awe_int03.start_qa(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; b awe_int03.bundles; q awe_int03.proofs; run text; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id','grant_id','key']); r:=awe_int03.lock_runtime(j,'awe_int03_verifier'); b:=awe_int03.bundle(r);
 IF NOT COALESCE(awe_int03.live(r),false) OR r.state<>'WORK_COMPLETED'
 OR NOT awe_int03.valid_grant(r,j->>'grant_id',session_user,'VERIFY',b.bundle_hash)
 THEN RAISE EXCEPTION 'INT03_QA_AUTHORITY_DENIED'; END IF;
 IF r.qa_key IS NOT NULL THEN
  IF (r.qa_key,r.qa_login,r.qa_grant) IS DISTINCT FROM (j->>'key',session_user,j->>'grant_id') THEN RAISE EXCEPTION 'INT03_QA_BUSY'; END IF;
  SELECT * INTO q FROM awe_int03.proofs WHERE project_id=r.project_id AND task_id=r.task_id AND run_id=r.qa_run;
  RETURN jsonb_build_object('physical_decision','DENY','run_id',r.qa_run,'bundle',b.body::jsonb,'bundle_hash',b.bundle_hash,'actor',session_user,'proof',q.proof::jsonb,'proof_hash',q.proof_hash);
 END IF;
 run:=awe_int03.hash(b.bundle_hash||':'||session_user||':'||(j->>'key'));
 UPDATE awe_int03.runtime SET qa='QA_PENDING',qa_run=run,qa_key=j->>'key',qa_login=session_user,qa_grant=j->>'grant_id',
 acceptance='REJECTED',revision=revision+1 WHERE project_id=r.project_id AND task_id=r.task_id;
 PERFORM awe_int03.audit(r,'QA_PENDING');
 RETURN jsonb_build_object('physical_decision','DENY','run_id',run,'bundle',b.body::jsonb,'bundle_hash',b.bundle_hash,'actor',session_user);
END $$;
CREATE FUNCTION awe_int03.read_evaluation(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; b awe_int03.bundles; tr awe_int03.evaluator_trust; q awe_int03.proofs; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id','run_id']); r:=awe_int03.lock_runtime(j,'awe_int03_evaluator'); b:=awe_int03.bundle(r);
 SELECT * INTO tr FROM awe_int03.evaluator_trust WHERE project_id=r.project_id AND login=session_user FOR SHARE;
 IF NOT COALESCE(awe_int03.live(r),false) OR r.state<>'WORK_COMPLETED' OR r.qa_run IS DISTINCT FROM j->>'run_id'
 OR r.qa NOT IN ('QA_PENDING','QA_PASS','QA_FAIL','QA_INCONCLUSIVE')
 OR NOT awe_int03.evaluator_live(r,session_user,tr.evaluator_sha256,tr.service_sha256)
 OR NOT awe_int03.valid_grant(r,r.qa_grant,r.qa_login,'VERIFY',b.bundle_hash)
 THEN RAISE EXCEPTION 'INT03_EVALUATOR_AUTHORITY_DENIED'; END IF;
 SELECT * INTO q FROM awe_int03.proofs WHERE project_id=r.project_id AND task_id=r.task_id AND run_id=r.qa_run;
 IF r.qa<>'QA_PENDING' AND q.run_id IS NULL THEN RAISE EXCEPTION 'INT03_EVALUATION_INTERRUPTED'; END IF;
 RETURN jsonb_build_object('physical_decision','DENY','run_id',r.qa_run,'grant_id',r.qa_grant,'bundle',b.body::jsonb,
  'bundle_hash',b.bundle_hash,'actor',r.qa_login,'proof',q.proof::jsonb,'proof_hash',q.proof_hash,
  'evaluator_sha256',tr.evaluator_sha256,'service_sha256',tr.service_sha256);
END $$;
CREATE FUNCTION awe_int03.finish_qa(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; b awe_int03.bundles; tr awe_int03.evaluator_trust;
 v jsonb:=(j->>'proof')::jsonb; ph text:=awe_int03.hash(j->>'proof'); BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id','grant_id','run_id','proof']); r:=awe_int03.lock_runtime(j,'awe_int03_evaluator'); b:=awe_int03.bundle(r);
 SELECT * INTO tr FROM awe_int03.evaluator_trust WHERE project_id=r.project_id AND login=session_user FOR SHARE;
 IF NOT COALESCE(awe_int03.live(r),false) OR r.state<>'WORK_COMPLETED' OR r.qa<>'QA_PENDING'
 OR NOT awe_int03.evaluator_live(r,session_user,tr.evaluator_sha256,tr.service_sha256)
 OR (r.qa_run,r.qa_grant) IS DISTINCT FROM (j->>'run_id',j->>'grant_id')
 OR NOT awe_int03.valid_grant(r,r.qa_grant,r.qa_login,'VERIFY',b.bundle_hash)
 OR v->>'bundle_hash' IS DISTINCT FROM b.bundle_hash OR v->>'verifier' IS DISTINCT FROM r.qa_login
 OR v->>'run_id' IS DISTINCT FROM r.qa_run
 OR v->'artifact' IS DISTINCT FROM b.body::jsonb->'reference' OR v->>'mode' IS DISTINCT FROM 'E0_SYNTHETIC_ONLY'
 OR v#>>'{result,artifact_hash}' IS DISTINCT FROM b.file_hash
 OR v#>>'{result,policy_version}' IS DISTINCT FROM 'D08_E0_EXACT_ARTIFACT_V1'
 OR v#>>'{result,verdict}' IS NULL OR v#>>'{result,verdict}' NOT IN ('QA_PASS','QA_FAIL','QA_INCONCLUSIVE')
 THEN RAISE EXCEPTION 'INT03_QA_PROOF_DENIED'; END IF;
 INSERT INTO awe_int03.proofs VALUES(r.project_id,r.task_id,r.qa_run,j->>'proof',ph,b.bundle_hash,r.qa_login,
  session_user,tr.evaluator_sha256,tr.service_sha256);
 UPDATE awe_int03.runtime SET qa=v#>>'{result,verdict}',proof_hash=ph,revision=revision+1 WHERE project_id=r.project_id AND task_id=r.task_id;
 PERFORM awe_int03.audit(r,v#>>'{result,verdict}',jsonb_build_object('proof_hash',ph,'evaluator_login',session_user,
  'evaluator_sha256',tr.evaluator_sha256,'service_sha256',tr.service_sha256));
 RETURN awe_int03.inspect(jsonb_build_object('project_id',r.project_id,'task_id',r.task_id))||jsonb_build_object('proof',v,'proof_hash',ph);
END $$;
CREATE FUNCTION awe_int03.accept(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; s jsonb; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id','grant_id','proof_hash','key']); r:=awe_int03.lock_runtime(j,'awe_int03_owner');
 s:=awe_int03.inspect(jsonb_build_object('project_id',r.project_id,'task_id',r.task_id));
 IF s->>'effective_qa'<>'QA_PASS' OR r.proof_hash IS DISTINCT FROM j->>'proof_hash' OR session_user=r.qa_login
 OR NOT awe_int03.valid_grant(r,j->>'grant_id',session_user,'ACCEPT',r.proof_hash) THEN RAISE EXCEPTION 'INT03_ACCEPTANCE_DENIED'; END IF;
 IF r.acceptance='OWNER_ACCEPTED' THEN
  IF (r.owner_login,r.owner_grant,r.acceptance_key) IS DISTINCT FROM (session_user,j->>'grant_id',j->>'key') THEN RAISE EXCEPTION 'INT03_ACCEPTANCE_CONFLICT'; END IF;
  RETURN s;
 END IF;
 UPDATE awe_int03.runtime SET acceptance='OWNER_ACCEPTED',owner_login=session_user,owner_grant=j->>'grant_id',acceptance_key=j->>'key',revision=revision+1
 WHERE project_id=r.project_id AND task_id=r.task_id;
 PERFORM awe_int03.audit(r,'OWNER_ACCEPTED'); RETURN awe_int03.inspect(jsonb_build_object('project_id',r.project_id,'task_id',r.task_id));
END $$;
CREATE FUNCTION awe_int03.flag_uncertain(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id','reason']); r:=awe_int03.lock_runtime(j,'awe_int03_host');
 IF r.attempt_id IS NOT NULL THEN PERFORM awe_d09.quarantine(r.project_id,r.attempt_id); END IF;
 UPDATE awe_int03.runtime SET state='OUTCOME_UNKNOWN',uncertain=true,qa='QA_INCONCLUSIVE',acceptance='REJECTED',revision=revision+1
 WHERE project_id=r.project_id AND task_id=r.task_id;
 PERFORM awe_int03.audit(r,'OUTCOME_UNKNOWN',jsonb_build_object('reason',j->>'reason'));
 RETURN awe_int03.inspect(jsonb_build_object('project_id',r.project_id,'task_id',r.task_id));
END $$;
CREATE FUNCTION awe_int03.cancel(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; a jsonb; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id']); r:=awe_int03.lock_runtime(j,'awe_int03_host');
 IF r.attempt_id IS NOT NULL THEN a:=awe_d09.cancel_attempt(jsonb_build_object('project_id',r.project_id,'attempt_id',r.attempt_id)); END IF;
 UPDATE awe_d09.tasks SET cancelled=true WHERE project_id=r.project_id AND task_id=r.task_id;
 UPDATE awe_int03.runtime SET state=CASE WHEN uncertain OR a->>'status'='OUTCOME_UNKNOWN' THEN 'OUTCOME_UNKNOWN' ELSE 'CANCELLED' END,
 qa='QA_INCONCLUSIVE',acceptance='REJECTED',revision=revision+1 WHERE project_id=r.project_id AND task_id=r.task_id;
 PERFORM awe_int03.audit(r,'CANCEL_REQUESTED'); RETURN awe_int03.inspect(j);
END $$;
CREATE FUNCTION awe_int03.recover(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id']); r:=awe_int03.lock_runtime(j,'awe_int03_host');
 IF r.state='RUNNING' THEN RETURN awe_int03.flag_uncertain(j||jsonb_build_object('reason','RESTART_WITH_SEND_INTENT')); END IF;
 IF r.qa='QA_PENDING' THEN
  UPDATE awe_int03.runtime SET qa='QA_INCONCLUSIVE',acceptance='REJECTED',revision=revision+1 WHERE project_id=r.project_id AND task_id=r.task_id;
  PERFORM awe_int03.audit(r,'QA_INTERRUPTED');
 END IF;
 RETURN awe_int03.inspect(j);
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA awe_int03 FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA awe_int03 FROM PUBLIC;
GRANT USAGE ON SCHEMA awe_int03 TO awe_int03_host,awe_int03_verifier,awe_int03_evaluator,awe_int03_owner,awe_d09_issuer,awe_d09_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA awe_int03 TO awe_d09_reader;
GRANT EXECUTE ON FUNCTION awe_int03.inspect(jsonb) TO awe_int03_host,awe_int03_verifier,awe_int03_owner,awe_d09_reader;
GRANT EXECUTE ON FUNCTION awe_int03.admit(jsonb),awe_int03.begin_execution(jsonb),awe_int03.complete(jsonb),awe_int03.revise(jsonb),
 awe_int03.cancel(jsonb),awe_int03.recover(jsonb),awe_int03.flag_uncertain(jsonb) TO awe_int03_host;
GRANT EXECUTE ON FUNCTION awe_int03.start_qa(jsonb) TO awe_int03_verifier;
GRANT EXECUTE ON FUNCTION awe_int03.read_evaluation(jsonb),awe_int03.finish_qa(jsonb) TO awe_int03_evaluator;
GRANT EXECUTE ON FUNCTION awe_int03.accept(jsonb) TO awe_int03_owner;
GRANT EXECUTE ON FUNCTION awe_int03.issue(jsonb) TO awe_d09_issuer;
COMMIT;
