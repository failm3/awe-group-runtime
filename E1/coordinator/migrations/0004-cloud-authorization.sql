-- Additive E1 authority/phase guard. Frozen 0001/0002/0003 remain unchanged.
-- No funding or provider proof is fabricated; prepared authorization permits no send.
BEGIN;
DO $$ DECLARE identity jsonb; BEGIN
  IF session_user<>'awe_e1_test' OR current_database()<>'awe_e1_test' OR current_setting('port')<>'5433' OR current_setting('data_directory')<>'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/pgdata' OR current_setting('unix_socket_directories')<>'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/socket' THEN RAISE EXCEPTION 'A2_MIGRATION_RESOURCE_DENIED'; END IF;
  SELECT to_jsonb(i) INTO identity FROM awe_e1_resource.identity i WHERE resource_id='awe_e1_a2a3_20261108';
  IF identity IS DISTINCT FROM jsonb_build_object('resource_id','awe_e1_a2a3_20261108','database_name','awe_e1_test','port',5433,'scope','LOCAL_TEST_ONLY') OR NOT EXISTS(SELECT 1 FROM awe_e1_runtime.schema_migration WHERE version=3) THEN RAISE EXCEPTION 'A2_MIGRATION_RESOURCE_DENIED'; END IF;
END $$;
CREATE TABLE IF NOT EXISTS awe_e1_runtime.cloud4_authorization(
 key_binding_id text PRIMARY KEY,authorization_digest text NOT NULL UNIQUE,document jsonb NOT NULL,signed_receipt jsonb NOT NULL,
 state text NOT NULL CHECK(state IN('PREPARED_PROVIDER_BLOCKED','CANARY','FOLLOWUP','HOLD')),funding_grant_digest text,canary_qa_receipt jsonb,
 prepared_at timestamptz NOT NULL DEFAULT clock_timestamp(),activated_at timestamptz,accepted_at timestamptz,hold_reason text);

CREATE OR REPLACE FUNCTION awe_e1_runtime.cloud4_install_authorization(p jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE r jsonb:=p->'receipt';d jsonb:=p->'receipt'->'document';a awe_e1_runtime.cloud4_authorization%ROWTYPE;projectid text;
BEGIN
 IF session_user NOT IN('awe_e1_coord','awe_e1_test') THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_HOST_REQUIRED'; END IF;
 IF r->>'schema' IS DISTINCT FROM 'awe.e1.cloud4.signed-receipt/1' OR r->>'algorithm' IS DISTINCT FROM 'Ed25519' OR NOT COALESCE(r->>'signature' ~ '^[A-Za-z0-9+/]{86}==$' ,false) OR r->>'public_key_digest' IS DISTINCT FROM p->>'trusted_public_key_digest' OR r->>'public_key_digest' IS DISTINCT FROM awe_e1_runtime.cloud_digest(jsonb_build_object('spki_der',r->>'public_key_spki_der')) OR r->>'document_digest' IS DISTINCT FROM awe_e1_runtime.cloud_digest(d) THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_SIGNATURE_BINDING'; END IF;
 IF d->>'schema' IS DISTINCT FROM 'awe.e1.cloud4.owner-authorization/1' OR d->>'provenance' IS DISTINCT FROM 'HOST_ATTESTED_CHAT_AND_GITHUB_DELEGATION' OR d->>'owner_consent' IS DISTINCT FROM 'ISSUED' OR d->>'provider' IS DISTINCT FROM 'router.cheap' OR d->>'budget_group_id' IS DISTINCT FROM 'router.cheap.shared/1' OR NOT COALESCE(d->>'key_binding_id' ~ '^[a-z][a-z0-9_.-]{0,79}$',false) OR NOT COALESCE(d->>'owner_id' ~ '^[a-z][a-z0-9_.-]{0,79}$',false) OR NOT COALESCE(d->>'issuer_id' ~ '^[a-z][a-z0-9_.-]{0,79}$',false) OR NOT COALESCE(d->>'mandate_digest' ~ '^sha256:[a-f0-9]{64}$',false) THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AUTHORIZATION_SCOPE'; END IF;
 IF d->'limits' IS DISTINCT FROM '{"total_actual_micros":"10000000","account_reserve_unallocated_micros":"21000000","total_attempts":22,"canary":{"budget_micros":"500000","per_attempt_micros":"250000","attempts":2,"route_ids":["router.cheap.chat.gpt-6-sol","router.cheap.chat.claude-opus-4-8"]},"followup":{"budget_micros":"9500000","per_attempt_micros":"1000000","attempts":20},"wire_attempts_per_request":1,"unknown_policy":"HOLD","fallback":"DENY","account_changes":"DENY"}'::jsonb THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AUTHORIZATION_LIMITS'; END IF;
 IF jsonb_typeof(d->'project_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(d->'project_ids') NOT BETWEEN 1 AND 32 OR (SELECT count(DISTINCT x) FROM jsonb_array_elements_text(d->'project_ids') x)<>jsonb_array_length(d->'project_ids') THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AUTHORIZATION_SCOPE'; END IF;
 FOR projectid IN SELECT * FROM jsonb_array_elements_text(d->'project_ids') LOOP
  IF projectid !~ '^[a-z][a-z0-9_.-]{0,79}$' OR EXISTS(SELECT 1 FROM awe_e1_runtime.project WHERE project_id=projectid AND owner_id<>d->>'owner_id') THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AUTHORIZATION_SCOPE'; END IF;
 END LOOP;
 IF d->>'evidence_mode'='EXPLICIT_SYNTHETIC' THEN
  IF d->>'key_binding_id' !~ '^synthetic_' OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(d->'project_ids') x WHERE x !~ '^prj_(cloud|qa3|qa4)_') THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_SYNTHETIC_SCOPE'; END IF;
 ELSIF d->>'evidence_mode' IS DISTINCT FROM 'AUTHENTICATED_HOST' OR d->>'key_binding_id' ~ '^synthetic_' THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_SYNTHETIC_SCOPE'; END IF;
 IF d->>'issued_at' IS NULL OR d->>'expires_at' IS NULL OR (d->>'issued_at')::timestamptz>clock_timestamp() OR (d->>'expires_at')::timestamptz<=clock_timestamp() OR (d->>'expires_at')::timestamptz>(d->>'issued_at')::timestamptz+interval '24 hours' THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AUTHORIZATION_EXPIRY'; END IF;
 PERFORM 1 FROM awe_e1_runtime.cloud_budget ORDER BY key_binding_id FOR UPDATE;
 SELECT * INTO a FROM awe_e1_runtime.cloud4_authorization WHERE key_binding_id=d->>'key_binding_id' FOR UPDATE;
 IF FOUND THEN
  IF a.authorization_digest<>r->>'document_digest' OR a.signed_receipt<>r THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AUTHORIZATION_IMMUTABLE'; END IF;
  RETURN jsonb_build_object('state',a.state,'owner_consent','ISSUED','authorization_digest',a.authorization_digest,'repeated',true);
 END IF;
 IF EXISTS(SELECT 1 FROM awe_e1_runtime.cloud_attempt WHERE key_binding_id=d->>'key_binding_id') THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_EXISTING_ATTEMPTS_REQUIRE_RECONCILIATION'; END IF;
 INSERT INTO awe_e1_runtime.cloud4_authorization(key_binding_id,authorization_digest,document,signed_receipt,state) VALUES(d->>'key_binding_id',r->>'document_digest',d,r,'PREPARED_PROVIDER_BLOCKED');
 RETURN jsonb_build_object('state','PREPARED_PROVIDER_BLOCKED','owner_consent','ISSUED','authorization_digest',r->>'document_digest','spending_enabled',false);
EXCEPTION WHEN OTHERS THEN RETURN jsonb_build_object('error',CASE WHEN SQLERRM ~ '^A2_[A-Z0-9_]+$' THEN SQLERRM ELSE 'A2_CLOUD_AUTHZ_AUTHORIZATION_REJECT' END);
END $$;

CREATE OR REPLACE FUNCTION awe_e1_runtime.cloud4_activate_canary(p jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE a awe_e1_runtime.cloud4_authorization%ROWTYPE;b awe_e1_runtime.cloud_budget%ROWTYPE;
BEGIN
 IF session_user NOT IN('awe_e1_coord','awe_e1_test') THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_HOST_REQUIRED'; END IF;
 PERFORM 1 FROM awe_e1_runtime.cloud_budget ORDER BY key_binding_id FOR UPDATE;
 SELECT * INTO a FROM awe_e1_runtime.cloud4_authorization WHERE key_binding_id=p->>'key_binding_id' FOR UPDATE;
 IF NOT FOUND OR a.authorization_digest IS DISTINCT FROM p->>'authorization_digest' OR a.state NOT IN('PREPARED_PROVIDER_BLOCKED','CANARY') THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AUTHORIZATION_STATE'; END IF;
 SELECT * INTO b FROM awe_e1_runtime.cloud_budget WHERE key_binding_id=a.key_binding_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_PROVIDER_PROOF_REQUIRED'; END IF;
 IF b.grant_digest IS DISTINCT FROM p->>'funding_grant_digest' OR b.state<>'ENABLED' OR b.owner_id IS DISTINCT FROM a.document->>'owner_id' OR b.grant_document->>'cloud4_authorization_digest' IS DISTINCT FROM a.authorization_digest OR b.grant_document->'project_ids' IS DISTINCT FROM a.document->'project_ids' OR b.grant_document->>'evidence_mode' IS DISTINCT FROM a.document->>'evidence_mode' OR b.budget_cap<>10000000 OR b.per_attempt_cap<>1000000 OR b.attempts_cap<>22 THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_FUNDING_BINDING'; END IF;
 IF (b.grant_document->>'expires_at')::timestamptz<=clock_timestamp() OR (b.provider_limit_evidence->>'expires_at')::timestamptz<=clock_timestamp() OR (a.document->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AUTHORIZATION_EXPIRY'; END IF;
 UPDATE awe_e1_runtime.cloud4_authorization SET state='CANARY',funding_grant_digest=b.grant_digest,activated_at=COALESCE(activated_at,clock_timestamp()) WHERE key_binding_id=a.key_binding_id;
 RETURN jsonb_build_object('state','CANARY','authorization_digest',a.authorization_digest,'canary_budget_micros','500000','canary_attempts',2,'provider_evidence_mode',b.grant_document->>'evidence_mode');
EXCEPTION WHEN OTHERS THEN RETURN jsonb_build_object('error',CASE WHEN SQLERRM ~ '^A2_[A-Z0-9_]+$' THEN SQLERRM ELSE 'A2_CLOUD_AUTHZ_ACTIVATION_REJECT' END);
END $$;

CREATE OR REPLACE FUNCTION awe_e1_runtime.cloud4_guard_attempt() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE a awe_e1_runtime.cloud4_authorization%ROWTYPE;b awe_e1_runtime.cloud_budget%ROWTYPE;phase text;phasecap bigint;percap bigint;attemptcap bigint;used_count bigint;exposure numeric;addition bigint:=0;model awe_e1_runtime.model_attempt%ROWTYPE;
BEGIN
 SELECT * INTO a FROM awe_e1_runtime.cloud4_authorization WHERE key_binding_id=NEW.key_binding_id FOR UPDATE;
 IF NOT FOUND THEN RETURN NEW; END IF;
 IF NEW.state='OUTCOME_UNKNOWN' THEN
  UPDATE awe_e1_runtime.cloud4_authorization SET state='HOLD',hold_reason='CLOUD_OUTCOME_UNKNOWN' WHERE key_binding_id=a.key_binding_id;RETURN NEW;
 END IF;
 IF NEW.state IN('CONFIRMED','FAILED') THEN RETURN NEW; END IF;
 IF a.state NOT IN('CANARY','FOLLOWUP') THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_PHASE_BLOCKED'; END IF;
 IF (a.document->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AUTHORIZATION_EXPIRY'; END IF;
 SELECT * INTO b FROM awe_e1_runtime.cloud_budget WHERE key_binding_id=NEW.key_binding_id;
 SELECT * INTO model FROM awe_e1_runtime.model_attempt WHERE attempt_id=NEW.attempt_id;
 IF b.grant_digest IS DISTINCT FROM a.funding_grant_digest OR b.grant_document->>'cloud4_authorization_digest' IS DISTINCT FROM a.authorization_digest OR NEW.quote->>'cloud4_authorization_digest' IS DISTINCT FROM a.authorization_digest OR NOT(a.document->'project_ids' ? model.project_id) OR a.document->>'owner_id' IS DISTINCT FROM (SELECT owner_id FROM awe_e1_runtime.project WHERE project_id=model.project_id) THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_FUNDING_BINDING'; END IF;
 phase:=NEW.quote->>'cloud4_phase';
 IF phase IS DISTINCT FROM a.state THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_PHASE_BINDING'; END IF;
 IF EXISTS(SELECT 1 FROM awe_e1_runtime.cloud_attempt WHERE key_binding_id=NEW.key_binding_id AND attempt_id<>NEW.attempt_id AND (state='OUTCOME_UNKNOWN' OR (NEW.state='SENDING' AND state='SENDING'))) THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_UNKNOWN_REQUIRES_HOLD'; END IF;
 IF phase='CANARY' THEN
  phasecap:=500000;percap:=250000;attemptcap:=2;
  IF NOT(a.document->'limits'->'canary'->'route_ids' ? model.route_id) THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_CANARY_ROUTE'; END IF;
 ELSE phasecap:=9500000;percap:=1000000;attemptcap:=20;END IF;
 IF NEW.reserved>percap THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_PER_ATTEMPT_LIMIT'; END IF;
 SELECT count(*),COALESCE(sum(CASE WHEN state='CONFIRMED' THEN actual_charged_micros WHEN state='FAILED' THEN 0 ELSE funded_reserved END),0) INTO used_count,exposure FROM awe_e1_runtime.cloud_attempt WHERE key_binding_id=NEW.key_binding_id AND quote->>'cloud4_phase'=phase;
 IF TG_OP='INSERT' THEN addition:=NEW.reserved;used_count:=used_count+1; END IF;
 IF used_count>attemptcap THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_PHASE_ATTEMPTS_EXHAUSTED'; END IF;
 IF exposure+addition>phasecap THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_PHASE_BUDGET_EXHAUSTED'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cloud4_guard_attempt ON awe_e1_runtime.cloud_attempt;
CREATE TRIGGER cloud4_guard_attempt BEFORE INSERT OR UPDATE ON awe_e1_runtime.cloud_attempt FOR EACH ROW EXECUTE FUNCTION awe_e1_runtime.cloud4_guard_attempt();

CREATE OR REPLACE FUNCTION awe_e1_runtime.cloud4_accept_canary(p jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE a awe_e1_runtime.cloud4_authorization%ROWTYPE;g jsonb:=p->'receipt'->'document';attempt_n bigint;confirmed_n bigint;route_n bigint;charged numeric;proof_ids jsonb;producer_ids jsonb;
BEGIN
 IF session_user NOT IN('awe_e1_coord','awe_e1_test') THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_HOST_REQUIRED'; END IF;
 PERFORM 1 FROM awe_e1_runtime.cloud_budget ORDER BY key_binding_id FOR UPDATE;
 SELECT * INTO a FROM awe_e1_runtime.cloud4_authorization WHERE key_binding_id=g->>'key_binding_id' FOR UPDATE;
 IF NOT FOUND OR a.state NOT IN('CANARY','FOLLOWUP') OR g->>'schema' IS DISTINCT FROM 'awe.e1.cloud4.canary-gate/1' OR g->>'authorization_digest' IS DISTINCT FROM a.authorization_digest OR g->>'verdict' IS DISTINCT FROM 'PASS' OR g->>'evaluator_id' IS NULL OR p->'receipt'->>'document_digest' IS DISTINCT FROM awe_e1_runtime.cloud_digest(g) OR p->'receipt'->>'public_key_digest' IS DISTINCT FROM p->>'trusted_public_key_digest' OR p->'receipt'->>'algorithm' IS DISTINCT FROM 'Ed25519' THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_INDEPENDENT_QA_REQUIRED'; END IF;
 IF (a.document->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AUTHORIZATION_EXPIRY'; END IF;
 SELECT count(*),count(*) FILTER(WHERE c.state='CONFIRMED'),count(DISTINCT m.route_id),COALESCE(sum(c.actual_charged_micros),0),jsonb_agg(c.attempt_id ORDER BY c.attempt_id),jsonb_agg(m.worker_id) INTO attempt_n,confirmed_n,route_n,charged,proof_ids,producer_ids FROM awe_e1_runtime.cloud_attempt c JOIN awe_e1_runtime.model_attempt m USING(attempt_id) WHERE c.key_binding_id=a.key_binding_id AND c.quote->>'cloud4_phase'='CANARY';
 IF attempt_n<>2 OR confirmed_n<>2 OR route_n<>2 OR charged>500000 OR producer_ids ? (g->>'evaluator_id') OR g->'attempt_ids' IS DISTINCT FROM proof_ids OR EXISTS(SELECT 1 FROM awe_e1_runtime.cloud_attempt WHERE key_binding_id=a.key_binding_id AND state IN('SENDING','OUTCOME_UNKNOWN','RESERVED')) THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_CANARY_NOT_ACCEPTED'; END IF;
 IF EXISTS(SELECT 1 FROM awe_e1_runtime.cloud_attempt c JOIN awe_e1_runtime.model_attempt m USING(attempt_id) JOIN awe_e1_runtime.cloud_task_policy pol ON pol.policy_digest=c.policy_digest WHERE c.key_binding_id=a.key_binding_id AND c.quote->>'cloud4_phase'='CANARY' AND NOT EXISTS(SELECT 1 FROM awe_e1_runtime.qa_revision q WHERE q.mission_id=m.mission_id AND q.task_id=m.task_id AND q.plan_digest=pol.plan_digest AND q.evaluator_id=g->>'evaluator_id' AND q.verdict='PASS')) THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_INDEPENDENT_QA_REQUIRED'; END IF;
 IF a.state='FOLLOWUP' THEN
  IF a.canary_qa_receipt IS DISTINCT FROM p->'receipt' THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_QA_CONFLICT'; END IF;
  RETURN jsonb_build_object('state','FOLLOWUP','repeated',true);
 END IF;
 UPDATE awe_e1_runtime.cloud4_authorization SET state='FOLLOWUP',canary_qa_receipt=p->'receipt',accepted_at=clock_timestamp() WHERE key_binding_id=a.key_binding_id;
 RETURN jsonb_build_object('state','FOLLOWUP','budget_micros','9500000','per_attempt_micros','1000000','attempts',20,'cumulative_budget_micros','10000000','accounting_reset',false);
EXCEPTION WHEN OTHERS THEN RETURN jsonb_build_object('error',CASE WHEN SQLERRM ~ '^A2_[A-Z0-9_]+$' THEN SQLERRM ELSE 'A2_CLOUD_AUTHZ_QA_REJECT' END);
END $$;
CREATE OR REPLACE FUNCTION awe_e1_runtime.cloud4_authorization_info(p jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE a awe_e1_runtime.cloud4_authorization%ROWTYPE;
BEGIN
 IF session_user NOT IN('awe_e1_coord','awe_e1_qa','awe_e1_test') THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_READ_DENIED'; END IF;
 SELECT * INTO a FROM awe_e1_runtime.cloud4_authorization WHERE key_binding_id=p->>'key_binding_id';
 IF NOT FOUND THEN RETURN jsonb_build_object('state','NOT_PREPARED','owner_consent','ISSUED_PENDING_HOST_ATTESTATION','spending_enabled',false); END IF;
 IF NOT(a.document->'project_ids' ? (p->>'project_id')) THEN RAISE EXCEPTION 'A2_PROJECT_SCOPE'; END IF;
 RETURN to_jsonb(a)||jsonb_build_object('owner_consent','ISSUED','spending_enabled',a.state IN('CANARY','FOLLOWUP'),'funding',awe_e1_runtime.cloud_command('cloud_budget',p));
EXCEPTION WHEN OTHERS THEN RETURN jsonb_build_object('error',CASE WHEN SQLERRM ~ '^A2_[A-Z0-9_]+$' THEN SQLERRM ELSE 'A2_CLOUD_AUTHZ_READ_REJECT' END);
END $$;
REVOKE ALL ON awe_e1_runtime.cloud4_authorization FROM PUBLIC,awe_e1_coord,awe_e1_worker,awe_e1_qa;
REVOKE ALL ON FUNCTION awe_e1_runtime.cloud4_install_authorization(jsonb),awe_e1_runtime.cloud4_activate_canary(jsonb),awe_e1_runtime.cloud4_guard_attempt(),awe_e1_runtime.cloud4_accept_canary(jsonb),awe_e1_runtime.cloud4_authorization_info(jsonb) FROM PUBLIC,awe_e1_coord,awe_e1_worker,awe_e1_qa;
GRANT EXECUTE ON FUNCTION awe_e1_runtime.cloud4_install_authorization(jsonb),awe_e1_runtime.cloud4_activate_canary(jsonb),awe_e1_runtime.cloud4_accept_canary(jsonb),awe_e1_runtime.cloud4_authorization_info(jsonb) TO awe_e1_coord;
GRANT EXECUTE ON FUNCTION awe_e1_runtime.cloud4_authorization_info(jsonb) TO awe_e1_qa;
INSERT INTO awe_e1_runtime.schema_migration VALUES(4,clock_timestamp()) ON CONFLICT DO NOTHING;
COMMIT;
