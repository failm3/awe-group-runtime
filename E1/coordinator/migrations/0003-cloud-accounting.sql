-- E1 cloud accounting is additive. Frozen 0001/0002 remain the local baseline.
-- This resource is LOCAL_TEST_ONLY. No provider grant or cap is installed here.
BEGIN;
DO $$
DECLARE identity jsonb;
BEGIN
  IF session_user<>'awe_e1_test' OR current_database()<>'awe_e1_test' OR current_setting('port')<>'5433' OR current_setting('data_directory')<>'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/pgdata' OR current_setting('unix_socket_directories')<>'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/socket' THEN RAISE EXCEPTION 'A2_MIGRATION_RESOURCE_DENIED'; END IF;
  SELECT to_jsonb(i) INTO identity FROM awe_e1_resource.identity i WHERE resource_id='awe_e1_a2a3_20261108';
  IF identity IS DISTINCT FROM jsonb_build_object('resource_id','awe_e1_a2a3_20261108','database_name','awe_e1_test','port',5433,'scope','LOCAL_TEST_ONLY') THEN RAISE EXCEPTION 'A2_MIGRATION_RESOURCE_DENIED'; END IF;
END $$;

-- The host binds a key identity to exactly one shared group. All projects using
-- that key consume this same row. Missing row means disabled, all caps zero.
CREATE TABLE IF NOT EXISTS awe_e1_runtime.cloud_budget(
  key_binding_id text PRIMARY KEY, budget_group_id text NOT NULL CHECK(budget_group_id='router.cheap.shared/1'),
  owner_id text NOT NULL, grant_digest text NOT NULL, grant_document jsonb NOT NULL,
  provider_limit_evidence_digest text NOT NULL, provider_limit_evidence jsonb NOT NULL,
  budget_cap bigint NOT NULL CHECK(budget_cap>0), per_attempt_cap bigint NOT NULL CHECK(per_attempt_cap>0),
  attempts_cap bigint NOT NULL CHECK(attempts_cap>0), spent bigint NOT NULL DEFAULT 0 CHECK(spent>=0),
  reserved bigint NOT NULL DEFAULT 0 CHECK(reserved>=0), attempts_used bigint NOT NULL DEFAULT 0 CHECK(attempts_used>=0),
  state text NOT NULL CHECK(state IN('ENABLED','HOLD')), installed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK(per_attempt_cap<=budget_cap),CHECK(spent+reserved<=budget_cap),CHECK(attempts_used<=attempts_cap));
CREATE TABLE IF NOT EXISTS awe_e1_runtime.cloud_task_policy(
  mission_id text NOT NULL,task_id text NOT NULL,plan_digest text NOT NULL,project_id text NOT NULL,
  key_binding_id text NOT NULL,policy_digest text NOT NULL,policy jsonb NOT NULL,
  PRIMARY KEY(mission_id,task_id,plan_digest),FOREIGN KEY(mission_id,task_id) REFERENCES awe_e1_runtime.task);
CREATE TABLE IF NOT EXISTS awe_e1_runtime.cloud_attempt(
  attempt_id text PRIMARY KEY REFERENCES awe_e1_runtime.model_attempt,key_binding_id text NOT NULL REFERENCES awe_e1_runtime.cloud_budget,
  policy_digest text NOT NULL,route_snapshot_digest text NOT NULL,route_snapshot jsonb NOT NULL,quote jsonb NOT NULL,
  reserved bigint NOT NULL CHECK(reserved>=0),funded_reserved bigint NOT NULL CHECK(funded_reserved>=0),
  state text NOT NULL,provider_request_id text,priced_usage_micros bigint,actual_charged_micros bigint,
  settlement jsonb,hold_reason text,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK(funded_reserved<=reserved),CHECK(actual_charged_micros IS NULL OR actual_charged_micros>=0));
CREATE UNIQUE INDEX IF NOT EXISTS cloud_provider_request_once ON awe_e1_runtime.cloud_attempt(key_binding_id,provider_request_id) WHERE provider_request_id IS NOT NULL;

-- These cloud contracts contain bounded ASCII and safe integral JSON numbers.
-- Canonical ordering equals the A1 UTF-16 key order for this vocabulary.
CREATE OR REPLACE FUNCTION awe_e1_runtime.cloud_canonical(v jsonb,depth integer DEFAULT 0) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE value text;
BEGIN
  IF depth>12 THEN RAISE EXCEPTION 'A2_CLOUD_DOCUMENT_SCHEMA'; END IF;
  CASE jsonb_typeof(v)
    WHEN 'object' THEN
      IF (SELECT count(*) FROM jsonb_object_keys(v))>64 OR EXISTS(SELECT 1 FROM jsonb_object_keys(v) k WHERE k !~ '^[a-zA-Z0-9_.:/-]{1,100}$') THEN RAISE EXCEPTION 'A2_CLOUD_DOCUMENT_SCHEMA'; END IF;
      SELECT '{'||COALESCE(string_agg(to_jsonb(key)::text||':'||awe_e1_runtime.cloud_canonical(val,depth+1),',' ORDER BY key COLLATE "C"),'')||'}' INTO value FROM jsonb_each(v) e(key,val);
    WHEN 'array' THEN
      IF jsonb_array_length(v)>64 THEN RAISE EXCEPTION 'A2_CLOUD_DOCUMENT_SCHEMA'; END IF;
      SELECT '['||COALESCE(string_agg(awe_e1_runtime.cloud_canonical(val,depth+1),',' ORDER BY n),'')||']' INTO value FROM jsonb_array_elements(v) WITH ORDINALITY e(val,n);
    WHEN 'string' THEN
      IF length(v#>>'{}')>1024 OR (v#>>'{}') !~ '^[ -~]*$' THEN RAISE EXCEPTION 'A2_CLOUD_DOCUMENT_SCHEMA'; END IF;
      value:=v::text;
    WHEN 'number' THEN
      IF v::text !~ '^(0|[1-9][0-9]{0,15})$' OR (v::text)::numeric>9007199254740991 THEN RAISE EXCEPTION 'A2_CLOUD_DOCUMENT_SCHEMA'; END IF;
      value:=v::text;
    WHEN 'boolean' THEN value:=v::text;
    WHEN 'null' THEN value:='null';
    ELSE RAISE EXCEPTION 'A2_CLOUD_DOCUMENT_SCHEMA';
  END CASE;
  RETURN value;
END $$;
CREATE OR REPLACE FUNCTION awe_e1_runtime.cloud_digest(v jsonb) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,awe_e1_runtime AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(awe_e1_runtime.cloud_canonical(v),'UTF8')),'hex')
$$;
CREATE OR REPLACE FUNCTION awe_e1_runtime.cloud_uint(v text) RETURNS bigint
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,awe_e1_runtime AS $$
BEGIN
  IF v IS NULL OR v !~ '^(0|[1-9][0-9]{0,15})$' OR v::numeric>9007199254740991 THEN RAISE EXCEPTION 'A2_CLOUD_INTEGER'; END IF;
  RETURN v::bigint;
END $$;
CREATE OR REPLACE FUNCTION awe_e1_runtime.cloud_fraction(v jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,awe_e1_runtime AS $$
BEGIN
  IF jsonb_typeof(v) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(v))<>2 OR NOT(v ?& ARRAY['numerator','denominator']) THEN RAISE EXCEPTION 'A2_CLOUD_PRICE_FRACTION'; END IF;
  IF v->>'numerator' IS NULL OR v->>'denominator' IS NULL OR v->>'numerator' !~ '^(0|[1-9][0-9]{0,35})$' OR v->>'denominator' !~ '^[1-9][0-9]{0,35}$' THEN RAISE EXCEPTION 'A2_CLOUD_PRICE_FRACTION'; END IF;
  RETURN true;
END $$;

-- All rational additions/multiplications use integer NUMERIC arithmetic. div()
-- and mod() perform the final ceil without a floating point or ppm conversion.
CREATE OR REPLACE FUNCTION awe_e1_runtime.cloud_cost(s jsonb,input_n bigint,cache_n bigint,output_n bigint,worst boolean,multiplied boolean DEFAULT true) RETURNS bigint
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE i jsonb:=s->'input_micros_per_token';c jsonb:=s->'cached_input_micros_per_token';o jsonb:=s->'output_micros_per_token';f jsonb:=s->'coefficient';
  ni numeric;di numeric;nc numeric;dc numeric;no numeric;do_ numeric;nf numeric;df numeric;n numeric;d numeric;answer numeric;
BEGIN
  PERFORM awe_e1_runtime.cloud_fraction(i);PERFORM awe_e1_runtime.cloud_fraction(c);PERFORM awe_e1_runtime.cloud_fraction(o);PERFORM awe_e1_runtime.cloud_fraction(f);
  ni:=(i->>'numerator')::numeric;di:=(i->>'denominator')::numeric;nc:=(c->>'numerator')::numeric;dc:=(c->>'denominator')::numeric;no:=(o->>'numerator')::numeric;do_:=(o->>'denominator')::numeric;nf:=(f->>'numerator')::numeric;df:=(f->>'denominator')::numeric;
  IF nf=0 OR input_n<0 OR cache_n<0 OR cache_n>input_n OR output_n<0 THEN RAISE EXCEPTION 'A2_CLOUD_USAGE'; END IF;
  IF worst THEN
    IF ni*dc<nc*di THEN ni:=nc;di:=dc; END IF;
    n:=ni*input_n*do_+no*output_n*di;d:=di*do_;
  ELSE
    n:=ni*(input_n-cache_n)*dc*do_+nc*cache_n*di*do_+no*output_n*di*dc;d:=di*dc*do_;
  END IF;
  IF multiplied THEN n:=n*nf;d:=d*df; END IF;
  answer:=div(n,d)+CASE WHEN mod(n,d)>0 THEN 1 ELSE 0 END;
  IF answer>9007199254740991 THEN RAISE EXCEPTION 'A2_CLOUD_COST_LIMIT'; END IF;
  RETURN answer::bigint;
END $$;

CREATE OR REPLACE FUNCTION awe_e1_runtime.cloud_assert_snapshot(v jsonb,route text,fresh boolean DEFAULT true) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE source jsonb;observed timestamptz;expiry timestamptz;
BEGIN
  IF v->>'schema' IS DISTINCT FROM 'awe.e1.cloud-route/1' OR v->>'provider' IS DISTINCT FROM 'router.cheap' OR v->>'endpoint' IS DISTINCT FROM 'https://router.cheap/v1/chat/completions' OR v->>'route_id' IS DISTINCT FROM route OR NOT COALESCE(v->>'model_id' ~ '^[a-zA-Z0-9][a-zA-Z0-9/_.:-]{0,127}$',false) OR NOT COALESCE(v->>'route_version' ~ '^[1-9][0-9]*[.][0-9]+[.][0-9]+$',false) OR NOT COALESCE(v->>'source_digest' ~ '^sha256:[a-f0-9]{64}$',false) OR NOT COALESCE(v->>'input_bound_evidence_digest' ~ '^sha256:[a-f0-9]{64}$',false) OR v->>'input_token_bound' IS DISTINCT FROM 'HOST_VERIFIED_UPPER_BOUND' THEN RAISE EXCEPTION 'A2_CLOUD_ROUTE_SNAPSHOT'; END IF;
  IF jsonb_typeof(v->'features') IS DISTINCT FROM 'object' OR EXISTS(SELECT 1 FROM unnest(ARRAY['chat_completions','strict_json_schema','non_streaming','source_identity','provider_request_id','usage','actual_billed_charge','bounded_input_tokens']) feature WHERE v->'features'->>feature IS DISTINCT FROM 'CONFIRMED') THEN RAISE EXCEPTION 'A2_CLOUD_PROVIDER_FEATURES'; END IF;
  IF awe_e1_runtime.cloud_uint(v->>'context_tokens')<1 OR awe_e1_runtime.cloud_uint(v->>'max_output_tokens')<1 OR awe_e1_runtime.cloud_uint(v->>'max_output_tokens')>awe_e1_runtime.cloud_uint(v->>'context_tokens') THEN RAISE EXCEPTION 'A2_CLOUD_ROUTE_SNAPSHOT'; END IF;
  IF jsonb_typeof(v->'sources') IS DISTINCT FROM 'array' OR jsonb_array_length(v->'sources') NOT BETWEEN 1 AND 32 OR (SELECT count(DISTINCT s->>'source_id') FROM jsonb_array_elements(v->'sources') s)<>jsonb_array_length(v->'sources') THEN RAISE EXCEPTION 'A2_CLOUD_PRICE_SOURCE'; END IF;
  FOR source IN SELECT * FROM jsonb_array_elements(v->'sources') LOOP
    IF NOT COALESCE(source->>'source_id' ~ '^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$',false) OR NOT COALESCE(source->>'price_evidence_digest' ~ '^sha256:[a-f0-9]{64}$',false) THEN RAISE EXCEPTION 'A2_CLOUD_PRICE_SOURCE'; END IF;
    PERFORM awe_e1_runtime.cloud_cost(source,1,0,1,true);
  END LOOP;
  observed:=(v->>'observed_at')::timestamptz;expiry:=(v->>'expires_at')::timestamptz;
  IF observed IS NULL OR expiry IS NULL OR observed>=expiry OR (fresh AND (observed>clock_timestamp()+interval '10 seconds' OR expiry<=clock_timestamp())) THEN RAISE EXCEPTION 'A2_CLOUD_QUOTE_EXPIRED'; END IF;
END $$;

-- No RPC method exposes this function. Its caller must be the host coordinator
-- after actual owner-funding and actual provider-limit evidence verification.
-- No update/reset/recharge path exists; an exact document is idempotent only.
CREATE OR REPLACE FUNCTION awe_e1_runtime.provision_cloud_budget(p jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE g jsonb:=p->'grant';e jsonb:=p->'provider_limit_evidence';b awe_e1_runtime.cloud_budget%ROWTYPE;
  cap bigint;percap bigint;attemptcap bigint;projectid text;nowat timestamptz:=clock_timestamp();
BEGIN
  IF session_user NOT IN('awe_e1_coord','awe_e1_test') THEN RAISE EXCEPTION 'A2_CLOUD_FUNDING_ROLE_DENIED'; END IF;
  IF g->>'schema' IS DISTINCT FROM 'awe.e1.cloud-funding-grant/1' OR g->>'budget_group_id' IS DISTINCT FROM 'router.cheap.shared/1' OR g->>'key_binding_id' IS NULL OR g->>'key_binding_id' !~ '^[a-z][a-z0-9_.-]{0,79}$' OR g->>'owner_id' IS NULL OR g->>'owner_id' !~ '^[a-z][a-z0-9_.-]{0,79}$' OR NOT COALESCE(g->>'owner_grant_digest' ~ '^sha256:[a-f0-9]{64}$',false) OR p->>'grant_digest' IS DISTINCT FROM awe_e1_runtime.cloud_digest(g) OR p->>'provider_limit_evidence_digest' IS DISTINCT FROM awe_e1_runtime.cloud_digest(e) THEN RAISE EXCEPTION 'A2_CLOUD_FUNDING_DIGEST'; END IF;
  cap:=awe_e1_runtime.cloud_uint(g->>'budget_cap_micros');percap:=awe_e1_runtime.cloud_uint(g->>'per_attempt_cap_micros');attemptcap:=awe_e1_runtime.cloud_uint(g->>'attempts_cap');
  IF cap<1 OR percap<1 OR percap>cap OR attemptcap<1 THEN RAISE EXCEPTION 'A2_CLOUD_FUNDING_LIMIT'; END IF;
  IF jsonb_typeof(g->'project_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(g->'project_ids') NOT BETWEEN 1 AND 32 OR (SELECT count(DISTINCT x) FROM jsonb_array_elements_text(g->'project_ids') x)<>jsonb_array_length(g->'project_ids') THEN RAISE EXCEPTION 'A2_CLOUD_FUNDING_PROJECTS'; END IF;
  FOR projectid IN SELECT * FROM jsonb_array_elements_text(g->'project_ids') LOOP IF projectid !~ '^[a-z][a-z0-9_.-]{0,79}$' THEN RAISE EXCEPTION 'A2_CLOUD_FUNDING_PROJECTS'; END IF; END LOOP;
  IF e->>'schema' IS DISTINCT FROM 'awe.e1.provider-hard-charge-limit/1' OR e->>'provider' IS DISTINCT FROM 'router.cheap' OR e->>'key_binding_id' IS DISTINCT FROM g->>'key_binding_id' OR e->>'currency' IS DISTINCT FROM 'USD' OR e->>'enforcement' IS DISTINCT FROM 'HARD_ACTUAL_CHARGE' OR e->'request_hard_cap_supported' IS DISTINCT FROM 'true'::jsonb OR e->>'evidence_mode' IS DISTINCT FROM g->>'evidence_mode' OR NOT COALESCE(e->>'account_binding_digest' ~ '^sha256:[a-f0-9]{64}$',false) OR e->>'limit_ref' IS NULL THEN RAISE EXCEPTION 'A2_CLOUD_HARD_PROVIDER_CAP_REQUIRED'; END IF;
  IF awe_e1_runtime.cloud_uint(e->>'actual_charge_cap_micros')<cap OR awe_e1_runtime.cloud_uint(e->>'max_request_actual_charge_micros')<percap THEN RAISE EXCEPTION 'A2_CLOUD_HARD_PROVIDER_CAP_REQUIRED'; END IF;
  IF g->>'evidence_mode'='EXPLICIT_SYNTHETIC' THEN
    IF g->>'key_binding_id' !~ '^synthetic_' OR NOT COALESCE(g->>'funding_ref' ~ '^synthetic:',false) OR e->>'limit_ref' !~ '^synthetic:' OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(g->'project_ids') x WHERE x !~ '^prj_(cloud|qa3)_') THEN RAISE EXCEPTION 'A2_CLOUD_SYNTHETIC_SCOPE'; END IF;
  ELSIF g->>'evidence_mode' IS DISTINCT FROM 'AUTHENTICATED_HOST' OR g->>'key_binding_id' ~ '^synthetic_' OR g->>'funding_ref' IS NULL OR g->>'funding_ref' ~ '^synthetic:' OR e->>'limit_ref' ~ '^synthetic:' THEN RAISE EXCEPTION 'A2_CLOUD_SYNTHETIC_SCOPE'; END IF;
  SELECT * INTO b FROM awe_e1_runtime.cloud_budget WHERE key_binding_id=g->>'key_binding_id' FOR UPDATE;
  IF FOUND THEN
    IF b.grant_digest<>p->>'grant_digest' OR b.grant_document<>g OR b.provider_limit_evidence_digest<>p->>'provider_limit_evidence_digest' OR b.provider_limit_evidence<>e THEN RAISE EXCEPTION 'A2_CLOUD_FUNDING_IMMUTABLE'; END IF;
    RETURN jsonb_build_object('status',b.state,'repeated',true,'key_binding_id',b.key_binding_id,'grant_digest',b.grant_digest);
  END IF;
  IF (g->>'issued_at')::timestamptz>nowat OR (g->>'expires_at')::timestamptz<=nowat OR (g->>'issued_at')::timestamptz>=(g->>'expires_at')::timestamptz OR (e->>'issued_at')::timestamptz>nowat OR (e->>'expires_at')::timestamptz<=nowat OR (e->>'issued_at')::timestamptz>=(e->>'expires_at')::timestamptz OR g->>'expires_at' IS NULL OR e->>'expires_at' IS NULL OR g->>'issued_at' IS NULL OR e->>'issued_at' IS NULL THEN RAISE EXCEPTION 'A2_CLOUD_FUNDING_EXPIRY'; END IF;
  -- A second key alias for the same account evidence must not create new money.
  IF EXISTS(SELECT 1 FROM awe_e1_runtime.cloud_budget WHERE provider_limit_evidence->>'account_binding_digest'=e->>'account_binding_digest') THEN RAISE EXCEPTION 'A2_CLOUD_ACCOUNT_ALREADY_BOUND'; END IF;
  INSERT INTO awe_e1_runtime.cloud_budget(key_binding_id,budget_group_id,owner_id,grant_digest,grant_document,provider_limit_evidence_digest,provider_limit_evidence,budget_cap,per_attempt_cap,attempts_cap,state) VALUES(g->>'key_binding_id','router.cheap.shared/1',g->>'owner_id',p->>'grant_digest',g,p->>'provider_limit_evidence_digest',e,cap,percap,attemptcap,'ENABLED');
  RETURN jsonb_build_object('status','ENABLED','key_binding_id',g->>'key_binding_id','grant_digest',p->>'grant_digest','evidence_mode',g->>'evidence_mode');
EXCEPTION WHEN OTHERS THEN RETURN jsonb_build_object('error',CASE WHEN SQLERRM ~ '^A2_[A-Z_]+$' THEN SQLERRM ELSE 'A2_CLOUD_FUNDING_REJECT' END);
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS cloud_account_single_budget ON awe_e1_runtime.cloud_budget((provider_limit_evidence->>'account_binding_digest'));

CREATE OR REPLACE FUNCTION awe_e1_runtime.cloud_sync() RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE a record;
BEGIN
  FOR a IN SELECT c.attempt_id,c.key_binding_id,c.funded_reserved,m.state FROM awe_e1_runtime.cloud_attempt c JOIN awe_e1_runtime.model_attempt m USING(attempt_id) WHERE c.state IS DISTINCT FROM m.state OR (m.state='FAILED' AND c.funded_reserved>0) ORDER BY c.key_binding_id,c.attempt_id FOR UPDATE OF c LOOP
    IF a.state='FAILED' AND a.funded_reserved>0 THEN
      UPDATE awe_e1_runtime.cloud_budget SET reserved=reserved-a.funded_reserved WHERE key_binding_id=a.key_binding_id;
      UPDATE awe_e1_runtime.cloud_attempt SET funded_reserved=0 WHERE attempt_id=a.attempt_id;
    END IF;
    UPDATE awe_e1_runtime.cloud_attempt SET state=a.state WHERE attempt_id=a.attempt_id;
  END LOOP;
END $$;

CREATE OR REPLACE FUNCTION awe_e1_runtime.cloud_command(op text,p jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE result jsonb;item jsonb;cp jsonb;r jsonb;s jsonb;v jsonb;quote jsonb:=p->'cloud';settlement_doc jsonb:=p->'cloud';
  a awe_e1_runtime.model_attempt%ROWTYPE;c awe_e1_runtime.cloud_attempt%ROWTYPE;b awe_e1_runtime.cloud_budget%ROWTYPE;t awe_e1_runtime.task%ROWTYPE;
  policyrow awe_e1_runtime.cloud_task_policy%ROWTYPE;scope_project text:=p->>'project_id';route text;keyid text;reserve_n bigint;priced bigint;base_n bigint;actual_n bigint;in_n bigint;cache_n bigint;out_n bigint;worst bigint;reason text;
BEGIN
  IF session_user NOT IN('awe_e1_test','awe_e1_coord','awe_e1_qa') THEN RAISE EXCEPTION 'A2_ROLE_DENIED'; END IF;
  IF session_user='awe_e1_qa' AND op NOT IN('snapshot','events','qa_evaluate','get_cursor','cloud_budget') THEN RAISE EXCEPTION 'A2_QA_WRITE_DENIED'; END IF;
  IF scope_project IS NULL OR scope_project !~ '^[a-z][a-z0-9_.-]{0,79}$' THEN RAISE EXCEPTION 'A2_PROJECT_SCOPE'; END IF;
  -- Stable order also covers cancellation/recovery of several projects/keys.
  PERFORM 1 FROM awe_e1_runtime.cloud_budget ORDER BY key_binding_id FOR UPDATE;
  IF op='cloud_budget' THEN
    SELECT * INTO b FROM awe_e1_runtime.cloud_budget WHERE key_binding_id=p->>'key_binding_id';
    v:=jsonb_build_object('schema','awe.e1.cloud-accounting-semantics/1','amount_encoding','UNSIGNED_DECIMAL_STRING_USD_MICROS','spent','BOOKED_CONFIRMED_CHARGES_ONLY','observed_held_charge_micros','OBSERVED_UNCONFIRMED_CHARGES_ON_HELD_ATTEMPTS','observed_overrun_micros','SUM_OF_POSITIVE_OBSERVED_HELD_CHARGE_MINUS_ORIGINAL_RESERVATION','unknown_charge_attempts','SENDING_OR_UNKNOWN_ATTEMPTS_WITHOUT_OBSERVED_CHARGE','unknown_charge_cost','UNKNOWN_NOT_ZERO');
    IF NOT FOUND THEN RETURN jsonb_build_object('state','DISABLED','budget_group_id','router.cheap.shared/1','key_binding_id',p->>'key_binding_id','budget_cap',0,'per_attempt_cap',0,'attempts_cap',0,'spent',0,'reserved',0,'attempts_used',0,'booked_confirmed_micros','0','observed_held_charge_micros','0','observed_overrun_micros','0','unknown_charge_attempts',0,'accounting_semantics',v,'reason','OWNER_FUNDING_AND_HARD_PROVIDER_CAP_NOT_VERIFIED'); END IF;
    IF NOT(b.grant_document->'project_ids' ? scope_project) THEN RAISE EXCEPTION 'A2_CLOUD_FUNDING_PROJECTS'; END IF;
    RETURN to_jsonb(b)||jsonb_build_object('booked_confirmed_micros',b.spent::text,'observed_held_charge_micros',COALESCE((SELECT sum(ca.actual_charged_micros)::text FROM awe_e1_runtime.cloud_attempt ca WHERE ca.key_binding_id=b.key_binding_id AND ca.state='OUTCOME_UNKNOWN' AND ca.actual_charged_micros IS NOT NULL),'0'),'observed_overrun_micros',COALESCE((SELECT sum(GREATEST(ca.actual_charged_micros-ca.reserved,0))::text FROM awe_e1_runtime.cloud_attempt ca WHERE ca.key_binding_id=b.key_binding_id AND ca.state='OUTCOME_UNKNOWN' AND ca.actual_charged_micros IS NOT NULL),'0'),'unknown_charge_attempts',(SELECT count(*) FROM awe_e1_runtime.cloud_attempt ca WHERE ca.key_binding_id=b.key_binding_id AND ca.state IN('SENDING','OUTCOME_UNKNOWN') AND ca.actual_charged_micros IS NULL),'accounting_semantics',v);
  END IF;
  IF op='admit' THEN
    FOR item IN SELECT * FROM jsonb_array_elements(p->'tasks') LOOP
      cp:=item->'cloud_policy';
      IF cp IS NOT NULL THEN
        IF cp->>'schema' IS DISTINCT FROM 'awe.e1.cloud-task-policy/1' OR cp->>'budget_group_id' IS DISTINCT FROM 'router.cheap.shared/1' OR cp->>'key_binding_id' IS NULL OR cp->>'key_binding_id' !~ '^[a-z][a-z0-9_.-]{0,79}$' OR NOT COALESCE(cp->>'funding_grant_digest' ~ '^sha256:[a-f0-9]{64}$',false) OR cp->>'owner_grant_digest' IS DISTINCT FROM p->>'grant_digest' OR item->>'executor_kind' IS DISTINCT FROM 'llm' OR item->'spec'->'effect'->>'effect_class' IS DISTINCT FROM 'NONE' OR jsonb_typeof(cp->'routes') IS DISTINCT FROM 'array' OR jsonb_array_length(cp->'routes') NOT BETWEEN 1 AND 4 THEN RAISE EXCEPTION 'A2_CLOUD_TASK_POLICY'; END IF;
        IF (SELECT count(DISTINCT x->>'route_id') FROM jsonb_array_elements(cp->'routes') x)<>jsonb_array_length(cp->'routes') THEN RAISE EXCEPTION 'A2_CLOUD_TASK_POLICY'; END IF;
        FOR r IN SELECT * FROM jsonb_array_elements(cp->'routes') LOOP
          IF r->>'route_id' IS NULL OR r->>'route_id' !~ '^router[.]cheap[.]chat[.][a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}$' OR r->>'snapshot_digest' IS DISTINCT FROM awe_e1_runtime.cloud_digest(r->'snapshot') OR NOT(item->'model_routes' ? (r->>'route_id')) THEN RAISE EXCEPTION 'A2_CLOUD_ROUTE_SNAPSHOT'; END IF;
          PERFORM awe_e1_runtime.cloud_assert_snapshot(r->'snapshot',r->>'route_id');
        END LOOP;
        SELECT * INTO policyrow FROM awe_e1_runtime.cloud_task_policy WHERE mission_id=p->'spec'->>'mission_id' AND task_id=item->'spec'->>'task_id' AND plan_digest=p->>'plan_digest';
        IF FOUND AND policyrow.policy<>cp THEN RAISE EXCEPTION 'A2_CLOUD_TASK_POLICY_IMMUTABLE'; END IF;
      END IF;
      FOR route IN SELECT * FROM jsonb_array_elements_text(item->'model_routes') LOOP
        IF route<>'ollama.local.qwen3-4b-instruct' AND (cp IS NULL OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(cp->'routes') x WHERE x->>'route_id'=route)) THEN RAISE EXCEPTION 'A2_MODEL_ROUTE_POLICY'; END IF;
      END LOOP;
    END LOOP;
  END IF;

  IF op IN('reserve','mark_sending','settle','unknown','fail_before_send') THEN
    SELECT * INTO a FROM awe_e1_runtime.model_attempt WHERE attempt_id=p->>'attempt_id';
    IF FOUND THEN route:=a.route_id; ELSE route:=p->>'route_id'; END IF;
    IF route LIKE 'router.cheap.chat.%' THEN
      IF a.attempt_id IS NOT NULL AND (a.project_id<>scope_project OR a.mission_id<>p->>'mission_id' OR a.task_id<>p->>'task_id' OR a.worker_id<>p->>'worker_id' OR a.logical_request_id<>p->>'logical_request_id' OR a.fence<>(p->>'fence')::bigint) THEN RAISE EXCEPTION 'A2_ATTEMPT_SCOPE'; END IF;
      SELECT * INTO t FROM awe_e1_runtime.task WHERE project_id=scope_project AND mission_id=p->>'mission_id' AND task_id=p->>'task_id';
      SELECT * INTO policyrow FROM awe_e1_runtime.cloud_task_policy WHERE mission_id=t.mission_id AND task_id=t.task_id AND plan_digest=t.plan_digest;
      IF policyrow.policy IS NULL THEN RAISE EXCEPTION 'A2_CLOUD_TASK_POLICY'; END IF;
      cp:=policyrow.policy;keyid:=cp->>'key_binding_id';
      SELECT * INTO b FROM awe_e1_runtime.cloud_budget WHERE key_binding_id=keyid FOR UPDATE;
      SELECT * INTO c FROM awe_e1_runtime.cloud_attempt WHERE attempt_id=p->>'attempt_id' FOR UPDATE;
      IF op IN('reserve','mark_sending') THEN
        IF b.key_binding_id IS NULL THEN RAISE EXCEPTION 'A2_CLOUD_BUDGET_DISABLED'; END IF;
        IF b.state<>'ENABLED' THEN RAISE EXCEPTION 'A2_CLOUD_BUDGET_HOLD'; END IF;
        IF b.grant_digest IS DISTINCT FROM cp->>'funding_grant_digest' OR NOT(b.grant_document->'project_ids' ? scope_project) OR b.owner_id IS DISTINCT FROM (SELECT owner_id FROM awe_e1_runtime.project WHERE project_id=scope_project) OR cp->>'owner_grant_digest' IS DISTINCT FROM (SELECT grant_digest FROM awe_e1_runtime.mission WHERE mission_id=t.mission_id) THEN RAISE EXCEPTION 'A2_CLOUD_FUNDING_SCOPE'; END IF;
        IF (b.grant_document->>'expires_at')::timestamptz<=clock_timestamp() OR (b.provider_limit_evidence->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION 'A2_CLOUD_FUNDING_EXPIRY'; END IF;
        SELECT x INTO r FROM jsonb_array_elements(cp->'routes') x WHERE x->>'route_id'=route;
        IF r IS NULL THEN RAISE EXCEPTION 'A2_CLOUD_ROUTE_SNAPSHOT'; END IF;
        PERFORM awe_e1_runtime.cloud_assert_snapshot(r->'snapshot',route);
      END IF;
      IF op='reserve' THEN
        IF quote IS NULL OR quote->>'route_snapshot_digest' IS DISTINCT FROM r->>'snapshot_digest' OR quote->>'quote_digest' IS NULL OR quote->>'quote_digest' !~ '^sha256:[a-f0-9]{64}$' THEN RAISE EXCEPTION 'A2_CLOUD_QUOTE_BINDING'; END IF;
        in_n:=awe_e1_runtime.cloud_uint(quote->>'input_tokens_bound');cache_n:=awe_e1_runtime.cloud_uint(quote->>'cached_input_tokens_bound');out_n:=awe_e1_runtime.cloud_uint(quote->>'output_tokens_bound');
        IF cache_n<>in_n OR in_n+out_n>awe_e1_runtime.cloud_uint(r->'snapshot'->>'context_tokens') OR out_n>awe_e1_runtime.cloud_uint(r->'snapshot'->>'max_output_tokens') OR out_n<1 THEN RAISE EXCEPTION 'A2_CLOUD_QUOTE_BOUND'; END IF;
        worst:=0;
        FOR s IN SELECT * FROM jsonb_array_elements(r->'snapshot'->'sources') LOOP worst:=GREATEST(worst,awe_e1_runtime.cloud_cost(s,in_n,cache_n,out_n,true));END LOOP;
        reserve_n:=awe_e1_runtime.cloud_uint(p->>'reserve_micros');
        IF reserve_n<1 OR reserve_n<>worst OR awe_e1_runtime.cloud_uint(quote->>'worst_case_micros')<>worst OR awe_e1_runtime.cloud_uint(quote->>'request_charge_cap_micros')<>reserve_n OR awe_e1_runtime.cloud_uint(p->>'quota_units')<>1 THEN RAISE EXCEPTION 'A2_CLOUD_RESERVATION_PRICE'; END IF;
        IF c.attempt_id IS NOT NULL THEN
          IF c.quote<>quote OR c.route_snapshot_digest<>r->>'snapshot_digest' OR c.reserved<>reserve_n THEN RAISE EXCEPTION 'A2_CLOUD_ATTEMPT_CONFLICT'; END IF;
        ELSE
          IF reserve_n>b.per_attempt_cap THEN RAISE EXCEPTION 'A2_CLOUD_PER_ATTEMPT_LIMIT'; END IF;
          IF b.spent+b.reserved+reserve_n>b.budget_cap THEN RAISE EXCEPTION 'A2_CLOUD_BUDGET_EXHAUSTED'; END IF;
          IF b.attempts_used>=b.attempts_cap THEN RAISE EXCEPTION 'A2_CLOUD_ATTEMPTS_EXHAUSTED'; END IF;
        END IF;
      ELSIF op='settle' THEN
        IF c.attempt_id IS NULL THEN RAISE EXCEPTION 'A2_CLOUD_ATTEMPT_SCOPE'; END IF;
        IF settlement_doc IS NULL OR settlement_doc->>'provider_request_id' IS NULL OR length(settlement_doc->>'provider_request_id') NOT BETWEEN 1 AND 256 OR settlement_doc->>'provider_request_id' IS DISTINCT FROM p->>'provider_ref' OR settlement_doc->>'source_id' IS NULL OR settlement_doc->>'source_factor_ref' IS DISTINCT FROM settlement_doc->>'source_id' OR NOT COALESCE(settlement_doc->>'source_factor_digest' ~ '^sha256:[a-f0-9]{64}$',false) OR NOT COALESCE(settlement_doc->>'charge_evidence_digest' ~ '^sha256:[a-f0-9]{64}$',false) OR settlement_doc->>'route_snapshot_digest' IS DISTINCT FROM c.route_snapshot_digest OR settlement_doc->>'quote_digest' IS DISTINCT FROM c.quote->>'quote_digest' THEN RAISE EXCEPTION 'A2_CLOUD_SETTLEMENT_EVIDENCE'; END IF;
        IF (b.grant_document->>'evidence_mode'='EXPLICIT_SYNTHETIC' AND settlement_doc->>'charge_evidence_label' IS DISTINCT FROM 'EXPLICIT_SYNTHETIC_FAKE_PROVIDER_CHARGED_COST') OR (b.grant_document->>'evidence_mode'<>'EXPLICIT_SYNTHETIC' AND settlement_doc->>'charge_evidence_label' IS DISTINCT FROM 'PROVIDER_AUTHENTICATED_BILLING') THEN RAISE EXCEPTION 'A2_CLOUD_SETTLEMENT_EVIDENCE'; END IF;
        actual_n:=awe_e1_runtime.cloud_uint(settlement_doc->>'actual_charged_micros');
        IF actual_n<>awe_e1_runtime.cloud_uint(p->>'actual_cost_micros') THEN RAISE EXCEPTION 'A2_CLOUD_ACTUAL_CHARGE_BINDING'; END IF;
        IF a.state='CONFIRMED' THEN
          IF c.settlement IS DISTINCT FROM settlement_doc THEN RAISE EXCEPTION 'A2_SETTLEMENT_CONFLICT'; END IF;
        ELSE
          in_n:=awe_e1_runtime.cloud_uint(p->'usage'->>'input_tokens');cache_n:=awe_e1_runtime.cloud_uint(p->'usage'->>'cached_input_tokens');out_n:=awe_e1_runtime.cloud_uint(p->'usage'->>'output_tokens');
          SELECT x INTO s FROM jsonb_array_elements(c.route_snapshot->'sources') x WHERE x->>'source_id'=settlement_doc->>'source_id';
          reason:=NULL;
          IF s IS NULL THEN reason:='CLOUD_SOURCE_UNKNOWN';
          ELSE
            priced:=awe_e1_runtime.cloud_cost(s,in_n,cache_n,out_n,false);base_n:=awe_e1_runtime.cloud_cost(s,in_n,cache_n,out_n,false,false);
            IF settlement_doc->'source_coefficient' IS DISTINCT FROM s->'coefficient' OR settlement_doc->>'source_factor_digest' IS DISTINCT FROM s->>'price_evidence_digest' OR awe_e1_runtime.cloud_uint(settlement_doc->>'base_cost_micros')<>base_n THEN reason:='CLOUD_SOURCE_FACTOR_MISMATCH'; END IF;
            IF actual_n<>priced THEN reason:='CLOUD_ACTUAL_CHARGE_PRICE_MISMATCH'; END IF;
          END IF;
          IF in_n>awe_e1_runtime.cloud_uint(c.quote->>'input_tokens_bound') OR cache_n>in_n OR out_n>awe_e1_runtime.cloud_uint(c.quote->>'output_tokens_bound') THEN reason:='CLOUD_USAGE_EXCEEDS_QUOTE'; END IF;
          IF actual_n>c.reserved THEN reason:='CLOUD_CHARGE_EXCEEDS_RESERVATION'; END IF;
          IF reason IS NOT NULL THEN
            IF a.state NOT IN('SENDING','OUTCOME_UNKNOWN') THEN RAISE EXCEPTION 'A2_ATTEMPT_STATE'; END IF;
            result:=awe_e1_runtime.command('unknown',p||jsonb_build_object('reason',reason));
            IF result ? 'error' THEN RAISE EXCEPTION '%',result->>'error'; END IF;
            UPDATE awe_e1_runtime.cloud_attempt SET state='OUTCOME_UNKNOWN',provider_request_id=settlement_doc->>'provider_request_id',priced_usage_micros=priced,actual_charged_micros=actual_n,settlement=settlement_doc,hold_reason=reason WHERE attempt_id=c.attempt_id;
            UPDATE awe_e1_runtime.cloud_budget SET state='HOLD' WHERE key_binding_id=keyid;
            PERFORM awe_e1_runtime.emit(scope_project,t.mission_id,t.task_id,'CLOUD_CHARGE_HELD',jsonb_build_object('attempt_id',c.attempt_id,'reason',reason,'actual_charged_micros',actual_n,'reserved_micros',c.reserved));
            RETURN jsonb_build_object('status','OUTCOME_UNKNOWN','hold',true,'reason',reason,'reserved_micros',c.reserved,'actual_charged_micros',actual_n);
          END IF;
        END IF;
      ELSIF c.attempt_id IS NULL THEN RAISE EXCEPTION 'A2_CLOUD_ATTEMPT_SCOPE';
      END IF;
    ELSIF op='reserve' AND quote IS NOT NULL THEN RAISE EXCEPTION 'A2_CLOUD_ROUTE_SNAPSHOT';
    END IF;
  END IF;

  -- Old command and every cloud debit are inside this exception subtransaction.
  -- Its JSON error is re-raised before any cloud mutation can commit.
  result:=awe_e1_runtime.command(op,p);
  IF result ? 'error' THEN RAISE EXCEPTION '%',result->>'error'; END IF;
  IF op='admit' THEN
    FOR item IN SELECT * FROM jsonb_array_elements(p->'tasks') LOOP
      cp:=item->'cloud_policy';
      IF cp IS NOT NULL THEN INSERT INTO awe_e1_runtime.cloud_task_policy VALUES(p->'spec'->>'mission_id',item->'spec'->>'task_id',p->>'plan_digest',scope_project,cp->>'key_binding_id',awe_e1_runtime.cloud_digest(cp),cp) ON CONFLICT DO NOTHING; END IF;
    END LOOP;
  ELSIF route LIKE 'router.cheap.chat.%' AND op='reserve' AND c.attempt_id IS NULL THEN
    INSERT INTO awe_e1_runtime.cloud_attempt(attempt_id,key_binding_id,policy_digest,route_snapshot_digest,route_snapshot,quote,reserved,funded_reserved,state) VALUES(p->>'attempt_id',keyid,policyrow.policy_digest,r->>'snapshot_digest',r->'snapshot',quote,reserve_n,reserve_n,'RESERVED');
    UPDATE awe_e1_runtime.cloud_budget SET reserved=reserved+reserve_n,attempts_used=attempts_used+1 WHERE key_binding_id=keyid;
  ELSIF route LIKE 'router.cheap.chat.%' AND op='settle' AND a.state<>'CONFIRMED' THEN
    UPDATE awe_e1_runtime.cloud_budget SET reserved=reserved-c.funded_reserved,spent=spent+actual_n WHERE key_binding_id=keyid;
    UPDATE awe_e1_runtime.cloud_attempt SET state='CONFIRMED',funded_reserved=0,provider_request_id=settlement_doc->>'provider_request_id',priced_usage_micros=priced,actual_charged_micros=actual_n,settlement=settlement_doc,hold_reason=NULL WHERE attempt_id=c.attempt_id;
  END IF;
  PERFORM awe_e1_runtime.cloud_sync();
  IF op='snapshot' THEN
    result:=result||jsonb_build_object('cloud_policies',COALESCE((SELECT jsonb_agg(to_jsonb(x)) FROM awe_e1_runtime.cloud_task_policy x WHERE project_id=scope_project),'[]'::jsonb),'cloud_attempts',COALESCE((SELECT jsonb_agg(to_jsonb(ca)) FROM awe_e1_runtime.cloud_attempt ca JOIN awe_e1_runtime.model_attempt ma USING(attempt_id) WHERE ma.project_id=scope_project),'[]'::jsonb));
  END IF;
  RETURN result;
EXCEPTION WHEN OTHERS THEN RETURN jsonb_build_object('error',CASE WHEN SQLERRM ~ '^A2_[A-Z_]+$' THEN SQLERRM ELSE 'A2_CLOUD_DATABASE_REJECT' END);
END $$;

REVOKE ALL ON awe_e1_runtime.cloud_budget,awe_e1_runtime.cloud_task_policy,awe_e1_runtime.cloud_attempt FROM PUBLIC,awe_e1_coord,awe_e1_worker,awe_e1_qa;
REVOKE ALL ON FUNCTION awe_e1_runtime.cloud_canonical(jsonb,integer),awe_e1_runtime.cloud_digest(jsonb),awe_e1_runtime.cloud_uint(text),awe_e1_runtime.cloud_fraction(jsonb),awe_e1_runtime.cloud_cost(jsonb,bigint,bigint,bigint,boolean,boolean),awe_e1_runtime.cloud_assert_snapshot(jsonb,text,boolean),awe_e1_runtime.provision_cloud_budget(jsonb),awe_e1_runtime.cloud_sync(),awe_e1_runtime.cloud_command(text,jsonb) FROM PUBLIC,awe_e1_coord,awe_e1_worker,awe_e1_qa;
-- The frozen implementation remains callable only by its owning definer.
REVOKE EXECUTE ON FUNCTION awe_e1_runtime.command(text,jsonb) FROM awe_e1_coord,awe_e1_qa;
GRANT EXECUTE ON FUNCTION awe_e1_runtime.cloud_command(text,jsonb) TO awe_e1_coord,awe_e1_qa;
GRANT EXECUTE ON FUNCTION awe_e1_runtime.provision_cloud_budget(jsonb) TO awe_e1_coord;
INSERT INTO awe_e1_runtime.schema_migration VALUES(3,clock_timestamp()) ON CONFLICT DO NOTHING;
COMMIT;
