-- CR-01 PROPOSED / UNAPPLIED. PostgreSQL18+ disposable test DB ONLY after approval.
-- No native AuthN/permit/counter/recovery decision is enabled by this patch.
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
SET LOCAL ROLE awe_d09_owner;
ALTER TABLE awe_int03.runtime ADD COLUMN execution_profile text NOT NULL DEFAULT 'E0'
 CHECK(execution_profile IN ('E0','SEC02_NATIVE_BINDING_ONLY_CR01'));
-- Extensions of the EXISTING authoritative task, not a second task registry.
-- No writer/provisioning API is added; NULL is unconfigured, never inferred from a request.
ALTER TABLE awe_d09.tasks ADD COLUMN native_spec jsonb,
 ADD COLUMN native_config_revision bigint CHECK(native_config_revision>0),
 ADD COLUMN native_lease_epoch bigint CHECK(native_lease_epoch>0),
 ADD CONSTRAINT native_pin_all_or_none_cr01 CHECK(
 (native_spec IS NULL AND native_config_revision IS NULL AND native_lease_epoch IS NULL) OR
 (native_spec IS NOT NULL AND native_config_revision IS NOT NULL AND native_lease_epoch IS NOT NULL));
CREATE TABLE awe_d09.native_bindings_cr01 (
 project_id text NOT NULL, attempt_id text NOT NULL, task_id text NOT NULL,
 body_text text NOT NULL CHECK(octet_length(body_text)<=65536), binding text NOT NULL,
 command_text text NOT NULL CHECK(octet_length(command_text)<=65536), approval_ref text NOT NULL,
 plan_hash text NOT NULL, pre_revision bigint NOT NULL CHECK(pre_revision>0),
 admitted_revision bigint NOT NULL CHECK(admitted_revision=pre_revision+1),
 task_pin jsonb NOT NULL, owner_login name NOT NULL REFERENCES awe_d09.principals(login),
 run_id text NOT NULL, parent_run_id text, child_id text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(project_id,attempt_id),
 FOREIGN KEY(project_id,attempt_id) REFERENCES awe_d09.attempts,
 FOREIGN KEY(project_id,task_id) REFERENCES awe_int03.runtime,
 CHECK(binding='sha256:'||encode(sha256(convert_to(body_text,'UTF8')),'hex')), CHECK(plan_hash ~ '^sha256:[a-f0-9]{64}$'),
 CHECK((parent_run_id IS NULL)=(child_id IS NULL)), CHECK(parent_run_id IS DISTINCT FROM run_id)
);
CREATE INDEX native_run_lookup_cr01 ON awe_d09.native_bindings_cr01(project_id,run_id);
ALTER TABLE awe_d09.native_bindings_cr01 ENABLE ROW LEVEL SECURITY;
ALTER TABLE awe_d09.native_bindings_cr01 FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_cr01 ON awe_d09.native_bindings_cr01 USING(awe_d09.can_access(project_id)) WITH CHECK(awe_d09.can_access(project_id));
CREATE TRIGGER native_binding_immutable_cr01 BEFORE UPDATE OR DELETE ON awe_d09.native_bindings_cr01
 FOR EACH ROW EXECUTE FUNCTION awe_d09.immutable_history();

-- All contract keys are ASCII. Explicit C ordering matches JS UTF16 key order
-- on that restricted key alphabet. Never hash jsonb::text as canonical JS JSON.
CREATE FUNCTION awe_int03.native_canonical_cr01(v jsonb,d integer DEFAULT 0) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,awe_int03 AS $$
DECLARE k text; item jsonb; parts text[]:='{}'; n numeric; BEGIN
 IF d>32 OR v IS NULL THEN RAISE EXCEPTION 'NATIVE_CANONICAL_INVALID'; END IF;
 CASE jsonb_typeof(v)
 WHEN 'object' THEN
  FOR k,item IN SELECT key,value FROM jsonb_each(v) ORDER BY key COLLATE "C" LOOP
   IF k !~ '^[A-Za-z0-9_]+$' OR k IN ('__proto__','prototype','constructor') THEN RAISE EXCEPTION 'NATIVE_CANONICAL_KEY'; END IF;
   parts:=array_append(parts,to_jsonb(k)::text||':'||awe_int03.native_canonical_cr01(item,d+1));
  END LOOP; RETURN '{'||array_to_string(parts,',')||'}';
 WHEN 'array' THEN
  FOR item IN SELECT value FROM jsonb_array_elements(v) LOOP parts:=array_append(parts,awe_int03.native_canonical_cr01(item,d+1)); END LOOP;
  RETURN '['||array_to_string(parts,',')||']';
 WHEN 'number' THEN
  IF v::text !~ '^-?(0|[1-9][0-9]*)$' THEN RAISE EXCEPTION 'NATIVE_CANONICAL_NUMBER'; END IF;
  n:=v::text::numeric; IF abs(n)>9007199254740991 THEN RAISE EXCEPTION 'NATIVE_CANONICAL_NUMBER'; END IF; RETURN n::text;
 WHEN 'string' THEN RETURN to_jsonb(v#>>'{}')::text;
 WHEN 'boolean' THEN RETURN v::text;
 WHEN 'null' THEN RETURN 'null';
 ELSE RAISE EXCEPTION 'NATIVE_CANONICAL_INVALID'; END CASE;
END $$;
CREATE FUNCTION awe_int03.native_shape_cr01(v jsonb,s jsonb) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,awe_int03 AS $$
DECLARE k text; t text; p text; BEGIN
 IF jsonb_typeof(s)='object' THEN
  IF jsonb_typeof(v) IS DISTINCT FROM 'object' OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(v) key)
   IS DISTINCT FROM (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(s) key) THEN RAISE EXCEPTION 'NATIVE_FIELDS_INVALID'; END IF;
  FOR k IN SELECT jsonb_object_keys(s) LOOP PERFORM awe_int03.native_shape_cr01(v->k,s->k); END LOOP; RETURN;
 END IF;
 t:=s#>>'{}'; p:=v#>>'{}';
 IF t='@null' THEN IF v IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'NATIVE_TYPE_INVALID'; END IF; RETURN; END IF;
 IF t IN ('@uint0','@uint1') THEN
  IF jsonb_typeof(v) IS DISTINCT FROM 'number' OR p !~ '^(0|[1-9][0-9]*)$' OR p::numeric>9007199254740991
   OR (t='@uint1' AND p::numeric<1) THEN RAISE EXCEPTION 'NATIVE_INTEGER_INVALID'; END IF; RETURN;
 END IF;
 IF jsonb_typeof(v) IS DISTINCT FROM 'string' OR p IS NULL THEN RAISE EXCEPTION 'NATIVE_TYPE_INVALID'; END IF;
 IF t='@id' AND p ~ '^[A-Za-z0-9_.:-]{1,128}$' THEN RETURN;
 ELSIF t='@hash' AND p ~ '^sha256:[a-f0-9]{64}$' THEN RETURN;
 ELSIF t='@money' AND p ~ '^(0|[1-9][0-9]{0,29})$' THEN RETURN;
 ELSIF t='@text' AND octet_length(p) BETWEEN 1 AND 128 AND p !~ '[[:cntrl:]]' THEN RETURN;
 ELSIF t='@jsontext' AND octet_length(p) BETWEEN 1 AND 65536 THEN RETURN;
 ELSIF t='@path' AND length(p) BETWEEN 1 AND 200 AND cardinality(string_to_array(p,'/'))<=12 THEN
  FOREACH k IN ARRAY string_to_array(p,'/') LOOP
   IF k !~ '^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}$' OR k ~ '[.]$' OR k ~* '^(con|prn|aux|nul|com[0-9]|lpt[0-9])([.]|$)' THEN RAISE EXCEPTION 'NATIVE_PATH_INVALID'; END IF;
  END LOOP; RETURN;
 END IF;
 RAISE EXCEPTION 'NATIVE_TYPE_INVALID';
END $$;
CREATE FUNCTION awe_int03.native_validate_cr01(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE b jsonb; c jsonb; shape jsonb; ar jsonb; mo jsonb; rt jsonb; tl jsonb; k text; BEGIN
 PERFORM awe_int03.native_shape_cr01(j,'{"project_id":"@id","task_id":"@id","schema":"@text","body_text":"@jsontext","binding":"@hash","approval_ref":"@id","command_text":"@jsontext","expected_revision":"@uint1","plan_hash":"@hash"}'::jsonb);
 IF j->>'schema'<>'sec02.native.admit.cr01.v1' THEN RAISE EXCEPTION 'NATIVE_CONTRACT_VERSION'; END IF;
 b:=(j->>'body_text')::jsonb; c:=(j->>'command_text')::jsonb;
 IF awe_int03.native_canonical_cr01(b) IS DISTINCT FROM j->>'body_text' OR awe_int03.native_canonical_cr01(c) IS DISTINCT FROM j->>'command_text'
  OR awe_int03.hash(j->>'body_text') IS DISTINCT FROM j->>'binding' THEN RAISE EXCEPTION 'NATIVE_BINDING_INVALID'; END IF;
 ar:='{"project_id":"@id","task_id":"@id","artifact_id":"@id","version":"@uint1","path":"@path","bytes":"@uint0","file_hash":"@hash","provenance_hash":"@hash"}';
 mo:='{"model_id":"@id","model_revision":"@text","profile_hash":"@hash","route_id":"@id","route_hash":"@hash","price_hash":"@hash","policy_hash":"@hash","protocol":"@id","endpoint_ref":"@id","account_ref":"@id"}';
 rt:='{"build_hash":"@hash","image_hash":"@hash","config_hash":"@hash","sandbox_profile_hash":"@hash","toolset_hash":"@hash"}';
 tl:='{"tool_id":"@id","version":"@text","code_digest":"@hash","schema_hash":"@hash","manifest_hash":"@hash"}';
 shape:='{"schema":"@text","kind":"@id","command_id":"@id","scope":{"project_id":"@id","task_id":"@id","origin_id":"@id","operation_id":"@id","attempt_id":"@id","effect_slot":"@id","idempotency_key":"@id","logical_request_id":"@id","correlation_id":"@id"},"run":{"run_id":"@id","parent_run_id":"@null","child_id":"@null"},"state_pin":{"spec":{"spec_id":"@id","revision":"@uint1","content_hash":"@hash"},"epochs":{"auth":"@uint1","policy":"@uint1","owner":"@uint1","stop":"@uint0"},"task_revision":"@uint1","task_fence":"@uint1","lease_epoch":"@uint1","config_revision":"@uint1","lease_expires_at":"@uint1"},"data_pins":{"payload_ref":{},"payload_hash":"@hash","payload_serializer_hash":"@hash","context_ref":{},"context_hash":"@hash","context_protocol_hash":"@hash"},"execution_pins":{"runtime":"@null","tool":"@null","model":"@null"},"authority":{"grant_ref":"@id","grant_lineage_digest":"@hash","subject_binding_hash":"@hash","policy_hash":"@hash"},"budget":{"currency":"@id","reserve_micros":"@money","quote_hash":"@hash","max_attempts":"@uint1"},"expires_at":"@uint1"}';
 shape:=jsonb_set(jsonb_set(shape,'{data_pins,payload_ref}',ar),'{data_pins,context_ref}',ar);
 IF b#>'{run,parent_run_id}' IS DISTINCT FROM 'null'::jsonb THEN shape:=jsonb_set(jsonb_set(shape,'{run,parent_run_id}','"@id"'),'{run,child_id}','"@id"'); END IF;
 CASE b->>'kind'
 WHEN 'MODEL_REQUEST' THEN shape:=jsonb_set(shape,'{execution_pins,model}',mo);
 WHEN 'RUNTIME_CONTROL' THEN shape:=jsonb_set(jsonb_set(shape,'{execution_pins,model}',mo),'{execution_pins,runtime}',rt);
 WHEN 'TOOL_EXECUTION' THEN shape:=jsonb_set(jsonb_set(shape,'{execution_pins,tool}',tl),'{execution_pins,runtime}',rt);
 ELSE RAISE EXCEPTION 'NATIVE_KIND_INVALID'; END CASE;
 PERFORM awe_int03.native_shape_cr01(b,shape);
 PERFORM awe_d09.check_command(c,ARRAY['project_id','task_id','operation_id','attempt_id','effect_slot','approval_id','grant_id','idempotency_key','plan_hash','payload_hash','reserve_micros']);
 IF b->>'schema'<>'sec02.native.binding.cr01.v1' OR b#>>'{run,parent_run_id}'=b#>>'{run,run_id}'
  OR b#>>'{budget,currency}'<>'RUB' OR b#>>'{budget,max_attempts}'<>'1' THEN RAISE EXCEPTION 'NATIVE_CONTRACT_INVALID'; END IF;
 FOR k IN SELECT unnest(ARRAY['project_id','task_id','operation_id','attempt_id','effect_slot','idempotency_key']) LOOP
  IF c->>k IS DISTINCT FROM b#>>ARRAY['scope',k] THEN RAISE EXCEPTION 'NATIVE_LEGACY_BINDING'; END IF;
 END LOOP;
 IF c->>'project_id' IS DISTINCT FROM j->>'project_id' OR c->>'task_id' IS DISTINCT FROM j->>'task_id'
  OR c->>'approval_id' IS DISTINCT FROM j->>'approval_ref' OR c->>'grant_id' IS DISTINCT FROM b#>>'{authority,grant_ref}'
  OR c->>'plan_hash' IS DISTINCT FROM b#>>'{budget,quote_hash}' OR c->>'reserve_micros' IS DISTINCT FROM b#>>'{budget,reserve_micros}' THEN RAISE EXCEPTION 'NATIVE_LEGACY_BINDING'; END IF;
 FOR k IN SELECT unnest(ARRAY['payload_ref','context_ref']) LOOP
  IF b#>>ARRAY['data_pins',k,'project_id'] IS DISTINCT FROM j->>'project_id' OR b#>>ARRAY['data_pins',k,'task_id'] IS DISTINCT FROM j->>'task_id' THEN RAISE EXCEPTION 'NATIVE_ARTIFACT_SCOPE'; END IF;
 END LOOP;
 RETURN b;
END $$;

-- Deliberately unconfigured policy interfaces. No GRANT, setter, JSON READY,
-- synthetic principal or GUC can make these return. Implementations need new CRs.
CREATE FUNCTION awe_int03.assert_native_authority_cr01(j jsonb) RETURNS void LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NATIVE_AUTHORITY_NOT_CONFIGURED_DEC04'; END $$;
CREATE FUNCTION awe_int03.assert_native_policy_cr01(j jsonb) RETURNS void LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NATIVE_COUNTING_ZERO_COST_NOT_CONFIGURED_DEC03_DEC05'; END $$;
CREATE FUNCTION awe_int03.assert_native_recovery_cr01(j jsonb) RETURNS void LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NATIVE_RECOVERY_NOT_CONFIGURED_DEC09'; END $$;
CREATE FUNCTION awe_int03.assert_native_data_cr01(j jsonb) RETURNS void LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NATIVE_D07_READBACK_NOT_CONFIGURED'; END $$;

CREATE FUNCTION awe_int03.native_task_pin_cr01(p text,t text) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE pr awe_d09.projects; x awe_d09.tasks; BEGIN
 SELECT * INTO pr FROM awe_d09.projects WHERE project_id=p FOR UPDATE;
 SELECT * INTO x FROM awe_d09.tasks WHERE project_id=p AND task_id=t FOR UPDATE;
 IF x.task_id IS NULL OR x.native_spec IS NULL OR x.native_config_revision IS NULL OR x.native_lease_epoch IS NULL
  OR pr.halted OR pr.restore_pending OR x.cancelled OR x.lease_until<=clock_timestamp() OR x.lease_holder<>session_user THEN RAISE EXCEPTION 'NATIVE_TASK_PIN_UNAVAILABLE'; END IF;
 RETURN jsonb_build_object('spec',x.native_spec,'epochs',jsonb_build_object('auth',pr.auth_epoch,'policy',pr.policy_epoch,'owner',pr.owner_epoch,'stop',pr.stop_epoch),
  'task_revision',x.revision,'task_fence',x.fence,'lease_epoch',x.native_lease_epoch,'config_revision',x.native_config_revision,
  'lease_expires_at',floor(extract(epoch FROM x.lease_until)*1000)::bigint);
END $$;

-- Private legacy cores remain owned by the same owner. Rename carries ACLs:
-- explicitly revoke every non-owner grantee before exposing guarded wrappers.
CREATE FUNCTION awe_int03.assert_e0_cr01(j jsonb) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; BEGIN r:=awe_int03.lock_runtime(j);
 IF r.execution_profile<>'E0' OR r.plan ? 'native_cr01' THEN RAISE EXCEPTION 'NATIVE_LEGACY_API_DENIED'; END IF;
END $$;
CREATE FUNCTION awe_d09.assert_e0_cr01(j jsonb,permission text) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
BEGIN
 PERFORM awe_d09.lock_project(j->>'project_id',permission);
 IF EXISTS(SELECT 1 FROM awe_int03.runtime r WHERE r.project_id=j->>'project_id'
   AND (r.execution_profile<>'E0' OR r.plan ? 'native_cr01') AND
   (r.task_id=j->>'task_id' OR r.attempt_id=j->>'attempt_id' OR (NOT j ? 'task_id' AND NOT j ? 'attempt_id')))
  OR EXISTS(SELECT 1 FROM awe_d09.native_bindings_cr01 b WHERE b.project_id=j->>'project_id' AND b.attempt_id=j->>'attempt_id')
 THEN RAISE EXCEPTION 'NATIVE_LEGACY_API_DENIED'; END IF;
END $$;
DO $$ DECLARE ns text; fn text; core text; who record; grants name[]; role_name name; permission text; BEGIN
 FOR ns,fn,permission IN SELECT * FROM (VALUES
  ('awe_int03','admit','READ'),('awe_int03','begin_execution','READ'),('awe_int03','complete','READ'),('awe_int03','revise','READ'),
  ('awe_int03','issue','READ'),('awe_int03','start_qa','READ'),('awe_int03','read_evaluation','READ'),('awe_int03','finish_qa','READ'),('awe_int03','accept','READ'),
  ('awe_d09','admit','EXECUTE'),('awe_d09','claim_attempt','EXECUTE'),('awe_d09','mark_sent','EXECUTE'),('awe_d09','cancel_attempt','EXECUTE'),('awe_d09','record_result','EXECUTE'),
  ('awe_d09','reconcile_charge','RECONCILE'),('awe_d09','prove_not_sent','RECONCILE'),('awe_d09','recover_project','RECONCILE')) v(ns,fn,permission) LOOP
  core:=fn||'_e0_cr01'; grants:='{}';
  EXECUTE format('ALTER FUNCTION %I.%I(jsonb) RENAME TO %I',ns,fn,core);
  FOR who IN SELECT a.grantee,p.proowner FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace,
   LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname=ns AND p.proname=core LOOP
   IF who.grantee=0 THEN EXECUTE format('REVOKE ALL ON FUNCTION %I.%I(jsonb) FROM PUBLIC',ns,core);
   ELSIF who.grantee<>who.proowner THEN
    SELECT rolname INTO role_name FROM pg_roles WHERE oid=who.grantee;
    EXECUTE format('REVOKE ALL ON FUNCTION %I.%I(jsonb) FROM %I',ns,core,role_name);grants:=array_append(grants,role_name);
   END IF;
  END LOOP;
  EXECUTE format('CREATE FUNCTION %I.%I(j jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $body$ BEGIN PERFORM %I.assert_e0_cr01(j%s); RETURN %I.%I(j); END $body$',ns,fn,ns,CASE WHEN ns='awe_d09' THEN format(',%L',permission) ELSE '' END,ns,core);
  EXECUTE format('REVOKE ALL ON FUNCTION %I.%I(jsonb) FROM PUBLIC',ns,fn);
  FOREACH role_name IN ARRAY grants LOOP EXECUTE format('GRANT EXECUTE ON FUNCTION %I.%I(jsonb) TO %I',ns,fn,role_name);END LOOP;
 END LOOP;
END $$;

ALTER FUNCTION awe_int03.inspect(jsonb) RENAME TO inspect_e0_cr01;
DO $$ DECLARE who record; role_name name; BEGIN
 FOR who IN SELECT a.grantee,p.proowner FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace,
  LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname='awe_int03' AND p.proname='inspect_e0_cr01' LOOP
  IF who.grantee=0 THEN REVOKE ALL ON FUNCTION awe_int03.inspect_e0_cr01(jsonb) FROM PUBLIC;
  ELSIF who.grantee<>who.proowner THEN SELECT rolname INTO role_name FROM pg_roles WHERE oid=who.grantee;
   EXECUTE format('REVOKE ALL ON FUNCTION awe_int03.inspect_e0_cr01(jsonb) FROM %I',role_name); END IF;
 END LOOP;
END $$;
CREATE FUNCTION awe_int03.inspect(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; BEGIN r:=awe_int03.lock_runtime(j);
 IF r.execution_profile<>'E0' OR r.plan ? 'native_cr01' THEN
  RETURN jsonb_build_object('execution_profile','SEC02_NATIVE_BINDING_ONLY_CR01','state','OUTCOME_UNKNOWN','revision',r.revision,
   'qa','QA_INCONCLUSIVE','effective_qa','QA_INCONCLUSIVE','acceptance','REJECTED','accepted',false,'uncertain',true,
   'published',false,'physical_decision','DENY','authoritative_complete',false,'plan_hash',r.plan_hash);
 END IF; RETURN awe_int03.inspect_e0_cr01(j)||jsonb_build_object('execution_profile','E0');
END $$;
GRANT EXECUTE ON FUNCTION awe_int03.inspect(jsonb) TO awe_int03_host,awe_int03_verifier,awe_int03_owner,awe_d09_reader;

CREATE FUNCTION awe_int03.native_profile_guard_cr01() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  IF OLD.execution_profile<>'E0' THEN RAISE EXCEPTION 'NATIVE_PROFILE_IMMUTABLE'; END IF; RETURN OLD;
 END IF;
 IF OLD.execution_profile<>'E0' THEN
  -- Only a conservative existing coordinator HOLD transition may update native.
  IF NEW.execution_profile IS DISTINCT FROM OLD.execution_profile OR NEW.state<>'OUTCOME_UNKNOWN' OR NOT NEW.uncertain
   OR NEW.qa<>'QA_INCONCLUSIVE' OR NEW.acceptance<>'REJECTED' OR NEW.revision<>OLD.revision+1
   OR (to_jsonb(NEW)-ARRAY['state','uncertain','qa','acceptance','revision']) IS DISTINCT FROM
      (to_jsonb(OLD)-ARRAY['state','uncertain','qa','acceptance','revision']) THEN RAISE EXCEPTION 'NATIVE_LEGACY_MUTATION_DENIED'; END IF;
 ELSIF NEW.execution_profile<>'E0' THEN
  IF OLD.state<>'CREATED' OR OLD.uncertain OR NEW.state<>'ADMITTED' OR NEW.revision<>OLD.revision+1
   OR NEW.plan IS DISTINCT FROM OLD.plan OR NEW.plan_hash IS DISTINCT FROM OLD.plan_hash
   OR NOT EXISTS(SELECT 1 FROM awe_d09.native_bindings_cr01 b WHERE b.project_id=NEW.project_id AND b.task_id=NEW.task_id
     AND b.attempt_id=NEW.attempt_id AND b.pre_revision=OLD.revision AND b.admitted_revision=NEW.revision
     AND b.command_text::jsonb=NEW.admission AND b.body_text=OLD.plan#>>'{native_cr01,body_text}')
  THEN RAISE EXCEPTION 'NATIVE_PROFILE_TRANSITION_DENIED'; END IF;
 END IF; RETURN NEW;
END $$;
CREATE TRIGGER native_profile_guard_cr01 BEFORE UPDATE OR DELETE ON awe_int03.runtime FOR EACH ROW EXECUTE FUNCTION awe_int03.native_profile_guard_cr01();
CREATE FUNCTION awe_d09.native_attempt_guard_cr01() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,awe_d09 AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM awe_d09.native_bindings_cr01 b WHERE b.project_id=OLD.project_id AND b.attempt_id=OLD.attempt_id)
 THEN RAISE EXCEPTION 'NATIVE_ATTEMPT_BINDING_ONLY_CR01'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
END $$;
CREATE TRIGGER native_attempt_guard_cr01 BEFORE UPDATE OR DELETE ON awe_d09.attempts FOR EACH ROW EXECUTE FUNCTION awe_d09.native_attempt_guard_cr01();

CREATE FUNCTION awe_int03.native_receipt_cr01(r awe_int03.runtime,status text) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE b awe_d09.native_bindings_cr01; BEGIN
 SELECT * INTO b FROM awe_d09.native_bindings_cr01 WHERE project_id=r.project_id AND attempt_id=r.attempt_id;
 IF b.attempt_id IS NULL THEN RAISE EXCEPTION 'NATIVE_BINDING_MISSING'; END IF;
 RETURN jsonb_build_object('schema','sec02.native.receipt.cr01.v1','execution_profile',r.execution_profile,'project_id',r.project_id,'task_id',r.task_id,
  'status',status,'body_text',b.body_text,'binding',b.binding,'command_text',b.command_text,'approval_ref',b.approval_ref,'plan_hash',b.plan_hash,
  'pre_revision',b.pre_revision::text,'revision',r.revision::text,'task_pin',b.task_pin,'attempt',awe_d09.view_attempt(r.project_id,r.attempt_id),
  'recorded_in_transaction',true,'physical_decision','DENY','dispatch_authorized',false,'accepted',false,
  'qa',CASE WHEN status='HOLD' THEN 'QA_INCONCLUSIVE' ELSE 'QA_NOT_RUN' END);
END $$;
CREATE FUNCTION awe_int03.admit_native_cr01(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; b jsonb; c jsonb; pin jsonb; a jsonb; old awe_d09.native_bindings_cr01; BEGIN
 b:=awe_int03.native_validate_cr01(j);r:=awe_int03.lock_runtime(j,'awe_int03_host');c:=(j->>'command_text')::jsonb;
 -- Exact immutable approved plan comes from existing trusted runtime provisioning,
 -- never supplied/registered by this API. Native pin fields must already exist.
 IF r.plan_hash IS DISTINCT FROM j->>'plan_hash' OR r.plan#>>'{native_cr01,body_text}' IS DISTINCT FROM j->>'body_text'
  OR r.plan#>>'{native_cr01,binding}' IS DISTINCT FROM j->>'binding' OR r.plan#>>'{native_cr01,command_text}' IS DISTINCT FROM j->>'command_text'
  OR r.plan#>>'{native_cr01,approval_ref}' IS DISTINCT FROM j->>'approval_ref' THEN RAISE EXCEPTION 'NATIVE_APPROVED_PLAN_MISMATCH'; END IF;
 PERFORM awe_int03.assert_native_authority_cr01(j);
 PERFORM awe_int03.assert_native_recovery_cr01(j);
 PERFORM awe_int03.assert_native_policy_cr01(j);
 PERFORM awe_int03.assert_native_data_cr01(j);
 pin:=awe_int03.native_task_pin_cr01(r.project_id,r.task_id);
 IF pin IS DISTINCT FROM b->'state_pin' OR (b->>'expires_at')::numeric<=extract(epoch FROM clock_timestamp())*1000
  OR (b->>'expires_at')::numeric>(pin->>'lease_expires_at')::numeric
  OR b#>>'{scope,origin_id}' IS DISTINCT FROM (SELECT origin_id FROM awe_d09.tasks WHERE project_id=r.project_id AND task_id=r.task_id)
 THEN RAISE EXCEPTION 'NATIVE_TASK_PIN_STALE'; END IF;
 SELECT * INTO old FROM awe_d09.native_bindings_cr01 WHERE project_id=r.project_id AND attempt_id=c->>'attempt_id';
 IF old.attempt_id IS NOT NULL THEN
  IF old.body_text IS DISTINCT FROM j->>'body_text' OR old.command_text IS DISTINCT FROM j->>'command_text' OR old.owner_login<>session_user
   OR old.pre_revision<>(j->>'expected_revision')::bigint OR r.execution_profile<>'SEC02_NATIVE_BINDING_ONLY_CR01'
   OR r.uncertain OR r.state<>'ADMITTED' OR r.revision<>old.admitted_revision THEN RAISE EXCEPTION 'NATIVE_READBACK_CONFLICT_OR_HOLD'; END IF;
  PERFORM awe_d09.live_authority(r.project_id,c->>'grant_id',c->>'attempt_id');
  RETURN awe_int03.native_receipt_cr01(r,'READBACK');
 END IF;
 IF r.execution_profile<>'E0' OR r.state<>'CREATED' OR r.uncertain OR r.admission IS NOT NULL OR r.revision<>(j->>'expected_revision')::bigint
  OR c->>'plan_hash' IS DISTINCT FROM r.plan->>'d06_plan_hash' OR c->>'payload_hash' IS DISTINCT FROM r.plan->>'payload_hash'
  OR c->>'reserve_micros' IS DISTINCT FROM r.plan->>'reserve_micros' THEN RAISE EXCEPTION 'NATIVE_COORDINATOR_CONFLICT'; END IF;
 IF EXISTS(SELECT 1 FROM awe_int03.dependencies d WHERE d.project_id=r.project_id AND d.task_id=r.task_id
  AND NOT COALESCE((awe_int03.inspect(jsonb_build_object('project_id',d.project_id,'task_id',d.parent_id))->>'accepted')::boolean,false)) THEN RAISE EXCEPTION 'NATIVE_DEPENDENCY_NOT_ACCEPTED'; END IF;
 -- D09 legacy admission has an idempotent readback branch. A previous unbound
 -- E0 attempt must NEVER be retrofitted into a supposedly atomic native admit.
 IF EXISTS(SELECT 1 FROM awe_d09.attempts x WHERE x.project_id=r.project_id
  AND (x.attempt_id=c->>'attempt_id' OR x.idempotency_key=c->>'idempotency_key' OR x.operation_id=c->>'operation_id'))
 THEN RAISE EXCEPTION 'NATIVE_PREEXISTING_UNBOUND_ATTEMPT'; END IF;
 -- Sole existing D09 reserve/attempt/approval/allocation/outbox implementation.
 a:=awe_d09.admit_e0_cr01(c);
 IF a->>'status'<>'ADMITTED' OR a->>'delivery_fence'<>'0' OR a->>'accounting_status'<>'RESERVED' THEN RAISE EXCEPTION 'NATIVE_ATTEMPT_NOT_FRESH'; END IF;
 INSERT INTO awe_d09.native_bindings_cr01(project_id,attempt_id,task_id,body_text,binding,command_text,approval_ref,plan_hash,pre_revision,admitted_revision,task_pin,owner_login,run_id,parent_run_id,child_id)
 VALUES(r.project_id,c->>'attempt_id',r.task_id,j->>'body_text',j->>'binding',j->>'command_text',j->>'approval_ref',r.plan_hash,r.revision,r.revision+1,pin,session_user,b#>>'{run,run_id}',b#>>'{run,parent_run_id}',b#>>'{run,child_id}');
 UPDATE awe_int03.runtime SET execution_profile='SEC02_NATIVE_BINDING_ONLY_CR01',state='ADMITTED',revision=revision+1,
  attempt_id=c->>'attempt_id',admission=c,epochs=awe_int03.epochs(r.project_id) WHERE project_id=r.project_id AND task_id=r.task_id RETURNING * INTO r;
 PERFORM awe_int03.audit(r,'NATIVE_BINDING_ADMITTED_CR01',jsonb_build_object('binding',j->>'binding','dispatch_authorized',false));
 RETURN awe_int03.native_receipt_cr01(r,'ADMITTED');
END $$;
CREATE FUNCTION awe_int03.inspect_native_cr01(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
DECLARE r awe_int03.runtime; BEGIN PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id']);r:=awe_int03.lock_runtime(j,'awe_int03_host');
 -- Readback is always HOLD: not current AuthN, recovery witness, or a permit.
 RETURN awe_int03.native_receipt_cr01(r,'HOLD'); END $$;
CREATE FUNCTION awe_int03.hold_native_cr01(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_int03,awe_d09 AS $$
BEGIN PERFORM awe_d09.check_command(j,ARRAY['project_id','task_id']);
 RETURN awe_int03.flag_uncertain(j||jsonb_build_object('reason','NATIVE_CR01_HOLD')); END $$;
REVOKE ALL ON TABLE awe_d09.native_bindings_cr01 FROM PUBLIC;
REVOKE ALL ON FUNCTION awe_int03.native_canonical_cr01(jsonb,integer),awe_int03.native_shape_cr01(jsonb,jsonb),
 awe_int03.native_validate_cr01(jsonb),awe_int03.assert_native_authority_cr01(jsonb),awe_int03.assert_native_policy_cr01(jsonb),
 awe_int03.assert_native_recovery_cr01(jsonb),awe_int03.assert_native_data_cr01(jsonb),awe_int03.native_task_pin_cr01(text,text),awe_int03.assert_e0_cr01(jsonb),awe_d09.assert_e0_cr01(jsonb,text),
 awe_int03.native_profile_guard_cr01(),awe_d09.native_attempt_guard_cr01(),
 awe_int03.native_receipt_cr01(awe_int03.runtime,text),awe_int03.admit_native_cr01(jsonb),awe_int03.inspect_native_cr01(jsonb),awe_int03.hold_native_cr01(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION awe_int03.admit_native_cr01(jsonb),awe_int03.inspect_native_cr01(jsonb),awe_int03.hold_native_cr01(jsonb) TO awe_int03_host;
COMMIT;
