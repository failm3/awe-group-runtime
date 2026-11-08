-- G1-02A SOURCE-ONLY CANDIDATE. UNAPPLIED. PostgreSQL18+ G1-02B approval required.
-- Variant A TCB: SEC bridge verifies Ed25519/PoP; per-subject session_user is
-- credentialed ONLY to that trusted bridge. SQL does NOT verify Ed25519 itself.
-- Enrollment is OFFLINE TEST ONLY, never real human/workload AuthN.
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
CREATE ROLE awe_sec_bridge_g102 NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE awe_sec_revoker_g102 NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
SET LOCAL ROLE awe_d09_owner;
-- Global native enrollment high-water marks on the EXISTING principal row.
-- Never compute them from tenant-filtered history (RLS can hide old projects).
-- This is DB-local monotonicity only, NOT the independent DEC09 restore witness.
ALTER TABLE awe_d09.principals
 ADD COLUMN native_process_generation_g102 bigint NOT NULL DEFAULT 0 CHECK(native_process_generation_g102>=0),
 ADD COLUMN native_principal_generation_g102 bigint NOT NULL DEFAULT 0 CHECK(native_principal_generation_g102>=0);

-- Dependent native credential extensions in the EXISTING D09 authority domain.
-- No automatic E0 enrollment, client setter, generic importer or AuthN-success bit.
CREATE TABLE awe_d09.native_issuers_g102 (
 project_id text NOT NULL REFERENCES awe_d09.projects,
 issuer_ref text NOT NULL, kid text NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 key_hash text NOT NULL CHECK(key_hash ~ '^sha256:[a-f0-9]{64}$'),
 not_before_ms bigint NOT NULL CHECK(not_before_ms>=0), expires_ms bigint NOT NULL,
 enrollment_evidence text NOT NULL CHECK(enrollment_evidence ~ '^sha256:[a-f0-9]{64}$'),
 revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(project_id,issuer_ref,kid,generation), CHECK(expires_ms>not_before_ms)
);
CREATE TABLE awe_d09.native_principals_g102 (
 project_id text NOT NULL, identity_hash text NOT NULL,
 login name NOT NULL REFERENCES awe_d09.principals(login), principal_id text NOT NULL,
 subject_id text NOT NULL, role text NOT NULL CHECK(role IN ('OWNER','SYSTEM','MAIN_AGENT','SUBAGENT','TOOL_EXECUTOR')),
 kind text NOT NULL CHECK((role='OWNER' AND kind='HUMAN') OR
 (role IN ('MAIN_AGENT','SUBAGENT') AND kind='AGENT') OR (role IN ('SYSTEM','TOOL_EXECUTOR') AND kind='SERVICE')),
 task_id text NOT NULL, run_id text NOT NULL, parent_run_id text,
 principal_generation bigint NOT NULL CHECK(principal_generation>0), process_generation bigint NOT NULL CHECK(process_generation>0),
 issuer_ref text NOT NULL, kid text NOT NULL, issuer_generation bigint NOT NULL,
 identity_token text NOT NULL CHECK(octet_length(identity_token)<=30000),
 proof_key_hash text NOT NULL CHECK(proof_key_hash ~ '^sha256:[a-f0-9]{64}$'),
 process_binding jsonb NOT NULL CHECK(jsonb_typeof(process_binding)='object'),
 not_before_ms bigint NOT NULL CHECK(not_before_ms>=0), expires_ms bigint NOT NULL,
 enrollment_evidence text NOT NULL CHECK(enrollment_evidence ~ '^sha256:[a-f0-9]{64}$'),
 enrollment_profile text NOT NULL CHECK(enrollment_profile='OFFLINE_TEMPORARY_TEST_SUBJECT'),
 revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(project_id,identity_hash),
 FOREIGN KEY(project_id,task_id) REFERENCES awe_d09.tasks,
 FOREIGN KEY(project_id,issuer_ref,kid,issuer_generation) REFERENCES awe_d09.native_issuers_g102,
 CHECK(identity_hash=awe_int03.hash(identity_token)), CHECK(expires_ms>not_before_ms),
 CHECK((role='SUBAGENT')=(parent_run_id IS NOT NULL)), CHECK(parent_run_id IS DISTINCT FROM run_id),
 CHECK(process_binding->>'generation'=process_generation::text)
);
CREATE UNIQUE INDEX native_login_live_g102 ON awe_d09.native_principals_g102(login) WHERE NOT revoked;
CREATE UNIQUE INDEX native_actor_live_g102 ON awe_d09.native_principals_g102(project_id,principal_id) WHERE NOT revoked;
CREATE UNIQUE INDEX native_subject_live_g102 ON awe_d09.native_principals_g102(project_id,subject_id) WHERE NOT revoked;
CREATE UNIQUE INDEX native_key_live_g102 ON awe_d09.native_principals_g102(project_id,proof_key_hash) WHERE NOT revoked;
CREATE UNIQUE INDEX native_channel_live_g102 ON awe_d09.native_principals_g102(project_id,(process_binding->>'channel_binding_hash')) WHERE NOT revoked;
CREATE UNIQUE INDEX native_process_live_g102 ON awe_d09.native_principals_g102(project_id,(process_binding->>'host_id'),(process_binding->>'boot_id'),(process_binding->>'pid'),(process_binding->>'start_ticks')) WHERE NOT revoked;
CREATE TABLE awe_d09.native_grants_g102 (
 project_id text NOT NULL, grant_id text NOT NULL, identity_hash text NOT NULL,
 parent_grant_id text, token text NOT NULL CHECK(octet_length(token)<=30000),
 token_hash text NOT NULL CHECK(token_hash=awe_int03.hash(token)), revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(project_id,grant_id),
 FOREIGN KEY(project_id,grant_id) REFERENCES awe_d09.grants,
 FOREIGN KEY(project_id,identity_hash) REFERENCES awe_d09.native_principals_g102,
 FOREIGN KEY(project_id,parent_grant_id) REFERENCES awe_d09.native_grants_g102 DEFERRABLE INITIALLY DEFERRED,
 CHECK(parent_grant_id IS DISTINCT FROM grant_id)
);
CREATE TABLE awe_d09.native_challenges_g102 (
 project_id text NOT NULL, challenge_id text NOT NULL CHECK(challenge_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
 identity_hash text NOT NULL, task_id text NOT NULL, run_id text NOT NULL,
 native_binding text NOT NULL CHECK(native_binding ~ '^sha256:[a-f0-9]{64}$'),
 request_text text NOT NULL CHECK(octet_length(request_text)<=65536),
 request_hash text NOT NULL CHECK(request_hash=awe_int03.hash(request_text)),
 nonce_hash text NOT NULL CHECK(nonce_hash ~ '^sha256:[a-f0-9]{64}$'),
 issued_ms bigint NOT NULL, expires_ms bigint NOT NULL CHECK(expires_ms>issued_ms AND expires_ms-issued_ms<=30000),
 consumed_proof_hash text CHECK(consumed_proof_hash ~ '^sha256:[a-f0-9]{64}$'), attempt_id text,
 PRIMARY KEY(project_id,challenge_id), UNIQUE(project_id,nonce_hash),
 FOREIGN KEY(project_id,identity_hash) REFERENCES awe_d09.native_principals_g102,
 FOREIGN KEY(project_id,task_id) REFERENCES awe_int03.runtime,
 FOREIGN KEY(project_id,attempt_id) REFERENCES awe_d09.native_bindings_cr01 DEFERRABLE INITIALLY DEFERRED,
 CHECK((consumed_proof_hash IS NULL)=(attempt_id IS NULL))
);
-- Append-only verification evidence subordinate to the SAME native attempt.
-- Deferred binding FK makes staging alone uncommittable, not a second permit store.
CREATE TABLE awe_d09.native_authority_tx_g102 (
 project_id text NOT NULL, transaction_id text NOT NULL CHECK(transaction_id ~ '^[1-9][0-9]*$'),
 login name NOT NULL REFERENCES awe_d09.principals, task_id text NOT NULL,
 challenge_id text NOT NULL, attempt_id text NOT NULL, command_hash text NOT NULL,
 payload jsonb NOT NULL, input_hash text NOT NULL,
 PRIMARY KEY(project_id,transaction_id,login), UNIQUE(project_id,challenge_id),
 FOREIGN KEY(project_id,challenge_id) REFERENCES awe_d09.native_challenges_g102,
 FOREIGN KEY(project_id,attempt_id) REFERENCES awe_d09.native_bindings_cr01 DEFERRABLE INITIALLY DEFERRED,
 CHECK(input_hash=awe_int03.hash(awe_int03.native_canonical_cr01(payload)))
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['native_issuers_g102','native_principals_g102','native_grants_g102','native_challenges_g102','native_authority_tx_g102'] LOOP
  EXECUTE format('ALTER TABLE awe_d09.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE awe_d09.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant_g102 ON awe_d09.%I USING(awe_d09.can_access(project_id)) WITH CHECK(awe_d09.can_access(project_id))',t);
  EXECUTE format('REVOKE ALL ON TABLE awe_d09.%I FROM PUBLIC',t);
 END LOOP;
END $$;

-- Canonical envelope parsing only. This is NOT SQL signature verification.
CREATE FUNCTION awe_int03.token_body_g102(token text) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,awe_int03 AS $$
DECLARE a text; s text; raw bytea; sig bytea; txt text; b jsonb; BEGIN
 IF token IS NULL OR octet_length(token)>30000 OR token !~ '^[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$' THEN RAISE EXCEPTION 'G102_TOKEN'; END IF;
 a:=split_part(token,'.',1);s:=split_part(token,'.',2);
 raw:=decode(translate(a,'-_','+/')||repeat('=',(4-length(a)%4)%4),'base64');
 sig:=decode(translate(s,'-_','+/')||repeat('=',(4-length(s)%4)%4),'base64');
 IF octet_length(sig)<>64 OR translate(rtrim(replace(encode(raw,'base64'),E'\n',''),'='),'+/','-_')<>a
  OR translate(rtrim(replace(encode(sig,'base64'),E'\n',''),'='),'+/','-_')<>s THEN RAISE EXCEPTION 'G102_ENCODING'; END IF;
 txt:=convert_from(raw,'UTF8');b:=txt::jsonb;
 IF awe_int03.native_canonical_cr01(b) IS DISTINCT FROM txt THEN RAISE EXCEPTION 'G102_CANONICAL'; END IF;
 RETURN b;
END $$;
CREATE FUNCTION awe_int03.native_session_g102(p text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09,awe_int03 AS $$
DECLARE r record; BEGIN
 SELECT * INTO r FROM pg_roles WHERE rolname=session_user;
 IF r.rolname IS NULL OR NOT r.rolcanlogin OR r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls
  OR NOT pg_has_role(session_user,'awe_sec_bridge_g102','MEMBER') OR NOT pg_has_role(session_user,'awe_int03_host','MEMBER')
  OR pg_has_role(session_user,'awe_d09_owner','MEMBER') OR pg_has_role(session_user,'awe_d09_issuer','MEMBER')
  OR pg_has_role(session_user,'awe_sec_revoker_g102','MEMBER') OR pg_has_role(session_user,'awe_int03_owner','MEMBER')
  OR pg_has_role(session_user,'awe_int03_verifier','MEMBER') OR pg_has_role(session_user,'awe_int03_evaluator','MEMBER')
 THEN RAISE EXCEPTION 'G102_SESSION_ROLE'; END IF;
 PERFORM awe_d09.lock_project(p,'EXECUTE');
 IF EXISTS(SELECT 1 FROM awe_d09.memberships m WHERE m.login=session_user AND (m.project_id<>p OR NOT m.permissions <@ ARRAY['READ','EXECUTE']))
  OR NOT EXISTS(SELECT 1 FROM awe_d09.memberships m WHERE m.login=session_user AND m.project_id=p AND ARRAY['READ','EXECUTE'] <@ m.permissions)
 THEN RAISE EXCEPTION 'G102_DEDICATED_PROJECT_LOGIN'; END IF;
END $$;
CREATE FUNCTION awe_int03.native_check_g102(e jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09,awe_int03 AS $$
DECLARE j jsonb; b jsonb; q jsonb; c jsonb; proof jsonb; g jsonb; previous jsonb;
 ident awe_d09.native_principals_g102; ancestor awe_d09.native_principals_g102;
 issuer awe_d09.native_issuers_g102; ng awe_d09.native_grants_g102; dg awe_d09.grants;
 ap awe_d09.approvals; principal awe_d09.principals; ch awe_d09.native_challenges_g102;
 r awe_int03.runtime; pin jsonb; tm bigint:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 tok text; hashes jsonb:='[]'; seen text[]:='{}'; idx integer:=0; f text; sb jsonb;
BEGIN
 PERFORM awe_d09.check_command(e,ARRAY['schema','profile','identity','grants','proof','request_text','observed_process','peer_profile','issuer_key_hash','command']);
 IF e->>'schema'<>'g102.sec.stage.v1' OR e->>'profile'<>'G102_TEMPORARY_TEST_KEYS_ONLY'
  OR e->>'peer_profile' NOT IN ('OS_OBSERVED_TEST_PROCESS','SYNTHETIC_UNIT_TEST_PEER') THEN RAISE EXCEPTION 'G102_TEST_PROFILE'; END IF;
 j:=e->'command';b:=awe_int03.native_validate_cr01(j);q:=(e->>'request_text')::jsonb;
 IF awe_int03.native_canonical_cr01(q) IS DISTINCT FROM e->>'request_text' THEN RAISE EXCEPTION 'G102_REQUEST_CANONICAL'; END IF;
 PERFORM awe_int03.native_session_g102(j->>'project_id');
 r:=awe_int03.lock_runtime(j,'awe_int03_host');pin:=awe_int03.native_task_pin_cr01(r.project_id,r.task_id);
 IF r.execution_profile<>'E0' OR r.state<>'CREATED' OR r.uncertain OR r.admission IS NOT NULL
  OR r.revision<>(j->>'expected_revision')::bigint OR pin IS DISTINCT FROM b->'state_pin'
  OR r.plan_hash IS DISTINCT FROM j->>'plan_hash' OR r.plan#>>'{native_cr01,body_text}' IS DISTINCT FROM j->>'body_text'
  OR r.plan#>>'{native_cr01,binding}' IS DISTINCT FROM j->>'binding' OR r.plan#>>'{native_cr01,command_text}' IS DISTINCT FROM j->>'command_text'
  OR r.plan#>>'{native_cr01,approval_ref}' IS DISTINCT FROM j->>'approval_ref'
  OR (b->>'expires_at')::bigint<=tm OR (b->>'expires_at')::bigint>(pin->>'lease_expires_at')::bigint
 THEN RAISE EXCEPTION 'G102_CURRENT_PIN'; END IF;
 c:=awe_int03.token_body_g102(e->>'identity');proof:=awe_int03.token_body_g102(e->>'proof');
 SELECT * INTO ident FROM awe_d09.native_principals_g102 WHERE project_id=r.project_id AND identity_hash=awe_int03.hash(e->>'identity') FOR UPDATE;
 SELECT * INTO principal FROM awe_d09.principals WHERE login=session_user;
 tm:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 PERFORM awe_int03.native_shape_cr01(c,jsonb_build_object(
  'v','@text','kind','@id','iss','@id','kid','@id','issuer_generation','@uint1','aud','@text','jti','@id','iat','@uint0','exp','@uint1','assurance','@text',
  'principal_id','@id','subject_id','@id','role','@id','principal_kind','@id','principal_generation','@uint1',
  'scope',jsonb_build_object('project_id','@id','task_id','@id','run_id','@id'),'parent_run_id',CASE WHEN c->>'parent_run_id' IS NULL THEN '@null' ELSE '@id' END,
  'proof_key','@text','proof_key_hash','@hash','login_ref','@id',
  'process_binding',jsonb_build_object('host_id','@id','boot_id','@id','pid','@uint1','start_ticks','@text','uid','@uint0','generation','@uint1','channel_binding_hash','@hash')));
 IF ident.login IS NULL OR ident.login<>session_user OR ident.revoked OR principal.revoked OR principal.valid_until<=clock_timestamp()
  OR ident.enrollment_profile<>'OFFLINE_TEMPORARY_TEST_SUBJECT' OR ident.identity_token IS DISTINCT FROM e->>'identity'
  OR ident.principal_id IS DISTINCT FROM principal.actor_id OR ident.issuer_ref IS DISTINCT FROM principal.issuer_ref
  OR ident.process_generation IS DISTINCT FROM principal.native_process_generation_g102
  OR ident.principal_generation IS DISTINCT FROM principal.native_principal_generation_g102
  OR c->>'v'<>'g101.authority.v1' OR c->>'kind'<>'IDENTITY' OR c->>'aud'<>'awe.sec.g101' OR c->>'assurance'<>'OFFLINE_TEMPORARY_TEST_SUBJECT'
  OR c->>'principal_id' IS DISTINCT FROM ident.principal_id OR c->>'subject_id' IS DISTINCT FROM ident.subject_id
  OR c->>'login_ref' IS DISTINCT FROM session_user::text OR c->>'role' IS DISTINCT FROM ident.role OR c->>'principal_kind' IS DISTINCT FROM ident.kind
  OR c->>'principal_generation' IS DISTINCT FROM ident.principal_generation::text OR c->>'proof_key_hash' IS DISTINCT FROM ident.proof_key_hash
  OR c->'process_binding' IS DISTINCT FROM ident.process_binding OR e->'observed_process' IS DISTINCT FROM ident.process_binding
  OR c#>>'{process_binding,generation}' IS DISTINCT FROM ident.process_generation::text
  OR c->'scope' IS DISTINCT FROM jsonb_build_object('project_id',r.project_id,'task_id',ident.task_id,'run_id',ident.run_id)
  OR c->>'parent_run_id' IS DISTINCT FROM ident.parent_run_id OR ident.task_id<>r.task_id OR ident.run_id IS DISTINCT FROM b#>>'{run,run_id}'
  OR ident.parent_run_id IS DISTINCT FROM b#>>'{run,parent_run_id}' OR ident.not_before_ms>tm OR ident.expires_ms<=tm
  OR c->>'iat' IS DISTINCT FROM ident.not_before_ms::text OR c->>'exp' IS DISTINCT FROM ident.expires_ms::text
 THEN RAISE EXCEPTION 'G102_CURRENT_IDENTITY'; END IF;
 IF NOT ((b->>'kind'='MODEL_REQUEST' AND ident.role IN ('MAIN_AGENT','SUBAGENT')) OR
         (b->>'kind'='TOOL_EXECUTION' AND ident.role='TOOL_EXECUTOR')) THEN RAISE EXCEPTION 'G102_OPERATION_ROLE'; END IF;
 SELECT * INTO issuer FROM awe_d09.native_issuers_g102 WHERE project_id=r.project_id AND issuer_ref=ident.issuer_ref AND kid=ident.kid AND generation=ident.issuer_generation FOR UPDATE;
 tm:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF issuer.issuer_ref IS NULL OR issuer.revoked OR issuer.not_before_ms>tm OR issuer.expires_ms<=tm
  OR issuer.key_hash IS DISTINCT FROM e->>'issuer_key_hash' OR c->>'iss' IS DISTINCT FROM issuer.issuer_ref
  OR c->>'kid' IS DISTINCT FROM issuer.kid OR c->>'issuer_generation' IS DISTINCT FROM issuer.generation::text THEN RAISE EXCEPTION 'G102_CURRENT_ISSUER'; END IF;
 -- Project row is the shared admission/revocation barrier. Sorted lineage locks.
 IF jsonb_typeof(e->'grants')<>'array' OR jsonb_array_length(e->'grants') NOT BETWEEN 1 AND 4 THEN RAISE EXCEPTION 'G102_LINEAGE'; END IF;
 PERFORM 1 FROM awe_d09.native_grants_g102 WHERE project_id=r.project_id
  AND grant_id IN (SELECT awe_int03.token_body_g102(value#>>'{}')->>'grant_id' FROM jsonb_array_elements(e->'grants')) ORDER BY grant_id FOR UPDATE;
 FOR tok IN SELECT value FROM jsonb_array_elements_text(e->'grants') LOOP
  g:=awe_int03.token_body_g102(tok);idx:=idx+1;
  SELECT * INTO ng FROM awe_d09.native_grants_g102 WHERE project_id=r.project_id AND grant_id=g->>'grant_id';
  SELECT * INTO dg FROM awe_d09.grants WHERE project_id=r.project_id AND grant_id=g->>'grant_id' FOR UPDATE;
  SELECT * INTO ap FROM awe_d09.approvals WHERE project_id=r.project_id AND approval_id=dg.approval_id FOR UPDATE;
  SELECT * INTO ancestor FROM awe_d09.native_principals_g102 WHERE project_id=r.project_id AND identity_hash=ng.identity_hash FOR UPDATE;
  tm:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  IF ng.grant_id IS NULL OR dg.grant_id IS NULL OR ap.approval_id IS NULL OR ancestor.login IS NULL OR ng.revoked OR dg.revoked OR ap.revoked OR ancestor.revoked
   OR ng.token IS DISTINCT FROM tok OR ng.token_hash IS DISTINCT FROM awe_int03.hash(tok) OR ng.parent_grant_id IS DISTINCT FROM g->>'parent_grant_id'
   OR g->>'grant_id'=ANY(seen) OR g->>'kind'<>'GRANT' OR g->>'v'<>'g101.authority.v1' OR g->>'aud'<>'awe.sec.g101' OR g->>'assurance'<>'OFFLINE_TEMPORARY_TEST_SUBJECT'
   OR g->>'iss' IS DISTINCT FROM issuer.issuer_ref OR g->>'kid' IS DISTINCT FROM issuer.kid OR g->>'issuer_generation' IS DISTINCT FROM issuer.generation::text
   OR (g->>'iat')::bigint>tm OR (g->>'exp')::bigint<=tm OR (g->>'exp')::bigint-(g->>'iat')::bigint NOT BETWEEN 1 AND 300000
   OR dg.expires_at<=clock_timestamp() OR ap.expires_at<=clock_timestamp() OR ancestor.expires_ms<=tm OR ancestor.not_before_ms>tm
   OR g->>'subject_id' IS DISTINCT FROM ancestor.principal_id OR dg.actor_id IS DISTINCT FROM ancestor.principal_id OR ap.actor_id IS DISTINCT FROM ancestor.principal_id
   OR g->>'identity_hash' IS DISTINCT FROM ancestor.identity_hash OR g->>'subject_role' IS DISTINCT FROM ancestor.role
   OR g->>'subject_generation' IS DISTINCT FROM ancestor.principal_generation::text OR g->>'process_generation' IS DISTINCT FROM ancestor.process_generation::text
   OR ancestor.issuer_ref IS DISTINCT FROM issuer.issuer_ref OR ancestor.kid IS DISTINCT FROM issuer.kid OR ancestor.issuer_generation IS DISTINCT FROM issuer.generation
   OR ancestor.task_id<>r.task_id OR ap.task_id<>r.task_id OR g->'scope' IS DISTINCT FROM jsonb_build_object('project_id',r.project_id,'task_id',r.task_id,'run_id',ancestor.run_id)
   OR g->>'parent_run_id' IS DISTINCT FROM ancestor.parent_run_id OR g->>'policy_hash' IS DISTINCT FROM b#>>'{authority,policy_hash}'
   OR (dg.auth_epoch,dg.policy_epoch,dg.owner_epoch,dg.stop_epoch) IS DISTINCT FROM ((pin#>>'{epochs,auth}')::bigint,(pin#>>'{epochs,policy}')::bigint,(pin#>>'{epochs,owner}')::bigint,(pin#>>'{epochs,stop}')::bigint)
   OR (dg.task_revision,dg.task_fence) IS DISTINCT FROM ((pin->>'task_revision')::bigint,(pin->>'task_fence')::bigint)
   OR NOT EXISTS(SELECT 1 FROM awe_d09.principals p JOIN awe_d09.memberships m USING(login) WHERE p.login=ancestor.login AND p.actor_id=ancestor.principal_id AND p.issuer_ref=issuer.issuer_ref AND p.native_process_generation_g102=ancestor.process_generation AND p.native_principal_generation_g102=ancestor.principal_generation AND NOT p.revoked AND p.valid_until>clock_timestamp() AND m.project_id=r.project_id AND 'EXECUTE'=ANY(m.permissions))
  THEN RAISE EXCEPTION 'G102_CURRENT_GRANT'; END IF;
  IF idx=1 THEN
   IF g->>'parent_grant_id' IS NOT NULL OR g->>'delegator_id' IS NOT NULL OR g->>'parent_run_id' IS NOT NULL OR g->>'subject_role'='SUBAGENT' THEN RAISE EXCEPTION 'G102_ROOT'; END IF;
  ELSE
   IF g->>'parent_grant_id' IS DISTINCT FROM previous->>'grant_id' OR g->>'delegator_id' IS DISTINCT FROM previous->>'subject_id'
    OR g->>'subject_id'=previous->>'subject_id' OR g->>'subject_role'<>'SUBAGENT' OR previous->>'subject_role' NOT IN ('MAIN_AGENT','SUBAGENT')
    OR NOT (previous->'actions' ? 'CHILD_CREATE') OR g->>'parent_run_id' IS DISTINCT FROM previous#>>'{scope,run_id}'
    OR g#>>'{scope,run_id}'=previous#>>'{scope,run_id}' OR (g->>'exp')::bigint>(previous->>'exp')::bigint OR (g->>'iat')::bigint<(previous->>'iat')::bigint
   THEN RAISE EXCEPTION 'G102_LINEAGE'; END IF;
   FOREACH f IN ARRAY ARRAY['actions','resources','capability_hashes'] LOOP IF NOT (g->f <@ previous->f) THEN RAISE EXCEPTION 'G102_ESCALATION'; END IF; END LOOP;
  END IF;
  hashes:=hashes||jsonb_build_array(awe_int03.hash(tok));seen:=array_append(seen,g->>'grant_id');previous:=g;
 END LOOP;
 IF g->>'identity_hash' IS DISTINCT FROM ident.identity_hash OR g->>'grant_id' IS DISTINCT FROM b#>>'{authority,grant_ref}'
  OR awe_int03.hash(awe_int03.native_canonical_cr01(hashes)) IS DISTINCT FROM b#>>'{authority,grant_lineage_digest}' THEN RAISE EXCEPTION 'G102_LEAF'; END IF;
 sb:=jsonb_build_object('principal_id',ident.principal_id,'subject_id',ident.subject_id,'role',ident.role,'principal_kind',ident.kind,'principal_generation',ident.principal_generation,'scope',c->'scope','proof_key_hash',ident.proof_key_hash,'login_ref',ident.login::text,'process_binding',ident.process_binding);
 IF awe_int03.hash(awe_int03.native_canonical_cr01(sb)) IS DISTINCT FROM b#>>'{authority,subject_binding_hash}' THEN RAISE EXCEPTION 'G102_SUBJECT_BINDING'; END IF;
 PERFORM awe_int03.native_shape_cr01(q,'{"v":"@text","principal_id":"@id","scope":{"project_id":"@id","task_id":"@id","run_id":"@id"},"expected_role":"@id","permission":{"action":"@id","resource":"@id","capability_hash":"@hash","policy_hash":"@hash"},"native_binding":"@hash","state_pin_hash":"@hash","expires_at":"@uint1","challenge_id":"@id"}'::jsonb);
 IF q->>'v'<>'g101.request.v1' OR q->>'principal_id' IS DISTINCT FROM ident.principal_id OR q->'scope' IS DISTINCT FROM c->'scope'
  OR q->>'expected_role' IS DISTINCT FROM ident.role OR q->>'native_binding' IS DISTINCT FROM j->>'binding'
  OR q->>'state_pin_hash' IS DISTINCT FROM awe_int03.hash(awe_int03.native_canonical_cr01(pin))
  OR (q->>'expires_at')::bigint<=tm OR (q->>'expires_at')::bigint>(b->>'expires_at')::bigint
  OR q#>>'{permission,action}' IS DISTINCT FROM b->>'kind' OR q#>>'{permission,policy_hash}' IS DISTINCT FROM g->>'policy_hash'
  OR NOT (g->'actions' ? (q#>>'{permission,action}')) OR NOT (g->'resources' ? (q#>>'{permission,resource}')) OR NOT (g->'capability_hashes' ? (q#>>'{permission,capability_hash}'))
 THEN RAISE EXCEPTION 'G102_REQUEST_BINDING'; END IF;
 SELECT * INTO ch FROM awe_d09.native_challenges_g102 WHERE project_id=r.project_id AND challenge_id=q->>'challenge_id' FOR UPDATE;
 tm:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF ch.challenge_id IS NULL OR ch.identity_hash IS DISTINCT FROM ident.identity_hash OR ch.task_id<>r.task_id OR ch.run_id<>ident.run_id
  OR ch.native_binding IS DISTINCT FROM j->>'binding' OR ch.request_text IS DISTINCT FROM e->>'request_text'
  OR ch.issued_ms>tm OR ch.expires_ms<=tm OR ch.consumed_proof_hash IS NOT NULL OR ch.attempt_id IS NOT NULL
 THEN RAISE EXCEPTION 'G102_REPLAY_OR_CHALLENGE'; END IF;
 PERFORM awe_int03.native_shape_cr01(proof,'{"v":"@text","kind":"@id","aud":"@text","jti":"@id","iat":"@uint0","exp":"@uint1","principal_id":"@id","identity_hash":"@hash","grant_chain_hash":"@hash","challenge_id":"@id","nonce_hash":"@hash","request_hash":"@hash","subject_binding_hash":"@hash"}'::jsonb);
 IF proof->>'v'<>'g101.proof.v1' OR proof->>'kind'<>'PROOF' OR proof->>'aud'<>'awe.sec.g101' OR proof->>'principal_id' IS DISTINCT FROM ident.principal_id
  OR proof->>'identity_hash' IS DISTINCT FROM ident.identity_hash OR proof->>'grant_chain_hash' IS DISTINCT FROM b#>>'{authority,grant_lineage_digest}'
  OR proof->>'challenge_id' IS DISTINCT FROM ch.challenge_id OR proof->>'nonce_hash' IS DISTINCT FROM ch.nonce_hash
  OR proof->>'request_hash' IS DISTINCT FROM ch.request_hash OR proof->>'subject_binding_hash' IS DISTINCT FROM b#>>'{authority,subject_binding_hash}'
  OR (proof->>'iat')::bigint>tm OR (proof->>'exp')::bigint<=tm OR (proof->>'exp')::bigint>ch.expires_ms
  OR (proof->>'exp')::bigint>(q->>'expires_at')::bigint OR (proof->>'exp')::bigint-(proof->>'iat')::bigint NOT BETWEEN 1 AND 300000
 THEN RAISE EXCEPTION 'G102_PROOF_BINDING'; END IF;
 -- Expiry must be rechecked after all possible lock waits, not at entry time.
 tm:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF ident.expires_ms<=tm OR issuer.expires_ms<=tm OR ch.expires_ms<=tm OR (proof->>'exp')::bigint<=tm
  OR (q->>'expires_at')::bigint<=tm OR (b->>'expires_at')::bigint<=tm OR (pin->>'lease_expires_at')::bigint<=tm
  OR EXISTS(SELECT 1 FROM awe_d09.native_grants_g102 x JOIN awe_d09.grants dg2 USING(project_id,grant_id)
   JOIN awe_d09.approvals ap2 ON ap2.project_id=dg2.project_id AND ap2.approval_id=dg2.approval_id
   JOIN awe_d09.native_principals_g102 np ON np.project_id=x.project_id AND np.identity_hash=x.identity_hash
   JOIN awe_d09.principals pp ON pp.login=np.login
   WHERE x.project_id=r.project_id AND x.grant_id=ANY(seen) AND (np.expires_ms<=tm OR pp.valid_until<=clock_timestamp()
    OR dg2.expires_at<=clock_timestamp() OR ap2.expires_at<=clock_timestamp() OR (awe_int03.token_body_g102(x.token)->>'exp')::bigint<=tm))
 THEN RAISE EXCEPTION 'G102_EXPIRED_AFTER_LOCK'; END IF;
 IF EXISTS(SELECT 1 FROM awe_d09.attempts x WHERE x.project_id=r.project_id AND
  (x.attempt_id=b#>>'{scope,attempt_id}' OR x.idempotency_key=b#>>'{scope,idempotency_key}' OR x.operation_id=b#>>'{scope,operation_id}')) THEN RAISE EXCEPTION 'G102_EXISTING_ATTEMPT'; END IF;
 RETURN jsonb_build_object('project_id',r.project_id,'task_id',r.task_id,'challenge_id',ch.challenge_id,'attempt_id',b#>>'{scope,attempt_id}','proof_hash',awe_int03.hash(e->>'proof'));
END $$;

CREATE FUNCTION awe_int03.stage_authority_g102(e jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09,awe_int03 AS $$
DECLARE checked jsonb; xid text:=pg_current_xact_id()::text; BEGIN
 checked:=awe_int03.native_check_g102(e);
 INSERT INTO awe_d09.native_authority_tx_g102(project_id,transaction_id,login,task_id,challenge_id,attempt_id,command_hash,payload,input_hash)
 VALUES(checked->>'project_id',xid,session_user,checked->>'task_id',checked->>'challenge_id',checked->>'attempt_id',
  awe_int03.hash(awe_int03.native_canonical_cr01(e->'command')),e,awe_int03.hash(awe_int03.native_canonical_cr01(e)));
 RETURN jsonb_build_object('schema','g102.stage.receipt.v1','status','STAGED_UNCOMMITTED','profile','G102_TEMPORARY_TEST_KEYS_ONLY',
  'input_hash',awe_int03.hash(awe_int03.native_canonical_cr01(e)),'project_id',checked->>'project_id','task_id',checked->>'task_id',
  'login',session_user,'challenge_id',checked->>'challenge_id','transaction_id',xid,'physical_decision','DENY','native_admission',false);
END $$;
-- SEC challenge control operation; no nonce consumption, task transition,
-- approval, attempt or reserve. UUID entropy comes from PostgreSQL core.
CREATE FUNCTION awe_int03.issue_challenge_g102(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09,awe_int03 AS $$
DECLARE cmd jsonb; b jsonb; q jsonb; np awe_d09.native_principals_g102; r awe_int03.runtime;
 tm bigint; expiry bigint; nonce text; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['command','identity_hash','request_text']);
 cmd:=j->'command';b:=awe_int03.native_validate_cr01(cmd);q:=(j->>'request_text')::jsonb;
 IF awe_int03.native_canonical_cr01(q) IS DISTINCT FROM j->>'request_text' THEN RAISE EXCEPTION 'G102_REQUEST_CANONICAL'; END IF;
 PERFORM awe_int03.native_session_g102(cmd->>'project_id');r:=awe_int03.lock_runtime(cmd,'awe_int03_host');
 SELECT * INTO np FROM awe_d09.native_principals_g102 WHERE project_id=r.project_id AND identity_hash=j->>'identity_hash' FOR UPDATE;
 tm:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF np.login IS NULL OR np.login<>session_user OR np.revoked OR np.expires_ms<=tm OR np.not_before_ms>tm
  OR np.task_id<>r.task_id OR np.run_id IS DISTINCT FROM b#>>'{run,run_id}'
  OR r.state<>'CREATED' OR r.execution_profile<>'E0' OR r.uncertain OR r.admission IS NOT NULL
  OR r.revision<>(cmd->>'expected_revision')::bigint OR b->'state_pin' IS DISTINCT FROM awe_int03.native_task_pin_cr01(r.project_id,r.task_id)
  OR r.plan_hash IS DISTINCT FROM cmd->>'plan_hash' OR r.plan#>>'{native_cr01,body_text}' IS DISTINCT FROM cmd->>'body_text'
  OR r.plan#>>'{native_cr01,binding}' IS DISTINCT FROM cmd->>'binding' OR r.plan#>>'{native_cr01,command_text}' IS DISTINCT FROM cmd->>'command_text'
  OR r.plan#>>'{native_cr01,approval_ref}' IS DISTINCT FROM cmd->>'approval_ref' THEN RAISE EXCEPTION 'G102_CHALLENGE_SCOPE'; END IF;
 PERFORM awe_int03.native_shape_cr01(q,'{"v":"@text","principal_id":"@id","scope":{"project_id":"@id","task_id":"@id","run_id":"@id"},"expected_role":"@id","permission":{"action":"@id","resource":"@id","capability_hash":"@hash","policy_hash":"@hash"},"native_binding":"@hash","state_pin_hash":"@hash","expires_at":"@uint1","challenge_id":"@id"}'::jsonb);
 IF q->>'v'<>'g101.request.v1' OR q->>'principal_id' IS DISTINCT FROM np.principal_id OR q->>'expected_role' IS DISTINCT FROM np.role
  OR q->'scope' IS DISTINCT FROM jsonb_build_object('project_id',r.project_id,'task_id',r.task_id,'run_id',np.run_id)
  OR q->>'native_binding' IS DISTINCT FROM cmd->>'binding' OR q->>'state_pin_hash' IS DISTINCT FROM awe_int03.hash(awe_int03.native_canonical_cr01(b->'state_pin'))
  OR q#>>'{permission,action}' IS DISTINCT FROM b->>'kind' OR q#>>'{permission,policy_hash}' IS DISTINCT FROM b#>>'{authority,policy_hash}'
 THEN RAISE EXCEPTION 'G102_CHALLENGE_REQUEST'; END IF;
 tm:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 expiry:=least((q->>'expires_at')::bigint,(b->>'expires_at')::bigint,np.expires_ms,tm+30000);
 IF expiry<=tm THEN RAISE EXCEPTION 'G102_CHALLENGE_EXPIRED'; END IF;
 nonce:=awe_int03.hash(gen_random_uuid()::text||gen_random_uuid()::text||gen_random_uuid()::text||gen_random_uuid()::text);
 INSERT INTO awe_d09.native_challenges_g102(project_id,challenge_id,identity_hash,task_id,run_id,native_binding,request_text,request_hash,nonce_hash,issued_ms,expires_ms)
 VALUES(r.project_id,q->>'challenge_id',np.identity_hash,r.task_id,np.run_id,cmd->>'binding',j->>'request_text',awe_int03.hash(j->>'request_text'),nonce,tm,expiry);
 RETURN jsonb_build_object('schema','g102.challenge.receipt.v1','profile','G102_TEMPORARY_TEST_KEYS_ONLY','status','ISSUED_NOT_AUTHORIZED',
  'project_id',r.project_id,'task_id',r.task_id,'challenge_id',q->>'challenge_id','identity_hash',np.identity_hash,
  'request_hash',awe_int03.hash(j->>'request_text'),'nonce_hash',nonce,'issued_ms',tm,'expires_ms',expiry,'physical_decision','DENY','native_admission',false);
END $$;
-- The SAME SQL002 coordinator invokes this hook, then its unchanged recovery,
-- policy and D07 hooks. Those still RAISE, so complete native admission stays shut.
CREATE OR REPLACE FUNCTION awe_int03.assert_native_authority_cr01(j jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09,awe_int03 AS $$
DECLARE a awe_d09.native_authority_tx_g102; checked jsonb; n integer; BEGIN
 PERFORM awe_int03.native_session_g102(j->>'project_id');
 SELECT * INTO a FROM awe_d09.native_authority_tx_g102 WHERE project_id=j->>'project_id'
  AND transaction_id=pg_current_xact_id()::text AND login=session_user FOR UPDATE;
 IF a.login IS NULL OR a.task_id IS DISTINCT FROM j->>'task_id' OR a.command_hash IS DISTINCT FROM awe_int03.hash(awe_int03.native_canonical_cr01(j))
  OR a.payload->'command' IS DISTINCT FROM j THEN RAISE EXCEPTION 'G102_NO_TRANSACTION_PROOF'; END IF;
 checked:=awe_int03.native_check_g102(a.payload);
 UPDATE awe_d09.native_challenges_g102 SET consumed_proof_hash=checked->>'proof_hash',attempt_id=checked->>'attempt_id'
 WHERE project_id=a.project_id AND challenge_id=a.challenge_id AND consumed_proof_hash IS NULL AND attempt_id IS NULL;
 GET DIAGNOSTICS n=ROW_COUNT;IF n<>1 THEN RAISE EXCEPTION 'G102_REPLAY'; END IF;
END $$;

-- Revocation uses the SAME existing project serialization barrier as admission.
-- No un-revoke, generation reset, grant issue, rearm or money transition API.
CREATE FUNCTION awe_int03.revoke_authority_g102(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09,awe_int03 AS $$
DECLARE n integer; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','kind','reference','reason_hash']);
 IF NOT pg_has_role(session_user,'awe_sec_revoker_g102','MEMBER') OR pg_has_role(session_user,'awe_sec_bridge_g102','MEMBER') THEN RAISE EXCEPTION 'G102_REVOKER_ROLE'; END IF;
 PERFORM awe_d09.lock_project(j->>'project_id','ISSUE');
 IF j->>'reason_hash' !~ '^sha256:[a-f0-9]{64}$' THEN RAISE EXCEPTION 'G102_REASON'; END IF;
 CASE j->>'kind'
 WHEN 'IDENTITY' THEN UPDATE awe_d09.native_principals_g102 SET revoked=true WHERE project_id=j->>'project_id' AND identity_hash=j->>'reference';
 WHEN 'GRANT' THEN UPDATE awe_d09.native_grants_g102 SET revoked=true WHERE project_id=j->>'project_id' AND grant_id=j->>'reference';
 WHEN 'ISSUER' THEN UPDATE awe_d09.native_issuers_g102 SET revoked=true WHERE project_id=j->>'project_id' AND key_hash=j->>'reference';
 ELSE RAISE EXCEPTION 'G102_REVOKE_KIND'; END CASE;
 GET DIAGNOSTICS n=ROW_COUNT;IF n<1 THEN RAISE EXCEPTION 'G102_REVOKE_MISSING'; END IF;
 -- Existing INT03 event journal, no independent authority event bus.
 INSERT INTO awe_int03.events(project_id,task_id,kind,body)
 SELECT project_id,task_id,'NATIVE_AUTHORITY_REVOKED_G102',jsonb_build_object('kind',j->>'kind','reference',j->>'reference','reason_hash',j->>'reason_hash','login',session_user)
 FROM awe_int03.runtime WHERE project_id=j->>'project_id';
 RETURN jsonb_build_object('status','REVOKED','physical_decision','DENY','native_admission',false);
END $$;

CREATE FUNCTION awe_d09.native_history_guard_g102() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,awe_d09 AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'G102_RETAIN_AUTHORITY_HISTORY'; END IF;
 IF TG_TABLE_NAME IN ('native_issuers_g102','native_principals_g102','native_grants_g102') THEN
  IF OLD.revoked AND NOT NEW.revoked OR (to_jsonb(OLD)-'revoked') IS DISTINCT FROM (to_jsonb(NEW)-'revoked') THEN RAISE EXCEPTION 'G102_IMMUTABLE_ENROLLMENT'; END IF;
 ELSIF TG_TABLE_NAME='native_challenges_g102' THEN
  IF OLD.consumed_proof_hash IS NOT NULL OR NEW.consumed_proof_hash IS NULL OR NEW.attempt_id IS NULL
   OR (to_jsonb(OLD)-ARRAY['consumed_proof_hash','attempt_id']) IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['consumed_proof_hash','attempt_id']) THEN RAISE EXCEPTION 'G102_IMMUTABLE_CHALLENGE'; END IF;
 ELSE RAISE EXCEPTION 'G102_IMMUTABLE_TX_EVIDENCE'; END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION awe_d09.native_generation_guard_g102() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE last_process bigint; last_principal bigint; BEGIN
 -- One dedicated login has one active project. Concurrent enrollment serializes
 -- on its EXISTING global principal row, then the existing project barrier.
 SELECT native_process_generation_g102,native_principal_generation_g102 INTO last_process,last_principal
  FROM awe_d09.principals WHERE login=NEW.login FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'G102_PRINCIPAL_MISSING'; END IF;
 PERFORM 1 FROM awe_d09.projects WHERE project_id=NEW.project_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'G102_PROJECT_MISSING'; END IF;
 IF NEW.process_generation<=last_process OR NEW.principal_generation<last_principal
 THEN RAISE EXCEPTION 'G102_GENERATION_ROLLBACK'; END IF;
 UPDATE awe_d09.principals SET native_process_generation_g102=NEW.process_generation,
  native_principal_generation_g102=NEW.principal_generation WHERE login=NEW.login;
 RETURN NEW;
END $$;
CREATE TRIGGER native_generation_g102 BEFORE INSERT ON awe_d09.native_principals_g102
 FOR EACH ROW EXECUTE FUNCTION awe_d09.native_generation_guard_g102();
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['native_issuers_g102','native_principals_g102','native_grants_g102','native_challenges_g102','native_authority_tx_g102'] LOOP
  EXECUTE format('CREATE TRIGGER native_history_g102 BEFORE UPDATE OR DELETE ON awe_d09.%I FOR EACH ROW EXECUTE FUNCTION awe_d09.native_history_guard_g102()',t);
 END LOOP;
END $$;
-- Empty enrollment by construction. Only separate reviewed bootstrap/importer
-- may insert test credential/challenge rows. No client DML grants are introduced.
REVOKE ALL ON FUNCTION awe_int03.token_body_g102(text),awe_int03.native_session_g102(text),awe_int03.native_check_g102(jsonb),
 awe_int03.stage_authority_g102(jsonb),awe_int03.issue_challenge_g102(jsonb),awe_int03.assert_native_authority_cr01(jsonb),awe_int03.revoke_authority_g102(jsonb),awe_d09.native_history_guard_g102(),awe_d09.native_generation_guard_g102() FROM PUBLIC;
GRANT USAGE ON SCHEMA awe_int03 TO awe_sec_bridge_g102,awe_sec_revoker_g102;
GRANT EXECUTE ON FUNCTION awe_int03.stage_authority_g102(jsonb) TO awe_sec_bridge_g102;
GRANT EXECUTE ON FUNCTION awe_int03.issue_challenge_g102(jsonb) TO awe_sec_bridge_g102;
GRANT EXECUTE ON FUNCTION awe_int03.revoke_authority_g102(jsonb) TO awe_sec_revoker_g102;
COMMIT;
