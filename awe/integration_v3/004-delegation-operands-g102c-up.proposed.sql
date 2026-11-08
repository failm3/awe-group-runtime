-- G1-02C SOURCE-ONLY CANDIDATE. UNAPPLIED; independent PG18.6 validation pending.
-- G102B-B01: only group JSONB extraction operands before containment.
-- Historical SQL003 SHA256: 788f68cd1d40040db743e7f2c8fdcb751ada3ec30b199dbb0273aade9c2dac3b
-- Apply only after exact SQL001/002/003 in a separately authorized disposable DB.
-- Same signature/owner/security/search_path; no DROP, ACL, data or admission changes.
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
SET LOCAL ROLE awe_d09_owner;
CREATE OR REPLACE FUNCTION awe_int03.native_check_g102(e jsonb) RETURNS jsonb
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
   FOREACH f IN ARRAY ARRAY['actions','resources','capability_hashes'] LOOP IF NOT ((g -> f) <@ (previous -> f)) THEN RAISE EXCEPTION 'G102_ESCALATION'; END IF; END LOOP;
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
COMMIT;
