-- Narrow lock-order repair; no changes to applied 0001 through 0005.
BEGIN;
DO $$ DECLARE identity jsonb; BEGIN
 IF session_user<>'awe_e1_test' OR current_database()<>'awe_e1_test' OR current_setting('port')<>'5433' OR current_setting('data_directory')<>'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/pgdata' OR current_setting('unix_socket_directories')<>'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/socket' THEN RAISE EXCEPTION 'A2_MIGRATION_RESOURCE_DENIED'; END IF;
 SELECT to_jsonb(i) INTO identity FROM awe_e1_resource.identity i WHERE resource_id='awe_e1_a2a3_20261108';
 IF identity IS DISTINCT FROM jsonb_build_object('resource_id','awe_e1_a2a3_20261108','database_name','awe_e1_test','port',5433,'scope','LOCAL_TEST_ONLY') OR NOT EXISTS(SELECT 1 FROM awe_e1_runtime.schema_migration WHERE version=5) THEN RAISE EXCEPTION 'A2_MIGRATION_RESOURCE_DENIED'; END IF;
END $$;
CREATE OR REPLACE FUNCTION awe_e1_runtime.cloud4_amend_scope(p jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE a awe_e1_runtime.cloud4_authorization%ROWTYPE;r jsonb:=p->'receipt';d jsonb:=p->'receipt'->'document';projectid text;
BEGIN
 IF session_user NOT IN('awe_e1_coord','awe_e1_test') THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_HOST_REQUIRED'; END IF;
 -- Table lock is necessary when this key has NO budget row to lock. It orders
 -- amendment before/after v1 provision INSERT without acquiring other-key rows.
 LOCK TABLE awe_e1_runtime.cloud_budget IN SHARE ROW EXCLUSIVE MODE;
 IF EXISTS(SELECT 1 FROM awe_e1_runtime.cloud_budget WHERE key_binding_id=d->>'key_binding_id') THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AMEND_FUNDED_OR_ATTEMPTED'; END IF;
 SELECT * INTO a FROM awe_e1_runtime.cloud4_authorization WHERE key_binding_id=d->>'key_binding_id' FOR UPDATE;
 IF NOT FOUND OR a.state<>'PREPARED_PROVIDER_BLOCKED' THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AMEND_STATE'; END IF;
 IF EXISTS(SELECT 1 FROM awe_e1_runtime.cloud_budget WHERE key_binding_id=a.key_binding_id) OR EXISTS(SELECT 1 FROM awe_e1_runtime.cloud_attempt WHERE key_binding_id=a.key_binding_id) THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AMEND_FUNDED_OR_ATTEMPTED'; END IF;
 IF a.authorization_digest=r->>'document_digest' AND a.signed_receipt=r THEN RETURN jsonb_build_object('state',a.state,'authorization_digest',a.authorization_digest,'repeated',true); END IF;
 IF d->>'prior_authorization_digest' IS DISTINCT FROM a.authorization_digest THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AMEND_CAS'; END IF;
 IF r->>'schema' IS DISTINCT FROM 'awe.e1.cloud4.signed-receipt/1' OR r->>'algorithm' IS DISTINCT FROM 'Ed25519' OR NOT COALESCE(r->>'signature' ~ '^[A-Za-z0-9+/]{86}==$' ,false) OR r->>'public_key_digest' IS DISTINCT FROM a.signed_receipt->>'public_key_digest' OR r->>'public_key_digest' IS DISTINCT FROM p->>'trusted_public_key_digest' OR r->>'public_key_spki_der' IS DISTINCT FROM a.signed_receipt->>'public_key_spki_der' OR r->>'document_digest' IS DISTINCT FROM awe_e1_runtime.cloud_digest(d) THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_SIGNATURE_BINDING'; END IF;
 IF (d-ARRAY['project_ids','issued_at','expires_at','prior_authorization_digest','scope_revision']) IS DISTINCT FROM (a.document-ARRAY['project_ids','issued_at','expires_at','prior_authorization_digest','scope_revision']) OR awe_e1_runtime.cloud_uint(d->>'scope_revision')<>COALESCE((a.document->>'scope_revision')::bigint,1)+1 THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AMEND_IDENTITY_OR_LIMITS'; END IF;
 IF d->>'issued_at' IS NULL OR d->>'expires_at' IS NULL OR (d->>'issued_at')::timestamptz>clock_timestamp() OR (d->>'issued_at')::timestamptz<(a.document->>'issued_at')::timestamptz OR (d->>'expires_at')::timestamptz> (a.document->>'expires_at')::timestamptz OR (d->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AMEND_EXPIRY'; END IF;
 IF jsonb_typeof(d->'project_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(d->'project_ids') NOT BETWEEN 1 AND 32 OR jsonb_array_length(d->'project_ids')<=jsonb_array_length(a.document->'project_ids') OR (SELECT count(DISTINCT x) FROM jsonb_array_elements_text(d->'project_ids') x)<>jsonb_array_length(d->'project_ids') OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(a.document->'project_ids') x WHERE NOT(d->'project_ids' ? x)) THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_SCOPE_EXPANSION_ONLY'; END IF;
 FOR projectid IN SELECT * FROM jsonb_array_elements_text(d->'project_ids') LOOP
  IF projectid !~ '^[a-z][a-z0-9_.-]{0,79}$' OR (d->>'evidence_mode'='EXPLICIT_SYNTHETIC' AND projectid !~ '^prj_(cloud|qa3|qa4)_') OR EXISTS(SELECT 1 FROM awe_e1_runtime.project WHERE project_id=projectid AND owner_id<>d->>'owner_id') THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_AUTHORIZATION_SCOPE'; END IF;
 END LOOP;
 INSERT INTO awe_e1_runtime.cloud4_authorization_history(key_binding_id,authorization_digest,document,signed_receipt,state_at_archive,successor_authorization_digest) VALUES(a.key_binding_id,a.authorization_digest,a.document,a.signed_receipt,a.state,r->>'document_digest');
 UPDATE awe_e1_runtime.cloud4_authorization SET authorization_digest=r->>'document_digest',document=d,signed_receipt=r WHERE key_binding_id=a.key_binding_id;
 RETURN jsonb_build_object('state','PREPARED_PROVIDER_BLOCKED','owner_consent','ISSUED','authorization_digest',r->>'document_digest','prior_authorization_digest',a.authorization_digest,'scope_revision',d->'scope_revision','key_binding_id',a.key_binding_id,'counter_reset',false,'spending_enabled',false);
EXCEPTION WHEN OTHERS THEN RETURN jsonb_build_object('error',CASE WHEN SQLERRM ~ '^A2_[A-Z0-9_]+$' THEN SQLERRM ELSE 'A2_CLOUD_AUTHZ_AMEND_REJECT' END);
END $$;
INSERT INTO awe_e1_runtime.schema_migration VALUES(6,clock_timestamp()) ON CONFLICT DO NOTHING;
COMMIT;
