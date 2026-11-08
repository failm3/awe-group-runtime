-- PREPARED_NOT_RUN. Disables scope-amend authority without changing history/money.
BEGIN;
DO $$ DECLARE identity jsonb; BEGIN
 IF session_user<>'awe_e1_test' OR current_database()<>'awe_e1_test' OR current_setting('port')<>'5433' OR current_setting('data_directory')<>'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/pgdata' OR current_setting('unix_socket_directories')<>'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/socket' THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_DISABLE_RESOURCE_DENIED'; END IF;
 SELECT to_jsonb(i) INTO identity FROM awe_e1_resource.identity i WHERE resource_id='awe_e1_a2a3_20261108';
 IF identity IS DISTINCT FROM jsonb_build_object('resource_id','awe_e1_a2a3_20261108','database_name','awe_e1_test','port',5433,'scope','LOCAL_TEST_ONLY') OR NOT EXISTS(SELECT 1 FROM awe_e1_runtime.schema_migration WHERE version=5) THEN RAISE EXCEPTION 'A2_CLOUD_AUTHZ_DISABLE_RESOURCE_DENIED'; END IF;
END $$;
REVOKE EXECUTE ON FUNCTION awe_e1_runtime.cloud4_amend_scope(jsonb) FROM PUBLIC,awe_e1_coord,awe_e1_worker,awe_e1_qa;
SELECT jsonb_build_object('state','CLOUD_SCOPE_AMENDMENT_DISABLED','history_deleted',false,'funding_or_attempts_reset',false,'legacy_bypass_regranted',false);
COMMIT;
