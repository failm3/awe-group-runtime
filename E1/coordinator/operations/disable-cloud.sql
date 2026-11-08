-- PREPARED ONLY. Not an automatic migration and not a destructive down migration.
-- Drain host funding-provision operations before executing this admin procedure.
-- Keep the 0003 psql-session cloud_command shim for local operation/reconciliation.
BEGIN;
DO $$
DECLARE identity jsonb;
BEGIN
  IF session_user<>'awe_e1_test' OR current_database()<>'awe_e1_test' OR current_setting('port')<>'5433' OR current_setting('data_directory')<>'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/pgdata' OR current_setting('unix_socket_directories')<>'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/socket' THEN RAISE EXCEPTION 'A2_CLOUD_DISABLE_RESOURCE_DENIED'; END IF;
  SELECT to_jsonb(i) INTO identity FROM awe_e1_resource.identity i WHERE resource_id='awe_e1_a2a3_20261108';
  IF identity IS DISTINCT FROM jsonb_build_object('resource_id','awe_e1_a2a3_20261108','database_name','awe_e1_test','port',5433,'scope','LOCAL_TEST_ONLY') OR NOT EXISTS(SELECT 1 FROM awe_e1_runtime.schema_migration WHERE version=3) THEN RAISE EXCEPTION 'A2_CLOUD_DISABLE_RESOURCE_DENIED'; END IF;
END $$;
LOCK TABLE awe_e1_runtime.cloud_budget IN SHARE ROW EXCLUSIVE MODE;
UPDATE awe_e1_runtime.cloud_budget SET state='HOLD' WHERE state<>'HOLD';
REVOKE EXECUTE ON FUNCTION awe_e1_runtime.provision_cloud_budget(jsonb) FROM PUBLIC,awe_e1_coord,awe_e1_worker,awe_e1_qa;
-- Keep only the wrapper entry point; never regrant the frozen bypass.
REVOKE EXECUTE ON FUNCTION awe_e1_runtime.command(text,jsonb) FROM PUBLIC,awe_e1_coord,awe_e1_worker,awe_e1_qa;
GRANT EXECUTE ON FUNCTION awe_e1_runtime.cloud_command(text,jsonb) TO awe_e1_coord,awe_e1_qa;
SELECT jsonb_build_object('status','CLOUD_DISABLED_RECONCILIATION_AVAILABLE','funded_keys_held',(SELECT count(*) FROM awe_e1_runtime.cloud_budget WHERE state='HOLD'),'retained_psql_shim','cloud_command','accounting_rows_deleted',0,'attempts_reset',false,'automatic_retry',false);
COMMIT;
