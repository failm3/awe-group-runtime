-- Empty-candidate rollback only. No state snapshots or memberships are removed.
BEGIN;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM awe_d09.projects WHERE d03_body_master01 IS NOT NULL)
  OR EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid='awe_d03_writer_master01'::regrole)
 THEN RAISE EXCEPTION 'D03_ROLLBACK_REQUIRES_PRESERVED_STATE_AND_OWNER_REVIEW'; END IF;
END $$;
DROP FUNCTION awe_d09.d03_read_master01(jsonb),awe_d09.d03_commit_master01(jsonb);
ALTER TABLE awe_d09.projects DROP CONSTRAINT d03_snapshot_master01,
 DROP COLUMN d03_body_master01,DROP COLUMN d03_hash_master01,DROP COLUMN d03_commit_master01;
REVOKE USAGE ON SCHEMA awe_d09 FROM awe_d03_writer_master01;
DROP ROLE awe_d03_writer_master01;
COMMIT;
