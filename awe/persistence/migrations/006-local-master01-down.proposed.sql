-- Empty-candidate rollback only. Never deletes local history or enrollment.
BEGIN;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM awe_d09.approvals WHERE local_plan_master01 IS NOT NULL)
  OR EXISTS(SELECT 1 FROM awe_d09.grants WHERE local_body_master01 IS NOT NULL)
  OR EXISTS(SELECT 1 FROM awe_d09.results WHERE local_output_master01 IS NOT NULL)
  OR EXISTS(SELECT 1 FROM awe_d09.projects WHERE local_policy_master01 IS NOT NULL)
  OR EXISTS(SELECT 1 FROM awe_d09.principals WHERE local_generation_master01 IS NOT NULL OR local_subject_master01 IS NOT NULL OR local_role_master01 IS NOT NULL)
  OR EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid IN ('awe_d09_local_master01'::regrole,'awe_d09_local_issuer_master01'::regrole))
 THEN RAISE EXCEPTION 'LOCAL_ROLLBACK_REQUIRES_PRESERVED_HISTORY_AND_OWNER_REVIEW'; END IF;
END $$;
DROP FUNCTION awe_d09.register_local_master01(jsonb),awe_d09.recover_local_master01(jsonb),awe_d09.admit_local_master01(jsonb),
 awe_d09.claim_local_master01(jsonb),awe_d09.sent_local_master01(jsonb),awe_d09.result_local_master01(jsonb),
 awe_d09.cancel_local_master01(jsonb),awe_d09.inspect_local_master01(jsonb),awe_d09.unknown_local_master01(jsonb),
 awe_d09.local_assert_master01(text,text),awe_d09.local_receipt_master01(text,text,text),
 awe_d09.local_state_master01(awe_d09.projects,jsonb),awe_d09.local_hash_master01(jsonb),awe_d09.local_role_master01(boolean);
ALTER TABLE awe_d09.results DROP COLUMN local_output_master01;
ALTER TABLE awe_d09.grants DROP COLUMN local_body_master01,DROP COLUMN local_token_hash_master01;
ALTER TABLE awe_d09.approvals DROP COLUMN local_plan_master01;
ALTER TABLE awe_d09.principals DROP COLUMN local_generation_master01,DROP COLUMN local_subject_master01,DROP COLUMN local_role_master01;
ALTER TABLE awe_d09.projects DROP COLUMN local_policy_master01;
REVOKE USAGE ON SCHEMA awe_d09 FROM awe_d09_local_master01,awe_d09_local_issuer_master01;
DROP ROLE awe_d09_local_master01,awe_d09_local_issuer_master01;
COMMIT;
