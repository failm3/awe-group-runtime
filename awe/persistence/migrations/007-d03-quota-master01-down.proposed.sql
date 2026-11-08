-- Removes only proposed read function. No state/evidence/enrollment is deleted.
BEGIN;
DROP FUNCTION awe_d09.quota_local_master01(jsonb);
COMMIT;
