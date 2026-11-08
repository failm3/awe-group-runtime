-- AWE_E1 rollback strategy, NOT EXECUTED / PostgreSQL runtime BLOCKED.
-- Version 0001 is additive. Binary rollback leaves this namespace and all data
-- intact. Never restore an old outbox or downgrade D03/D09 to revert a binary.
BEGIN;
DO $guard$
BEGIN
  IF current_database() !~ '^awe_e1_[a-z0-9_]+$'
     OR current_setting('awe.composition', true) IS DISTINCT FROM 'AWE_E1'
     OR current_setting('awe.migration_authorized', true) IS DISTINCT FROM 'E1_ONLY'
  THEN RAISE EXCEPTION 'C1_E1_DATABASE_SCOPE_REQUIRED'; END IF;
END;
$guard$;
-- Deliberately no DROP/TRUNCATE/DELETE/restore operation. A future separately
-- authorized adapter may mark one exact installation ROLLED_BACK after drain,
-- signature/protocol checks and independent readback of the prior binary.
COMMIT;
