-- PROPOSED / UNAPPLIED. Safe removal ONLY when no native-affiliated data exists.
-- Never delete bindings/attempts/liability or silently reclassify native as E0.
BEGIN ISOLATION LEVEL READ COMMITTED;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
-- Global maintenance check must NOT run under the tenant-filtered NOBYPASSRLS
-- owner. DDL can DROP a table even when FORCE RLS hides all its rows.
SET LOCAL row_security=off;
DO $$ BEGIN
 IF current_user<>session_user OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=session_user AND rolsuper)
 THEN RAISE EXCEPTION 'CR01_GLOBAL_MAINTENANCE_ADMIN_REQUIRED'; END IF;
END $$;
-- Maintenance barrier BEFORE the emptiness snapshot. Existing APIs lock/read
-- projects first; no concurrent admitted binding can slip between guard and DROP.
LOCK TABLE awe_d09.projects IN ACCESS EXCLUSIVE MODE;
LOCK TABLE awe_int03.runtime,awe_d09.tasks,awe_d09.native_bindings_cr01 IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM awe_d09.native_bindings_cr01)
  OR EXISTS(SELECT 1 FROM awe_int03.runtime WHERE execution_profile<>'E0' OR plan ? 'native_cr01')
  OR EXISTS(SELECT 1 FROM awe_d09.tasks WHERE native_spec IS NOT NULL OR native_config_revision IS NOT NULL OR native_lease_epoch IS NOT NULL)
 THEN RAISE EXCEPTION 'CR01_ROLLBACK_REQUIRES_RETAINED_HOLD_AND_REVIEW'; END IF;
END $$;
SET LOCAL ROLE awe_d09_owner;
REVOKE ALL ON FUNCTION awe_int03.admit_native_cr01(jsonb),awe_int03.inspect_native_cr01(jsonb),awe_int03.hold_native_cr01(jsonb) FROM awe_int03_host;
DROP FUNCTION awe_int03.admit_native_cr01(jsonb),awe_int03.inspect_native_cr01(jsonb),awe_int03.hold_native_cr01(jsonb);
DROP FUNCTION awe_int03.native_receipt_cr01(awe_int03.runtime,text);
DROP TRIGGER native_profile_guard_cr01 ON awe_int03.runtime;
DROP TRIGGER native_attempt_guard_cr01 ON awe_d09.attempts;
DROP FUNCTION awe_int03.native_profile_guard_cr01(),awe_d09.native_attempt_guard_cr01();
-- Restore the ACLs of each guarded wrapper to the original private core.
DO $$ DECLARE ns text; fn text; role_name name; who record; grantees name[]; BEGIN
 FOR ns,fn IN SELECT * FROM (VALUES
  ('awe_int03','admit'),('awe_int03','begin_execution'),('awe_int03','complete'),('awe_int03','revise'),('awe_int03','issue'),
  ('awe_int03','start_qa'),('awe_int03','read_evaluation'),('awe_int03','finish_qa'),('awe_int03','accept'),('awe_int03','inspect'),
  ('awe_d09','admit'),('awe_d09','claim_attempt'),('awe_d09','mark_sent'),('awe_d09','cancel_attempt'),('awe_d09','record_result'),
  ('awe_d09','reconcile_charge'),('awe_d09','prove_not_sent'),('awe_d09','recover_project')) v(ns,fn) LOOP
  grantees:='{}';
  FOR who IN SELECT a.grantee,p.proowner FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace,
   LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname=ns AND p.proname=fn LOOP
   IF who.grantee<>0 AND who.grantee<>who.proowner THEN SELECT rolname INTO role_name FROM pg_roles WHERE oid=who.grantee;grantees:=array_append(grantees,role_name); END IF;
  END LOOP;
  EXECUTE format('DROP FUNCTION %I.%I(jsonb)',ns,fn);
  EXECUTE format('ALTER FUNCTION %I.%I(jsonb) RENAME TO %I',ns,fn||'_e0_cr01',fn);
  FOREACH role_name IN ARRAY grantees LOOP EXECUTE format('GRANT EXECUTE ON FUNCTION %I.%I(jsonb) TO %I',ns,fn,role_name);END LOOP;
 END LOOP;
END $$;
DROP FUNCTION awe_int03.assert_e0_cr01(jsonb),awe_d09.assert_e0_cr01(jsonb,text);
DROP FUNCTION awe_int03.native_validate_cr01(jsonb),awe_int03.native_task_pin_cr01(text,text),
 awe_int03.assert_native_authority_cr01(jsonb),awe_int03.assert_native_policy_cr01(jsonb),awe_int03.assert_native_recovery_cr01(jsonb),awe_int03.assert_native_data_cr01(jsonb);
DROP FUNCTION awe_int03.native_shape_cr01(jsonb,jsonb),awe_int03.native_canonical_cr01(jsonb,integer);
DROP TABLE awe_d09.native_bindings_cr01;
ALTER TABLE awe_int03.runtime DROP COLUMN execution_profile;
ALTER TABLE awe_d09.tasks DROP CONSTRAINT native_pin_all_or_none_cr01,
 DROP COLUMN native_spec,DROP COLUMN native_config_revision,DROP COLUMN native_lease_epoch;
COMMIT;
