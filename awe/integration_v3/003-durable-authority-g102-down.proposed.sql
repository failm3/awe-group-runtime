-- G1-02A SOURCE ONLY. UNAPPLIED. No CASCADE, row deletion or generation reset.
BEGIN ISOLATION LEVEL READ COMMITTED;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
SET LOCAL row_security=off;
DO $$ BEGIN
 IF current_user<>session_user OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=session_user AND rolsuper)
 THEN RAISE EXCEPTION 'G102_MAINTENANCE_ADMIN_REQUIRED'; END IF;
END $$;
-- Global maintenance barrier; row counts are not hidden by FORCE RLS.
LOCK TABLE awe_d09.principals,awe_d09.projects IN ACCESS EXCLUSIVE MODE;
LOCK TABLE awe_int03.runtime,awe_d09.native_bindings_cr01,awe_d09.native_issuers_g102,
 awe_d09.native_principals_g102,awe_d09.native_grants_g102,awe_d09.native_challenges_g102,
 awe_d09.native_authority_tx_g102 IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM awe_d09.native_issuers_g102) OR EXISTS(SELECT 1 FROM awe_d09.native_principals_g102)
  OR EXISTS(SELECT 1 FROM awe_d09.native_grants_g102) OR EXISTS(SELECT 1 FROM awe_d09.native_challenges_g102)
  OR EXISTS(SELECT 1 FROM awe_d09.native_authority_tx_g102) OR EXISTS(SELECT 1 FROM awe_d09.native_bindings_cr01)
  OR EXISTS(SELECT 1 FROM awe_d09.principals WHERE native_process_generation_g102<>0 OR native_principal_generation_g102<>0)
 THEN RAISE EXCEPTION 'G102_ROLLBACK_REQUIRES_RETAINED_HOLD_AND_REVIEW'; END IF;
 IF EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid OR r.oid=m.member
   WHERE r.rolname IN ('awe_sec_bridge_g102','awe_sec_revoker_g102'))
 THEN RAISE EXCEPTION 'G102_ROLLBACK_ROLE_MEMBERSHIPS_REQUIRE_REVIEW'; END IF;
END $$;
SET LOCAL ROLE awe_d09_owner;
REVOKE EXECUTE ON FUNCTION awe_int03.stage_authority_g102(jsonb) FROM awe_sec_bridge_g102;
REVOKE EXECUTE ON FUNCTION awe_int03.issue_challenge_g102(jsonb) FROM awe_sec_bridge_g102;
REVOKE EXECUTE ON FUNCTION awe_int03.revoke_authority_g102(jsonb) FROM awe_sec_revoker_g102;
-- Restore exact previous fail-closed authority behavior; never drop its guard.
CREATE OR REPLACE FUNCTION awe_int03.assert_native_authority_cr01(j jsonb) RETURNS void LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'NATIVE_AUTHORITY_NOT_CONFIGURED_DEC04'; END $$;
REVOKE ALL ON FUNCTION awe_int03.assert_native_authority_cr01(jsonb) FROM PUBLIC;
ALTER FUNCTION awe_int03.assert_native_authority_cr01(jsonb) SECURITY INVOKER;
ALTER FUNCTION awe_int03.assert_native_authority_cr01(jsonb) RESET ALL;
DROP FUNCTION awe_int03.stage_authority_g102(jsonb),awe_int03.issue_challenge_g102(jsonb),awe_int03.revoke_authority_g102(jsonb);
DROP FUNCTION awe_int03.native_check_g102(jsonb);
DROP FUNCTION awe_int03.native_session_g102(text),awe_int03.token_body_g102(text);
DROP TABLE awe_d09.native_authority_tx_g102;
DROP TABLE awe_d09.native_challenges_g102;
DROP TABLE awe_d09.native_grants_g102;
DROP TABLE awe_d09.native_principals_g102;
DROP TABLE awe_d09.native_issuers_g102;
DROP FUNCTION awe_d09.native_history_guard_g102(),awe_d09.native_generation_guard_g102();
ALTER TABLE awe_d09.principals DROP COLUMN native_process_generation_g102,DROP COLUMN native_principal_generation_g102;
REVOKE USAGE ON SCHEMA awe_int03 FROM awe_sec_bridge_g102,awe_sec_revoker_g102;
RESET ROLE;
-- Explicit drop fails on unknown external dependencies or memberships: no force.
DROP ROLE awe_sec_bridge_g102;
DROP ROLE awe_sec_revoker_g102;
COMMIT;
