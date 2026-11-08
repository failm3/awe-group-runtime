-- CANDIDATE ONLY / REAL POSTGRESQL NOT_RUN. No runtime calls or enrollment.
-- Apply only after separately authorized disposable validation of SQL001-004.
-- D03 state remains one authoritative snapshot on the existing D09 project row.
BEGIN;
CREATE ROLE awe_d03_writer_master01 NOLOGIN NOSUPERUSER NOBYPASSRLS;
SET LOCAL ROLE awe_d09_owner;
ALTER TABLE awe_d09.projects
 ADD COLUMN d03_body_master01 text,
 ADD COLUMN d03_hash_master01 text,
 ADD COLUMN d03_commit_master01 bigint CHECK(d03_commit_master01>=0),
 ADD CONSTRAINT d03_snapshot_master01 CHECK (
  (d03_body_master01 IS NULL AND d03_hash_master01 IS NULL AND d03_commit_master01 IS NULL) OR
  (d03_body_master01 IS NOT NULL AND d03_hash_master01 ~ '^[a-f0-9]{64}$' AND d03_commit_master01 IS NOT NULL
   AND d03_hash_master01=encode(sha256(convert_to(d03_body_master01,'UTF8')),'hex')));
CREATE FUNCTION awe_d09.d03_read_master01(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE p awe_d09.projects; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id']);
 IF NOT pg_has_role(session_user,'awe_d03_writer_master01','MEMBER') THEN RAISE EXCEPTION 'D03_WRITER_ROLE'; END IF;
 p:=awe_d09.lock_project(j->>'project_id','READ');
 IF p.d03_body_master01 IS NULL THEN RAISE EXCEPTION 'D03_OWNER_ENROLLMENT_REQUIRED'; END IF;
 RETURN jsonb_build_object('body_text',p.d03_body_master01,'hash',p.d03_hash_master01,'commit',p.d03_commit_master01,'physical_decision','DENY');
END $$;
CREATE FUNCTION awe_d09.d03_commit_master01(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09 AS $$
DECLARE p awe_d09.projects; b jsonb; d jsonb; n bigint; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['project_id','expected_commit','expected_hash','body_text','hash']);
 IF NOT pg_has_role(session_user,'awe_d03_writer_master01','MEMBER') THEN RAISE EXCEPTION 'D03_WRITER_ROLE'; END IF;
 p:=awe_d09.lock_project(j->>'project_id','EXECUTE');
 IF p.halted OR p.restore_pending OR p.d03_body_master01 IS NULL THEN RAISE EXCEPTION 'D03_HOLD_OR_ENROLLMENT'; END IF;
 IF jsonb_typeof(j->'expected_commit') IS DISTINCT FROM 'number' OR j->>'expected_commit' !~ '^(0|[1-9][0-9]*)$'
  OR length(j->>'expected_commit')>16 OR (j->>'expected_commit')::numeric>9007199254740991
  OR p.d03_commit_master01 IS DISTINCT FROM (j->>'expected_commit')::bigint
  OR p.d03_hash_master01 IS DISTINCT FROM j->>'expected_hash' THEN RAISE EXCEPTION 'D03_CAS_CONFLICT'; END IF;
 IF jsonb_typeof(j->'body_text') IS DISTINCT FROM 'string' OR octet_length(j->>'body_text')>8388608
  OR jsonb_typeof(j->'hash') IS DISTINCT FROM 'string' OR j->>'hash' !~ '^[a-f0-9]{64}$'
  OR encode(sha256(convert_to(j->>'body_text','UTF8')),'hex') IS DISTINCT FROM j->>'hash' THEN RAISE EXCEPTION 'D03_BODY_HASH'; END IF;
 b:=(j->>'body_text')::jsonb;d:=b->'data';n:=p.d03_commit_master01+1;
 IF n>9007199254740991 OR b->>'snapshot_version' IS DISTINCT FROM '1' OR d->>'format' IS DISTINCT FROM 'awe-e0-state-v1'
  OR jsonb_typeof(d->'commit') IS DISTINCT FROM 'number' OR (d->>'commit')::numeric<>n
  OR jsonb_typeof(d->'projects') IS DISTINCT FROM 'object'
  OR EXISTS(SELECT 1 FROM jsonb_object_keys(d->'projects') k WHERE k<>j->>'project_id')
  THEN RAISE EXCEPTION 'D03_SCOPE_OR_REVISION'; END IF;
 UPDATE awe_d09.projects SET d03_body_master01=j->>'body_text',d03_hash_master01=j->>'hash',d03_commit_master01=n WHERE project_id=p.project_id;
 RETURN jsonb_build_object('body_text',j->>'body_text','hash',j->>'hash','commit',n,'physical_decision','DENY');
END $$;
REVOKE ALL ON FUNCTION awe_d09.d03_read_master01(jsonb),awe_d09.d03_commit_master01(jsonb) FROM PUBLIC;
GRANT USAGE ON SCHEMA awe_d09 TO awe_d03_writer_master01;
GRANT EXECUTE ON FUNCTION awe_d09.d03_read_master01(jsonb),awe_d09.d03_commit_master01(jsonb) TO awe_d03_writer_master01;
-- No membership, project state, user, grant, approval, budget or task is seeded.
COMMIT;
