-- Resource-only reconciliation of a pinned LOCAL zero-cost NONE-effect attempt.
-- This does not resolve its outcome, usage, quota, money, mission or task HOLD.
BEGIN;
DO $$
DECLARE identity jsonb;
BEGIN
  IF session_user<>'awe_e1_test' OR current_database()<>'awe_e1_test' OR current_setting('port')<>'5433' OR current_setting('data_directory')<>'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/pgdata' OR current_setting('unix_socket_directories')<>'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/socket' THEN RAISE EXCEPTION 'A2_MIGRATION_RESOURCE_DENIED'; END IF;
  SELECT to_jsonb(i) INTO identity FROM awe_e1_resource.identity i WHERE resource_id='awe_e1_a2a3_20261108';
  IF identity IS DISTINCT FROM jsonb_build_object('resource_id','awe_e1_a2a3_20261108','database_name','awe_e1_test','port',5433,'scope','LOCAL_TEST_ONLY') THEN RAISE EXCEPTION 'A2_MIGRATION_RESOURCE_DENIED'; END IF;
END $$;
CREATE TABLE IF NOT EXISTS awe_e1_runtime.local_model_quiescence(
  attempt_id text PRIMARY KEY REFERENCES awe_e1_runtime.model_attempt,
  project_id text NOT NULL REFERENCES awe_e1_runtime.project,mission_id text NOT NULL,task_id text NOT NULL,
  original_fence bigint NOT NULL,new_fence bigint NOT NULL,proof_digest text NOT NULL,
  proof jsonb NOT NULL,accounting_before jsonb NOT NULL,at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY(mission_id,task_id) REFERENCES awe_e1_runtime.task);
REVOKE ALL ON awe_e1_runtime.local_model_quiescence FROM PUBLIC,awe_e1_coord,awe_e1_worker,awe_e1_qa;

-- The proof vocabulary contains only bounded ASCII strings/objects/arrays.
-- Under that restriction C key ordering equals A1 UTF-16 key ordering, and
-- PostgreSQL's JSON string encoding equals the A1 JSON.stringify representation.
CREATE OR REPLACE FUNCTION awe_e1_runtime.quiescence_canonical(v jsonb,depth integer DEFAULT 0) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE value text;
BEGIN
  IF depth>4 THEN RAISE EXCEPTION 'A2_QUIESCENCE_PROOF_SCHEMA'; END IF;
  CASE jsonb_typeof(v)
    WHEN 'object' THEN
      IF EXISTS(SELECT 1 FROM jsonb_object_keys(v) k WHERE k !~ '^[a-z_]{1,40}$') THEN RAISE EXCEPTION 'A2_QUIESCENCE_PROOF_SCHEMA'; END IF;
      SELECT '{'||COALESCE(string_agg(to_jsonb(key)::text||':'||awe_e1_runtime.quiescence_canonical(val,depth+1),',' ORDER BY key COLLATE "C"),'')||'}' INTO value FROM jsonb_each(v) e(key,val);
    WHEN 'array' THEN
      IF jsonb_array_length(v)>2 THEN RAISE EXCEPTION 'A2_QUIESCENCE_PROOF_SCHEMA'; END IF;
      SELECT '['||COALESCE(string_agg(awe_e1_runtime.quiescence_canonical(val,depth+1),',' ORDER BY n),'')||']' INTO value FROM jsonb_array_elements(v) WITH ORDINALITY e(val,n);
    WHEN 'string' THEN
      IF length(v#>>'{}')>512 OR (v#>>'{}') !~ '^[ -~]*$' THEN RAISE EXCEPTION 'A2_QUIESCENCE_PROOF_SCHEMA'; END IF;
      value:=v::text;
    ELSE RAISE EXCEPTION 'A2_QUIESCENCE_PROOF_SCHEMA';
  END CASE;
  RETURN value;
END $$;

CREATE OR REPLACE FUNCTION awe_e1_runtime.quiescence_ref(v jsonb,schema_name text,expected_status text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,awe_e1_runtime AS $$
BEGIN
  RETURN jsonb_typeof(v)='object' AND (SELECT count(*) FROM jsonb_object_keys(v))=5 AND v ?& ARRAY['schema','ref','digest','observed_at','status']
    AND v->>'schema'=schema_name AND v->>'status'=expected_status
    AND v->>'ref' ~ '^artifact:[a-z][a-z0-9._/-]{0,127}$' AND v->>'digest' ~ '^sha256:[a-f0-9]{64}$'
    AND v->>'observed_at' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$';
END $$;

CREATE OR REPLACE FUNCTION awe_e1_runtime.quiesce_local_model(p jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_e1_runtime AS $$
DECLARE
  proof jsonb:=p->'proof'; proofhash text:=p->>'proof_digest'; projectid text:=p->>'project_id';
  pp awe_e1_runtime.project%ROWTYPE;mm awe_e1_runtime.mission%ROWTYPE;tt awe_e1_runtime.task%ROWTYPE;
  aa awe_e1_runtime.model_attempt%ROWTYPE;ll awe_e1_runtime.lease%ROWTYPE;rr awe_e1_runtime.task_reservation%ROWTYPE;
  previous awe_e1_runtime.local_model_quiescence%ROWTYPE;canonical_proof text;newfence bigint;observed timestamptz;
  cancelled timestamptz;idle1 timestamptz;idle2 timestamptz;absent timestamptz;sent_at timestamptz;before jsonb;
BEGIN
  IF session_user NOT IN('awe_e1_coord','awe_e1_test') THEN RAISE EXCEPTION 'A2_QUIESCENCE_ROLE_DENIED'; END IF;
  IF current_database()<>'awe_e1_test' OR current_setting('port')<>'5433' OR current_setting('data_directory')<>'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/pgdata' OR current_setting('unix_socket_directories')<>'/var/lib/awe-e1-test/awe_e1_a2a3_20261108/socket' THEN RAISE EXCEPTION 'A2_QUIESCENCE_RESOURCE_DENIED'; END IF;
  IF jsonb_typeof(proof) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(proof))<>20 OR NOT(proof ?& ARRAY['schema','resource_id','project_id','mission_id','task_id','logical_request_id','attempt_id','worker_id','fence','route_id','model_id','model_digest','effect_class','attestor_id','observed_at','proof_ref','cancellation','idle_observations','runner_absence','statement']) THEN RAISE EXCEPTION 'A2_QUIESCENCE_PROOF_SCHEMA'; END IF;
  canonical_proof:=awe_e1_runtime.quiescence_canonical(proof);
  IF octet_length(canonical_proof)>8192 OR proofhash IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(canonical_proof,'UTF8')),'hex') THEN RAISE EXCEPTION 'A2_QUIESCENCE_PROOF_DIGEST'; END IF;
  IF proof->>'schema'<>'awe.e1.local-model-quiescence/1' OR proof->>'resource_id'<>'awe_e1_a2a3_20261108' OR proof->>'route_id'<>'ollama.local.qwen3-4b-instruct' OR proof->>'model_id'<>'qwen3:4b-instruct' OR proof->>'model_digest'<>'0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0' OR proof->>'attestor_id'<>'e1_local_operator' OR proof->>'statement'<>'PHYSICALLY_QUIESCENT_OUTCOME_STILL_UNKNOWN' OR proof->>'effect_class'<>'NONE' OR proof->>'proof_ref' !~ '^artifact:[a-z][a-z0-9._/-]{0,127}$' THEN RAISE EXCEPTION 'A2_QUIESCENCE_PROOF_PIN'; END IF;
  IF proof->>'project_id' IS DISTINCT FROM projectid OR proof->>'mission_id' IS DISTINCT FROM p->>'mission_id' OR proof->>'task_id' IS DISTINCT FROM p->>'task_id' OR proof->>'attempt_id' IS DISTINCT FROM p->>'attempt_id' OR proof->>'logical_request_id' IS DISTINCT FROM p->>'logical_request_id' OR proof->>'worker_id' IS DISTINCT FROM p->>'worker_id' OR proof->>'fence' IS DISTINCT FROM p->>'fence' OR proof->>'fence' !~ '^[1-9][0-9]{0,15}$' THEN RAISE EXCEPTION 'A2_QUIESCENCE_PROOF_SCOPE'; END IF;
  IF NOT awe_e1_runtime.quiescence_ref(proof->'cancellation','awe.e1.local-cancel-proof-ref/1','COMPLETED') OR jsonb_typeof(proof->'idle_observations') IS DISTINCT FROM 'array' OR jsonb_array_length(proof->'idle_observations')<>2 OR NOT awe_e1_runtime.quiescence_ref(proof->'idle_observations'->0,'awe.e1.local-idle-proof-ref/1','IDLE') OR NOT awe_e1_runtime.quiescence_ref(proof->'idle_observations'->1,'awe.e1.local-idle-proof-ref/1','IDLE') OR NOT awe_e1_runtime.quiescence_ref(proof->'runner_absence','awe.e1.local-runner-absence-proof-ref/1','ABSENT') THEN RAISE EXCEPTION 'A2_QUIESCENCE_EVIDENCE_REF'; END IF;
  IF (SELECT count(DISTINCT item->>'ref') FROM jsonb_array_elements(jsonb_build_array(proof->'cancellation',proof->'idle_observations'->0,proof->'idle_observations'->1,proof->'runner_absence')) item)<>4 OR (SELECT count(DISTINCT item->>'digest') FROM jsonb_array_elements(jsonb_build_array(proof->'cancellation',proof->'idle_observations'->0,proof->'idle_observations'->1,proof->'runner_absence')) item)<>4 THEN RAISE EXCEPTION 'A2_QUIESCENCE_EVIDENCE_REF'; END IF;
  IF proof->>'observed_at' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$' THEN RAISE EXCEPTION 'A2_QUIESCENCE_PROOF_TIME'; END IF;
  observed:=(proof->>'observed_at')::timestamptz;cancelled:=(proof->'cancellation'->>'observed_at')::timestamptz;idle1:=(proof->'idle_observations'->0->>'observed_at')::timestamptz;idle2:=(proof->'idle_observations'->1->>'observed_at')::timestamptz;absent:=(proof->'runner_absence'->>'observed_at')::timestamptz;
  IF cancelled>idle1 OR idle1+interval '1 second'>idle2 OR cancelled>absent OR GREATEST(idle2,absent)>observed THEN RAISE EXCEPTION 'A2_QUIESCENCE_PROOF_TIME'; END IF;
  SELECT * INTO pp FROM awe_e1_runtime.project WHERE project_id=projectid FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'A2_PROJECT_SCOPE'; END IF;
  SELECT * INTO mm FROM awe_e1_runtime.mission WHERE project_id=projectid AND mission_id=p->>'mission_id' FOR UPDATE;
  IF NOT FOUND OR mm.state<>'HOLD' THEN RAISE EXCEPTION 'A2_QUIESCENCE_NOT_HELD'; END IF;
  SELECT * INTO tt FROM awe_e1_runtime.task WHERE project_id=projectid AND mission_id=mm.mission_id AND task_id=p->>'task_id' FOR UPDATE;
  IF NOT FOUND OR tt.state<>'HOLD' OR NOT tt.is_current OR tt.plan_digest<>mm.plan_digest OR tt.executor_kind<>'llm' OR NOT(tt.model_routes ? 'ollama.local.qwen3-4b-instruct') OR tt.document->'effect'->>'effect_class' IS DISTINCT FROM 'NONE' THEN RAISE EXCEPTION 'A2_QUIESCENCE_TASK_SCOPE'; END IF;
  SELECT * INTO aa FROM awe_e1_runtime.model_attempt WHERE attempt_id=p->>'attempt_id' FOR UPDATE;
  IF NOT FOUND OR aa.project_id<>projectid OR aa.mission_id<>mm.mission_id OR aa.task_id<>tt.task_id OR aa.worker_id<>p->>'worker_id' OR aa.logical_request_id<>p->>'logical_request_id' OR aa.fence<>(p->>'fence')::bigint OR tt.producer_id<>aa.worker_id THEN RAISE EXCEPTION 'A2_ATTEMPT_SCOPE'; END IF;
  IF aa.state<>'OUTCOME_UNKNOWN' OR aa.route_id<>'ollama.local.qwen3-4b-instruct' OR aa.reserved<>0 OR aa.actual_cost IS NOT NULL OR pp.reserved<>0 OR mm.reserved<>0 THEN RAISE EXCEPTION 'A2_QUIESCENCE_ACCOUNTING_NOT_ELIGIBLE'; END IF;
  SELECT * INTO rr FROM awe_e1_runtime.task_reservation WHERE mission_id=mm.mission_id AND task_id=tt.task_id FOR UPDATE;
  IF NOT FOUND OR rr.amount<>0 OR rr.allocated<>0 THEN RAISE EXCEPTION 'A2_QUIESCENCE_ACCOUNTING_NOT_ELIGIBLE'; END IF;
  IF EXISTS(SELECT 1 FROM awe_e1_runtime.effect_intent WHERE mission_id=mm.mission_id AND task_id=tt.task_id) OR EXISTS(SELECT 1 FROM awe_e1_runtime.model_attempt a WHERE a.attempt_id<>aa.attempt_id AND ((a.mission_id=mm.mission_id AND a.task_id=tt.task_id AND a.state IN('RESERVED','SENDING','OUTCOME_UNKNOWN')) OR (a.fence=aa.fence AND (a.project_id<>projectid OR a.mission_id<>mm.mission_id OR a.task_id<>tt.task_id OR a.worker_id<>aa.worker_id)))) THEN RAISE EXCEPTION 'A2_QUIESCENCE_LINKAGE'; END IF;
  SELECT * INTO previous FROM awe_e1_runtime.local_model_quiescence WHERE attempt_id=aa.attempt_id;
  IF FOUND THEN
    IF previous.proof_digest<>proofhash OR previous.proof<>proof THEN RAISE EXCEPTION 'A2_QUIESCENCE_PROOF_CONFLICT'; END IF;
    IF tt.fence<>previous.new_fence OR EXISTS(SELECT 1 FROM awe_e1_runtime.lease WHERE mission_id=mm.mission_id AND task_id=tt.task_id) THEN RAISE EXCEPTION 'A2_QUIESCENCE_LINKAGE'; END IF;
    RETURN jsonb_build_object('status','QUIESCED_EXECUTION_ONLY','attempt_state','OUTCOME_UNKNOWN','mission_state','HOLD','task_state','HOLD','quota_released',false,'accounting_unchanged',true,'new_fence',previous.new_fence,'proof_digest',proofhash,'repeated',true);
  END IF;
  -- Idempotent same-proof readback above does not age out or advance the fence.
  IF observed<clock_timestamp()-interval '5 minutes' OR observed>clock_timestamp()+interval '10 seconds' OR LEAST(cancelled,idle1,idle2,absent)<clock_timestamp()-interval '5 minutes' THEN RAISE EXCEPTION 'A2_QUIESCENCE_PROOF_TIME'; END IF;
  SELECT max(at) INTO sent_at FROM awe_e1_runtime.event WHERE project_id=projectid AND mission_id=mm.mission_id AND task_id=tt.task_id AND kind='MODEL_SENDING' AND body->>'attempt_id'=aa.attempt_id;
  IF sent_at IS NULL OR cancelled<sent_at THEN RAISE EXCEPTION 'A2_QUIESCENCE_PROOF_TIME'; END IF;
  SELECT * INTO ll FROM awe_e1_runtime.lease WHERE project_id=projectid AND mission_id=mm.mission_id AND task_id=tt.task_id FOR UPDATE;
  IF NOT FOUND OR NOT ll.held OR ll.fence<>aa.fence OR tt.fence<>aa.fence OR ll.worker_id<>aa.worker_id THEN RAISE EXCEPTION 'A2_QUIESCENCE_LINKAGE'; END IF;
  IF EXISTS(SELECT 1 FROM awe_e1_runtime.lease_slot s WHERE s.mission_id=mm.mission_id AND s.task_id=tt.task_id AND (s.project_id<>projectid OR s.fence<>aa.fence)) THEN RAISE EXCEPTION 'A2_QUIESCENCE_LINKAGE'; END IF;
  before:=jsonb_build_object('project_spent',pp.spent,'project_reserved',pp.reserved,'project_quota_used',pp.quota_used,'mission_spent',mm.spent,'mission_reserved',mm.reserved,'attempt',to_jsonb(aa),'task_reservation',to_jsonb(rr),'claims',tt.claims);
  newfence:=nextval('awe_e1_runtime.fence_sequence');
  INSERT INTO awe_e1_runtime.local_model_quiescence(attempt_id,project_id,mission_id,task_id,original_fence,new_fence,proof_digest,proof,accounting_before) VALUES(aa.attempt_id,projectid,mm.mission_id,tt.task_id,aa.fence,newfence,proofhash,proof,before);
  UPDATE awe_e1_runtime.task SET fence=newfence WHERE mission_id=mm.mission_id AND task_id=tt.task_id;
  DELETE FROM awe_e1_runtime.lease WHERE mission_id=mm.mission_id AND task_id=tt.task_id AND fence=aa.fence;
  PERFORM awe_e1_runtime.emit(projectid,mm.mission_id,tt.task_id,'LOCAL_MODEL_EXECUTION_QUIESCED',jsonb_build_object('attempt_id',aa.attempt_id,'proof_digest',proofhash,'proof_ref',proof->>'proof_ref','outcome','OUTCOME_UNKNOWN','quota_released',false,'new_fence',newfence));
  RETURN jsonb_build_object('status','QUIESCED_EXECUTION_ONLY','attempt_state','OUTCOME_UNKNOWN','mission_state','HOLD','task_state','HOLD','quota_released',false,'accounting_unchanged',true,'new_fence',newfence,'proof_digest',proofhash,'repeated',false);
EXCEPTION WHEN OTHERS THEN RETURN jsonb_build_object('error',CASE WHEN SQLERRM ~ '^A2_[A-Z_]+$' THEN SQLERRM ELSE 'A2_QUIESCENCE_REJECT' END);
END $$;
REVOKE ALL ON FUNCTION awe_e1_runtime.quiescence_canonical(jsonb,integer),awe_e1_runtime.quiescence_ref(jsonb,text,text),awe_e1_runtime.quiesce_local_model(jsonb) FROM PUBLIC,awe_e1_coord,awe_e1_worker,awe_e1_qa;
GRANT EXECUTE ON FUNCTION awe_e1_runtime.quiesce_local_model(jsonb) TO awe_e1_coord;
INSERT INTO awe_e1_runtime.schema_migration VALUES(2,clock_timestamp()) ON CONFLICT DO NOTHING;
COMMIT;
