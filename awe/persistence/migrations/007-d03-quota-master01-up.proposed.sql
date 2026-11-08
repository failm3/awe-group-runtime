-- Proposed additive read-only D09 capacity evidence. NOT executed offline.
-- Planning observation only: no budget allocation, attempt, launch or admission.
BEGIN;
SET LOCAL ROLE awe_d09_owner;
CREATE FUNCTION awe_d09.quota_local_master01(j jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_d09,awe_int03 AS $$
DECLARE pr awe_d09.projects; b jsonb:=j->'binding';dp jsonb;dt jsonb;ops jsonb;expected jsonb;caps jsonb;issued bigint;expires bigint;receipt jsonb; BEGIN
 PERFORM awe_d09.check_command(j,ARRAY['binding','expected_head']);
 IF NOT pg_has_role(session_user,'awe_d03_writer_master01','MEMBER') THEN RAISE EXCEPTION 'QUOTA_D03_ROLE'; END IF;
 pr:=awe_d09.lock_project(b#>>'{scope,project_id}','READ');
 IF pr.halted OR pr.restore_pending OR pr.d03_body_master01 IS NULL
  OR encode(sha256(convert_to(pr.d03_body_master01,'UTF8')),'hex') IS DISTINCT FROM pr.d03_hash_master01
  OR j->'expected_head' IS DISTINCT FROM jsonb_build_object('commit',pr.d03_commit_master01,'hash',pr.d03_hash_master01)
  THEN RAISE EXCEPTION 'QUOTA_DURABLE_HEAD'; END IF;
 dp:=pr.d03_body_master01::jsonb#>ARRAY['data','projects',pr.project_id];dt:=dp#>ARRAY['tasks',b#>>'{scope,task_id}'];
 IF dt IS NULL OR dp->>'status' IS DISTINCT FROM 'READY' OR dt->>'state' IS DISTINCT FROM 'READY'
  OR dt->'restore_pending' IS DISTINCT FROM 'false'::jsonb OR dt->'cancel_requested' IS DISTINCT FROM 'false'::jsonb
  OR dt->'acceptance_stale' IS DISTINCT FROM 'false'::jsonb
  OR coalesce(dp#>>ARRAY['master01',substring(dt->>'id' from 6),'phase'],'UNKNOWN') NOT IN ('NEW','RESUMING')
  OR dp#>ARRAY['master01',substring(dt->>'id' from 6),'scope'] IS DISTINCT FROM b->'scope' OR dt#>>'{lease,expires_at}' IS NULL
  OR (dt#>>'{lease,expires_at}')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION 'QUOTA_TASK_NOT_READY'; END IF;
 -- json_each retains original snapshot order: matches D03 opsFor/Object.values.
 SELECT coalesce(jsonb_agg(e.value::jsonb ORDER BY e.ordinality),'[]'::jsonb) INTO ops
 FROM json_each(pr.d03_body_master01::json#>ARRAY['data','projects',pr.project_id,'operations']) WITH ORDINALITY e
 WHERE e.value#>>'{scope,task_id}'=dt->>'id';
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(ops) x WHERE x->>'status' IN ('INTENT','DISPATCHED','OUTCOME_UNKNOWN')) THEN RAISE EXCEPTION 'QUOTA_UNRESOLVED_EFFECT'; END IF;
 expected:=jsonb_build_object('mode','E0','scope',jsonb_build_object('project_id',pr.project_id,'task_id',dt->>'id','operation_id',dt->>'control_operation_id'),
  'spec',dt->'spec','epochs',dp->'epochs','revision',dt->'revision','fence',dt->'fence','config_revision',dp->'config_revision','operations_hash',awe_d09.local_hash_master01(ops));
 IF b IS DISTINCT FROM expected OR dp->'epochs' IS DISTINCT FROM jsonb_build_object('auth',pr.auth_epoch,'policy',pr.policy_epoch,'owner',pr.owner_epoch,'stop',pr.stop_epoch-1)
  OR pr.local_policy_master01->'active' IS DISTINCT FROM 'true'::jsonb
  OR pr.local_policy_master01->>'profile' IS DISTINCT FROM 'MASTER01_LITERAL_TEXT_ONLY'
  OR pr.local_policy_master01->>'cost_micros' IS DISTINCT FROM '0'
  OR pr.local_policy_master01->>'physical_decision' IS DISTINCT FROM 'DENY'
  OR pr.local_policy_master01->>'external_network' IS DISTINCT FROM '0' THEN RAISE EXCEPTION 'QUOTA_BINDING_OR_POLICY'; END IF;
 issued:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF coalesce((pr.local_policy_master01->>'expires_at')::bigint,0)<=issued THEN RAISE EXCEPTION 'QUOTA_POLICY_EXPIRED'; END IF;
 expires:=least(issued+2000,floor(extract(epoch FROM (dt#>>'{lease,expires_at}')::timestamptz)*1000)::bigint,(pr.local_policy_master01->>'expires_at')::bigint);
 SELECT jsonb_agg(jsonb_build_object('budget_id',x.budget_id,'kind',x.kind,'currency',x.currency,'cap_micros',x.cap_micros::text,'balance_micros',x.balance_micros::text,'reserved_micros',x.reserved_micros::text,'spent_micros',x.spent_micros::text,'attempt_limit',x.attempt_limit,'attempts_used',x.attempts_used,'valid_until',floor(extract(epoch FROM x.valid_until)*1000)::bigint) ORDER BY x.budget_id),least(expires,min(floor(extract(epoch FROM x.valid_until)*1000)::bigint))
 INTO caps,expires FROM awe_d09.budgets x WHERE x.project_id=pr.project_id AND x.kind IN ('PROJECT','ORIGIN','DAY','MONTH','ACCOUNT') AND x.valid_until>clock_timestamp();
 IF expires IS NULL OR expires<=issued OR caps IS NULL
  OR (SELECT count(DISTINCT x->>'kind') FROM jsonb_array_elements(caps) x)<>5
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(caps) x WHERE x->>'currency'<>'RUB' OR (x->>'cap_micros')::numeric<>0 OR (x->>'balance_micros')::numeric<>0 OR (x->>'reserved_micros')::numeric<>0 OR (x->>'spent_micros')::numeric<>0 OR (x->>'attempts_used')::bigint>=(x->>'attempt_limit')::bigint)
  THEN RAISE EXCEPTION 'QUOTA_SHARED_CAP_DENIED'; END IF;
 receipt:=jsonb_build_object('schema','master01.d09.quota-evidence.v1','binding',b,'head',j->'expected_head','issued_at',issued,'expires_at',expires,'budgets',caps,'budget_hash',awe_d09.local_hash_master01(caps),'task_attempt_ceiling',1,'cost_micros','0','planning_only',true,'admission',false,'physical_decision','DENY');
 RETURN jsonb_build_object('body',receipt,'evidence_ref',awe_d09.local_hash_master01(receipt));
END $$;
REVOKE ALL ON FUNCTION awe_d09.quota_local_master01(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION awe_d09.quota_local_master01(jsonb) TO awe_d03_writer_master01;
COMMIT;
