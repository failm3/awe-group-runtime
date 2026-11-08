import {readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {createCluster,json,quote} from './local-postgres.mjs';
import {createIntegratedHost} from '../../awe/integration_v3/postgres.mjs';
import {digest,copy} from '../../awe/qa/common.mjs';
import {prepareSyntheticJob} from './synthetic-job.mjs';
export {json,quote};
let cluster,counter=0,legacy=false;
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export function start({legacyMigration}={}) {
  legacy=legacyMigration!==undefined;
  if(legacy && sha(legacyMigration)!=='8e67be66148b5d8545bffe94b05d1f0f46a2f454b766d64146483322ea1b3f17')throw Error('LEGACY_REPRODUCTION_HASH_MISMATCH');
  cluster=createCluster();
  cluster.sql(legacyMigration??readFileSync(new URL('../../awe/integration_v3/001-up.sql',import.meta.url),'utf8'));
  cluster.sql(`GRANT awe_int03_host,awe_d09_reconciler TO d09_worker;
    GRANT awe_int03_verifier,awe_d09_reader TO d09_qa_login;
    GRANT awe_int03_owner,awe_d09_reader TO d09_owner_login;`);
  if(!legacy)cluster.sql('GRANT awe_int03_evaluator TO d09_evaluator_login');
  const settings={};for(const key of ['server_version','server_version_num','data_directory','port','listen_addresses','fsync','synchronous_commit','full_page_writes'])settings[key]=cluster.sql('SHOW '+key);
  if(Number(settings.server_version_num)<180000 || settings.port!=='55493' || !settings.data_directory.startsWith('/tmp/awe-int03-'))throw Error('INT03_CLUSTER_IDENTITY_DENIED');
  writeFileSync(join(cluster.run,'server-settings.json'),JSON.stringify(settings,null,2)+'\n');
  return cluster;
}
export function stop(){cluster?.close();}
export async function fixture() {
  const name='int03_case'+(++counter);cluster.createDatabase(name);
  const sql=(text,login='awe_d09_bootstrap')=>cluster.sql(text,{db:name,login});
  const job=await prepareSyntheticJob();
  const plan=job.plan,scope={project_id:'prj_alpha',task_id:'task_one'};
  const follow={...copy(plan),task_id:'task_followup',requirements:{...copy(plan.requirements),task_id:'task_followup'}};
  sql(`INSERT INTO awe_d09.projects(project_id) VALUES('prj_alpha'),('prj_beta');
    INSERT INTO awe_d09.memberships VALUES
    ('prj_alpha','d09_worker',ARRAY['READ','EXECUTE','RECONCILE']),('prj_alpha','d09_other',ARRAY['READ','EXECUTE']),
    ('prj_alpha','d09_reconciler_login',ARRAY['READ','RECONCILE']),('prj_alpha','d09_issuer_login',ARRAY['READ','ISSUE']),
    ('prj_alpha','d09_reader_login',ARRAY['READ']),('prj_alpha','d09_qa_login',ARRAY['READ']),('prj_alpha','d09_owner_login',ARRAY['READ']),
    ('prj_alpha','d09_evaluator_login',ARRAY['READ']);
    INSERT INTO awe_d09.origins VALUES('prj_alpha','origin1',false),('prj_beta','origin1',false);
    INSERT INTO awe_d09.tasks VALUES('prj_alpha','task_one','origin1',1,1,'d09_worker',clock_timestamp()+interval '1 hour',false),
      ('prj_alpha','task_followup','origin1',1,1,'d09_worker',clock_timestamp()+interval '1 hour',false),
      ('prj_beta','task_one','origin1',1,1,'d09_other',clock_timestamp()+interval '1 hour',false);
    INSERT INTO awe_d09.budgets(project_id,budget_id,kind,currency,cap_micros,balance_micros,attempt_limit,valid_until)
      SELECT 'prj_alpha',lower(k),k,'RUB',100000,100000,10,clock_timestamp()+interval '1 hour'
      FROM unnest(ARRAY['PROJECT','TASK','ORIGIN','DAY','MONTH','ACCOUNT','ANCESTOR']) k;
    INSERT INTO awe_d09.task_budgets SELECT project_id,t,budget_id FROM awe_d09.budgets CROSS JOIN unnest(ARRAY['task_one','task_followup']) t;
    INSERT INTO awe_d09.approvals VALUES('prj_alpha','ap1','task_one','d09_worker','o1','s1',${quote(plan.payload_hash)},${quote(plan.d06_plan_hash)},100000,clock_timestamp()+interval '1 hour',false,NULL),
      ('prj_alpha','ap2','task_followup','d09_worker','o2','s2',${quote(plan.payload_hash)},${quote(plan.d06_plan_hash)},100000,clock_timestamp()+interval '1 hour',false,NULL);
    INSERT INTO awe_d09.grants VALUES('prj_alpha','g1','ap1','d09_worker',1,1,1,1,1,1,clock_timestamp()+interval '1 hour',false),
      ('prj_alpha','g2','ap2','d09_worker',1,1,1,1,1,1,clock_timestamp()+interval '1 hour',false);
    INSERT INTO awe_int03.runtime(project_id,task_id,worker_login,plan,plan_hash) VALUES
      ('prj_alpha','task_one','d09_worker',${json(plan)},${quote(digest(plan))}),
      ('prj_alpha','task_followup','d09_worker',${json(follow)},${quote(digest(follow))});
    INSERT INTO awe_int03.dependencies VALUES('prj_alpha','task_followup','task_one');`);
  if(!legacy)sql(`INSERT INTO awe_int03.evaluator_trust VALUES('prj_alpha','d09_evaluator_login',
    ${quote(sha(readFileSync(new URL('../../awe/qa/evaluator.mjs',import.meta.url))))},
    ${quote(sha(readFileSync(new URL('../../awe/integration_v3/evaluator-service.mjs',import.meta.url))))},
    'D08_E0_EXACT_ARTIFACT_V1',clock_timestamp()+interval '1 hour',false)`);
  const service=legacy?null:cluster.evaluatorTransport(name);
  const pools={workerPool:cluster.pool('d09_worker',name),verifierPool:cluster.pool('d09_qa_login',name),ownerPool:cluster.pool('d09_owner_login',name)};
  const make=(overrides={})=>createIntegratedHost({...pools,evaluator:service?.client,projectId:'prj_alpha',taskId:'task_one',...overrides});
  const host=make(),command={operation_id:'o1',attempt_id:'a1',effect_slot:'s1',approval_id:'ap1',grant_id:'g1',idempotency_key:'key1',
    plan_hash:plan.d06_plan_hash,payload_hash:plan.payload_hash,reserve_micros:plan.reserve_micros};
  const call=(fn,body={},login='d09_worker')=>JSON.parse(sql(`SELECT awe_int03.${fn}(${json({...scope,...body})})`,login));
  const issue=(action='VERIFY',grant_id='qa1',login='d09_qa_login')=>call('issue',{action,grant_id,login},'d09_issuer_login');
  const execute=async()=>{await host.trusted.admit(command);return host.trusted.execute(job);};
  const verify=async()=>{issue();return host.trusted.verify('qa1','qa_key');};
  const accept=async proof=>{issue('ACCEPT','own1','d09_owner_login');return host.trusted.accept('own1',proof.proof_hash,'owner_key');};
  const bundle=()=>JSON.parse(sql("SELECT body FROM awe_int03.bundles WHERE task_id='task_one' ORDER BY version DESC LIMIT 1"));
  const counts=()=>JSON.parse(sql(`SELECT jsonb_build_object('attempts',(SELECT count(*) FROM awe_d09.attempts),
    'bundles',(SELECT count(*) FROM awe_int03.bundles),'invoices',(SELECT count(*) FROM awe_d09.invoices),
    'reserved',(SELECT reserved_micros::text FROM awe_d09.budgets WHERE kind='PROJECT'),
    'spent',(SELECT spent_micros::text FROM awe_d09.budgets WHERE kind='PROJECT'),
    'attempts_used',(SELECT attempts_used FROM awe_d09.budgets WHERE kind='PROJECT'))`));
  return {cluster,name,job,plan,host,pools,evaluator:service?.client,evaluatorControl:service?.control,
    make,command,call,sql,issue,execute,verify,accept,bundle,counts,scope};
}
