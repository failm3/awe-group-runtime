// Genuine PostgreSQL harness. Never accepts a connection URL, existing data dir,
// production credentials or a remote host. Only its own fresh initdb cluster.
import {spawn,spawnSync} from 'node:child_process';
import {mkdirSync,mkdtempSync,writeFileSync,readFileSync,existsSync,unlinkSync,realpathSync} from 'node:fs';
import {join,isAbsolute,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomBytes,createHash} from 'node:crypto';
import {tmpdir,release} from 'node:os';
export const root=fileURLToPath(new URL('../../',import.meta.url));
const tools=['initdb','pg_ctl','psql','pg_dump','pg_restore'];
const bin=process.env.D09_PG_BIN;
if(bin && !isAbsolute(bin)) throw Error('D09_ABSOLUTE_PG_BIN_REQUIRED');
const executable=n=>bin?join(bin,n+(process.platform==='win32'?'.exe':'')):n;
// Deliberately do not inherit PG*, service/credential files, proxy or provider env.
const env={TZ:'UTC',LANG:'C',LC_ALL:'C',PGCONNECT_TIMEOUT:'3',PGPASSFILE:join(root,'D-09','no-passfile')};
for(const k of ['SystemRoot','WINDIR','PATH','TEMP','TMP','COMSPEC']) if(process.env[k]) env[k]=process.env[k];
export const probe=tools.map(name=>{
  const r=spawnSync(executable(name),['--version'],{env,encoding:'utf8',windowsHide:true,timeout:5000});
  return {name,available:r.status===0,version:r.status===0?r.stdout.trim():null,error:r.error?.code??(r.status===0?null:'NONZERO')};
});
export const available=probe.every(x=>x.available);
if(process.env.D09_REQUIRE_PG==='1'&&!available)throw Error('D09_REQUIRED_POSTGRES_UNAVAILABLE');
export const reason='NOT_RUN: genuine disposable PostgreSQL requires initdb, pg_ctl, psql, pg_dump and pg_restore; no emulation is used';
export const quote=v=>"'"+String(v).replaceAll("'","''")+"'";
export const json=v=>quote(JSON.stringify(v))+'::jsonb';
export const hash='sha256:'+'a'.repeat(64);
export function admission(p,i=1,reserve='60') {return {project_id:p,task_id:'t1',operation_id:'o'+i,attempt_id:'a'+i,effect_slot:'s'+i,approval_id:'ap'+i,grant_id:'g'+i,idempotency_key:'key'+i,plan_hash:hash,payload_hash:hash,reserve_micros:reserve};}
export function invoice(p,i=1,actual='30') {return {project_id:p,attempt_id:'a'+i,provider:'synthetic',invoice_id:p+'-invoice'+i,actual_micros:actual,input_tokens:100,output_tokens:20,evidence_hash:hash};}
export function createCluster() {
  if(!available) throw Error(reason);
  const evidence=join(root,'D-09','evidence');mkdirSync(evidence,{recursive:true});
  const run=mkdtempSync(join(evidence,'postgres-'));
  // PostgreSQL requires native Linux permissions; never put WSL PGDATA on /mnt/c.
  const sandbox=process.platform==='linux'?mkdtempSync(join(tmpdir(),'awe-d09-')):run;
  const data=join(sandbox,'cluster'),logs=[],password=randomBytes(24).toString('hex');
  const passwords={awe_d09_bootstrap:password};
  const port=55491; // Collision => fail; never attach to whatever occupies this port.
  const pgEnv={...env,PGPASSWORD:password,PGAPPNAME:'d09-tests'};
  const pw=join(sandbox,'initdb-password.txt');writeFileSync(pw,password+'\n',{mode:0o600});
  let started=false,initialized=false;
  const redact=text=>Object.values(passwords).reduce((s,p)=>s.replaceAll(p,'<REDACTED_EPHEMERAL_PASSWORD>'),text??'');
  const persist=()=>writeFileSync(join(run,'commands.json'),JSON.stringify(logs,null,2)+'\n');
  writeFileSync(join(run,'suite-environment.json'),JSON.stringify({node:process.version,node_executable:process.execPath,
    node_sha256:createHash('sha256').update(readFileSync(process.execPath)).digest('hex'),platform:process.platform,release:release(),uid:process.getuid?.(),
    tools:probe,worktree:root,cluster_data_dir:data,host:'127.0.0.1',port,physical_decision:'DENY'},null,2)+'\n');
  const runTool=(name,args,options={})=>{
    const r=spawnSync(executable(name),args,{env:pgEnv,encoding:'utf8',windowsHide:true,timeout:60000,maxBuffer:8*1024*1024,...options});
    // Commands never contain the ephemeral password, except private role setup below
    // (whose SQL text is intentionally not logged).
    logs.push({tool:name,args:args.map(a=>/CREATE ROLE.*PASSWORD/s.test(a)?'<REDACTED_EPHEMERAL_CREDENTIAL_SETUP>':a),exit:r.status,error:r.error?.code??null,stdout:redact(r.stdout),stderr:redact(r.stderr)});
    if(r.status!==0) {persist();throw Error('D09_PG_COMMAND_FAILED '+name+': '+redact(r.stderr??r.error?.code));}
    return (r.stdout??'').trim();
  };
  const args=(login,db)=>['-X','--no-password','-h','127.0.0.1','-p',String(port),'-U',login,'-d',db,'-v','ON_ERROR_STOP=1','-A','-t','-q'];
  const sql=(text,{login='awe_d09_bootstrap',db='awe_d09_test'}={})=>runTool('psql',[...args(login,db),'-c',text],{env:{...pgEnv,PGPASSWORD:passwords[login]}});
  const asyncSql=(text,{login='d09_worker',app='d09-concurrent'}={})=>new Promise(resolveResult=>{
    const argv=[...args(login,'awe_d09_test'),'-c',text];
    const child=spawn(executable('psql'),argv,{env:{...pgEnv,PGPASSWORD:passwords[login],PGAPPNAME:app},windowsHide:true});
    let stdout='',stderr='';const timer=setTimeout(()=>child.kill(),15000);
    child.stdout.on('data',x=>stdout+=x);child.stderr.on('data',x=>stderr+=x);
    child.on('error',e=>{stderr+=e.code;});child.on('close',code=>{clearTimeout(timer);logs.push({tool:'psql-concurrent',args:argv,exit:code,stdout,stderr});resolveResult({code,stdout,stderr});});
  });
  const checkCluster=()=>{if(!initialized||!realpathSync(data).startsWith(realpathSync(sandbox)+sep)||!existsSync(join(data,'PG_VERSION')))throw Error('D09_CLUSTER_PATH_DENIED');};
  const start=()=>{checkCluster();try{runTool('pg_ctl',['-D',data,'-l',join(sandbox,'server.log'),'-w','-t','15','start']);}finally{started=existsSync(join(data,'postmaster.pid'));}};
  const stop=mode=>{if(started){checkCluster();runTool('pg_ctl',['-D',data,'-w','-t','15','-m',mode,'stop']);started=false;}};
  const serverLog=()=>{if(existsSync(join(sandbox,'server.log')))writeFileSync(join(run,'server.log'),redact(readFileSync(join(sandbox,'server.log'),'utf8')));};
  const migration=direction=>sql(readFileSync(join(root,'awe','persistence','migrations','001-'+direction+'.sql'),'utf8'));
  try {
    runTool('initdb',['-D',data,'-U','awe_d09_bootstrap','--pwfile='+pw,'--auth-host=scram-sha-256','--auth-local=scram-sha-256','--encoding=UTF8','--no-locale']);initialized=true;unlinkSync(pw);
    writeFileSync(join(data,'postgresql.auto.conf'),`listen_addresses = '127.0.0.1'\nport = ${port}\nunix_socket_directories = '${sandbox.replaceAll("'","''")}'\nfsync = on\nsynchronous_commit = on\nfull_page_writes = on\n`);
    start();sql('CREATE DATABASE awe_d09_test',{db:'postgres'});migration('up');
    for(const login of ['d09_worker','d09_other','d09_reconciler_login','d09_issuer_login','d09_reader_login','d09_intruder']) {
      passwords[login]=randomBytes(24).toString('hex');
      sql(`CREATE ROLE ${login} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD ${quote(passwords[login])}`);
    }
    sql(`GRANT awe_d09_api,awe_d09_reader TO d09_worker,d09_other,d09_reader_login,d09_intruder;
      GRANT awe_d09_reconciler TO d09_reconciler_login; GRANT awe_d09_issuer TO d09_issuer_login;
      INSERT INTO awe_d09.principals SELECT login,login::text,'TEST_ONLY_LOCAL_ISSUER',clock_timestamp()+interval '1 day',false
      FROM (VALUES ('d09_worker'::name),('d09_other'::name),('d09_reconciler_login'::name),('d09_issuer_login'::name),('d09_reader_login'::name)) AS x(login);`);
  } catch(e) {try{stop('immediate');}catch{} if(existsSync(pw))unlinkSync(pw);persist();serverLog();throw e;}
  return {
    run,sql,asyncSql,migration,
    worker:text=>sql(text,{login:'d09_worker'}),
    call:(fn,body,login='d09_worker')=>JSON.parse(sql(`SELECT awe_d09.${fn}(${json(body)})`,{login})),
    seed:(p,{cap='100',count=3}={})=>{
      if(!/^[a-z0-9_]+$/.test(p)||!/^\d+$/.test(cap)||!Number.isSafeInteger(count))throw Error('D09_FIXTURE_INVALID');
      sql(`INSERT INTO awe_d09.projects(project_id) VALUES(${quote(p)});
        INSERT INTO awe_d09.memberships VALUES(${quote(p)},'d09_worker',ARRAY['READ','EXECUTE']),(${quote(p)},'d09_other',ARRAY['READ','EXECUTE']),
        (${quote(p)},'d09_reconciler_login',ARRAY['READ','RECONCILE']),(${quote(p)},'d09_issuer_login',ARRAY['READ','ISSUE']),(${quote(p)},'d09_reader_login',ARRAY['READ']);
        INSERT INTO awe_d09.origins VALUES(${quote(p)},'origin1',false);
        INSERT INTO awe_d09.tasks VALUES(${quote(p)},'t1','origin1',1,1,'d09_worker',clock_timestamp()+interval '1 hour',false);
        INSERT INTO awe_d09.budgets(project_id,budget_id,kind,currency,cap_micros,balance_micros,attempt_limit,valid_until)
          SELECT ${quote(p)},lower(k),k,'RUB',${cap},${cap},10,clock_timestamp()+interval '1 hour'
          FROM unnest(ARRAY['PROJECT','TASK','ORIGIN','DAY','MONTH','ACCOUNT']) k;
        INSERT INTO awe_d09.task_budgets SELECT project_id,'t1',budget_id FROM awe_d09.budgets WHERE project_id=${quote(p)};`);
      for(let i=1;i<=count;i++) sql(`INSERT INTO awe_d09.approvals VALUES(${quote(p)},'ap${i}','t1','d09_worker','o${i}','s${i}',${quote(hash)},${quote(hash)},${cap},clock_timestamp()+interval '1 hour',false,NULL);
        INSERT INTO awe_d09.grants VALUES(${quote(p)},'g${i}','ap${i}','d09_worker',1,1,1,1,1,1,clock_timestamp()+interval '1 hour',false);`);
    },
    expire:(p,a)=>sql(`UPDATE awe_d09.attempts SET delivery_until=clock_timestamp()-interval '1 second',deadline=clock_timestamp()-interval '1 second' WHERE project_id=${quote(p)} AND attempt_id=${quote(a)}`),
    crashRestart:()=>{stop('immediate');start();},
    backupRestore:fenceCommand=>{
      const backup=join(run,'backup.dump');runTool('pg_dump',['-h','127.0.0.1','-p',String(port),'-U','awe_d09_bootstrap','-d','awe_d09_test','-Fc','--schema=awe_d09','-f',backup]);
      sql('CREATE DATABASE awe_d09_restore',{db:'postgres'});
      runTool('pg_restore',['-h','127.0.0.1','-p',String(port),'-U','awe_d09_bootstrap','-d','awe_d09_restore','--exit-on-error',backup]);
      const tables=sql("SELECT tablename FROM pg_tables WHERE schemaname='awe_d09' ORDER BY tablename").split('\n');
      const digest=db=>createHash('sha256').update(tables.map(t=>t+':'+sql(`SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb)::text FROM awe_d09.${t} x`,{db})).join('\n')).digest('hex');
      const source=digest('awe_d09_test'),restored=digest('awe_d09_restore');
      // Restore is fenced BEFORE any client connection: restored approvals cannot authorize dispatch.
      sql('UPDATE awe_d09.projects SET restore_pending=true, auth_epoch=auth_epoch+1',{db:'awe_d09_restore'});
      const fenced=sql('SELECT bool_and(restore_pending) FROM awe_d09.projects',{db:'awe_d09_restore'});
      let dispatchDenied=false;
      try{sql(`SELECT awe_d09.admit(${json(fenceCommand)})`,{login:'d09_worker',db:'awe_d09_restore'});}
      catch(e){dispatchDenied=e.message.includes('D09_STALE_OR_INVALID_AUTHORITY');}
      const restoredAttemptCount=sql(`SELECT count(*) FROM awe_d09.attempts WHERE project_id=${quote(fenceCommand.project_id)}`,{db:'awe_d09_restore'});
      sql('DROP DATABASE awe_d09_restore WITH (FORCE)',{db:'postgres'});
      const proof={source,restored,fenced,dispatch_denied:dispatchDenied,restored_attempt_count:restoredAttemptCount,backup_sha256:createHash('sha256').update(readFileSync(backup)).digest('hex')};
      writeFileSync(join(run,'backup-restore.json'),JSON.stringify(proof,null,2)+'\n');return proof;
    },
    close:()=>{
      checkCluster();stop('fast');persist();serverLog();
      writeFileSync(join(run,'scope.json'),JSON.stringify({host:'127.0.0.1',port,cluster_data_dir:data,fresh_initdb:true,production:false,physical_dispatches:0,physical_decision:'DENY',cluster_retained:true,cluster_stopped:!started},null,2)+'\n');
    }
  };
}
