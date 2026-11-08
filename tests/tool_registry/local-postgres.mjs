import {spawnSync} from 'node:child_process';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,existsSync,unlinkSync,realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {randomBytes} from 'node:crypto';
import {ensure,sha} from '../../awe/tool_registry/common.mjs';
import {createPsqlPool} from './psql-pool.mjs';
export const root=resolve(import.meta.dirname,'../..');
export const quote=v=>"'"+String(v).replaceAll("'","''")+"'";
export function createCluster(){
 ensure(process.platform==='linux'&&process.getuid()!==0,'TR_LINUX_NONROOT_TEST_ONLY');
 const bin='/usr/lib/postgresql/18/bin',evidence=join(root,'TR-01/evidence');mkdirSync(evidence,{recursive:true});
 const run=mkdtempSync(join(evidence,'tr01-pg-')),sandbox=mkdtempSync(join(tmpdir(),'awe-tr01-')),data=join(sandbox,'cluster'),password=randomBytes(24).toString('hex'),pw=join(sandbox,'password');
 const env={TZ:'UTC',LANG:'C',LC_ALL:'C',PATH:'/usr/bin:/bin',PGCONNECT_TIMEOUT:'3',PGPASSWORD:password,PGPASSFILE:join(sandbox,'no-passfile')};
 const commands=[],port=55497;let started=false;
 const runTool=(name,args,input)=>{const r=spawnSync(join(bin,name),args,{env,input,encoding:'utf8',timeout:60000,maxBuffer:32*1024*1024});commands.push({name,args:args.map(a=>a.includes('PASSWORD')?'<EPHEMERAL_ROLE_SETUP>':a),exit:r.status,error:r.error?.code??null,stderr:(r.stderr??'').replaceAll(password,'<REDACTED>'),stdout_sha256:sha(r.stdout??'')});ensure(r.status===0,'TR_PG_TOOL '+name+': '+(r.stderr??r.error?.code).replaceAll(password,'<REDACTED>'));return (r.stdout??'').trim();};
 const args=login=>['-X','--no-password','-h','127.0.0.1','-p',String(port),'-U',login,'-d','postgres','-v','ON_ERROR_STOP=1','-Atq'];
 const sql=(s,login='tr_bootstrap')=>runTool('psql',args(login),s);
 const check=()=>ensure(realpathSync(data).startsWith(realpathSync(sandbox)+'/')&&existsSync(join(data,'PG_VERSION')),'TR_CLUSTER_PATH');
 const close=()=>{if(started){check();runTool('pg_ctl',['-D',data,'-w','-t','15','-m','fast','stop']);started=false;}
  writeFileSync(join(run,'commands.json'),JSON.stringify(commands,null,2)+'\n');writeFileSync(join(run,'scope.json'),JSON.stringify({data_directory:data,port,listen:'127.0.0.1',fresh_initdb:true,stopped:!started,physical_decision:'DENY',node:process.version,pg_version:runTool('psql',['--version'])},null,2)+'\n');
  if(existsSync(join(sandbox,'server.log')))writeFileSync(join(run,'server.log'),readFileSync(join(sandbox,'server.log'),'utf8').replaceAll(password,'<REDACTED>'));};
 try{
  writeFileSync(pw,password+'\n',{mode:0o600});runTool('initdb',['-D',data,'-U','tr_bootstrap','--pwfile='+pw,'--auth-host=scram-sha-256','--auth-local=scram-sha-256','--encoding=UTF8','--no-locale']);unlinkSync(pw);
  writeFileSync(join(data,'postgresql.auto.conf'),`listen_addresses='127.0.0.1'\nport=${port}\nunix_socket_directories='${sandbox}'\nfsync=on\nsynchronous_commit=on\nfull_page_writes=on\n`);
  check();try{runTool('pg_ctl',['-D',data,'-l',join(sandbox,'server.log'),'-w','-t','15','start']);}finally{started=existsSync(join(data,'postmaster.pid'));}
  const settings=JSON.parse(sql("SELECT json_build_object('data_directory',current_setting('data_directory'),'port',current_setting('port'),'version',current_setting('server_version_num'),'fsync',current_setting('fsync'))"));
  ensure(settings.data_directory===data&&settings.port===String(port)&&Number(settings.version)>=180000,'TR_CLUSTER_IDENTITY');
  sql(readFileSync(join(root,'awe/tool_registry/migrations/001-up.sql'),'utf8'));
  for(const role of ['tr_alice','tr_bob','tr_intruder','tr_ingest','tr_expired'])sql(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD ${quote(password)}`);
  sql("GRANT awe_tr01_reader TO tr_alice,tr_bob,tr_intruder,tr_expired; GRANT awe_tr01_ingester TO tr_ingest; INSERT INTO awe_tr01.principals VALUES('tr_alice','tenant_a','alice',clock_timestamp()+interval '1 day',false),('tr_bob','tenant_b','bob',clock_timestamp()+interval '1 day',false),('tr_expired','tenant_a','expired',clock_timestamp()-interval '1 day',false); INSERT INTO awe_tr01.projects VALUES('project_a','tenant_a',1),('project_b','tenant_b',1); INSERT INTO awe_tr01.memberships VALUES('project_a','tr_alice'),('project_b','tr_bob'),('project_a','tr_expired');");
  return {run,sql,settings,pool:login=>createPsqlPool({executable:join(bin,'psql'),args:args(login),env,record:r=>commands.push(r)}),close};
 }catch(e){try{close();}catch{}if(existsSync(pw))unlinkSync(pw);throw e;}
}
