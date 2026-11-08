import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {digest} from '../../awe/tool_registry/common.mjs';
const quote=v=>v===null||v===undefined?'NULL':Array.isArray(v)?'ARRAY['+v.map(quote).join(',')+']::text[]':typeof v==='number'?String(v):"'"+String(v).replaceAll("'","''")+"'";
// Test-only binding bridge to the existing psql binary. Each checkout is one real
// SQL session; transaction/rollback tests do not use a simulated SQL implementation.
export function createPsqlPool({executable,args,env,record=()=>{}}){return {async connect(){
 const child=spawn(executable,args,{env,windowsHide:true}),marker='TR01_'+randomBytes(16).toString('hex');let pending=null,output='',errors='',closed=false;
 child.stderr.on('data',b=>errors+=b);child.on('error',e=>{closed=true;pending?.reject(e);pending=null;});
 child.on('close',code=>{closed=true;pending?.reject(Error('PSQL_EXIT_'+code+': '+errors));pending=null;});child.stdin.on('error',()=>{});
 child.stdout.on('data',b=>{output+=b;if(pending&&output.includes(marker)){const at=output.indexOf(marker),text=output.slice(0,at).trim();output=output.slice(at+marker.length).replace(/^\r?\n/,'');const p=pending;pending=null;p.resolve(text);}});
 const execute=sql=>new Promise((resolve,reject)=>{if(closed)return reject(Error('PSQL_CLOSED'));if(pending)return reject(Error('PSQL_CONCURRENT'));
  const timer=setTimeout(()=>{child.kill();reject(Error('PSQL_TIMEOUT'));},60000);pending={resolve:t=>{clearTimeout(timer);resolve(t);},reject:e=>{clearTimeout(timer);reject(e);}};child.stdin.write(sql+';\n\\echo '+marker+'\n');});
 return {async query(sql,params=[]){const expanded=sql.replace(/\$(\d+)/g,(_,n)=>quote(params[Number(n)-1]));const select=/^SELECT\b/.test(sql);
  const text=await execute(select?"SELECT COALESCE(jsonb_agg(to_jsonb(q)),'[]'::jsonb) FROM ("+expanded+') q':expanded);
  record({sql,parameter_digest:digest(params),parameter_bytes:Buffer.byteLength(JSON.stringify(params)),success:true});return {rows:select?JSON.parse(text):[]};},release(){if(!closed)child.stdin.end('\\q\n');}};
}};}
