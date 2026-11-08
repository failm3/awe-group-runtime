import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';

// Test transport only: one authenticated psql PROCESS/connection per checked-out
// client. BEGIN, SELECT and COMMIT really execute on that SAME server session.
// It is not a scripted SQL fake. Production driver/authentication remains gated.
export function createPsqlPool({executable,args,env,record}) {
  let fault=null;
  return {
    faultNextCommit(mode='after',fn=null){fault={mode,fn};},
    async connect() {
      const child=spawn(executable,args,{env,stdio:['pipe','pipe','pipe'],windowsHide:true});
      const marker='INT03_'+randomBytes(16).toString('hex');
      let pending=null,output='',errors='',closed=false,lastFunction=null;
      child.stderr.on('data',b=>{errors+=b;});
      child.on('error',e=>{closed=true;pending?.reject(e);pending=null;});
      child.on('close',code=>{closed=true;pending?.reject(Error('PSQL_EXIT_'+code+': '+errors));pending=null;});
      child.stdin.on('error',()=>{});
      child.stdout.on('data',b=>{
        output+=b;
        if(pending && output.includes(marker)) {
          const at=output.indexOf(marker),text=output.slice(0,at).trim();
          output=output.slice(at+marker.length).replace(/^\r?\n/,'');
          const p=pending;pending=null;p.resolve(text);
        }
      });
      const execute=text=>new Promise((resolve,reject)=>{
        if(closed)return reject(Error('PSQL_CLOSED: '+errors));
        if(pending)return reject(Error('PSQL_CONCURRENT_QUERY_DENIED'));
        const timer=setTimeout(()=>{child.kill();reject(Error('PSQL_TIMEOUT'));},20000);
        pending={resolve:v=>{clearTimeout(timer);resolve(v);},reject:e=>{clearTimeout(timer);reject(e);}};
        child.stdin.write(text+';\n\\echo '+marker+'\n');
      });
      return {
        async query(sql,params=[]) {
          let expanded=sql;
          if(params.length) {
            if(params.length!==1 || !sql.includes('$1::jsonb'))throw Error('PSQL_PARAMETER_CONTRACT');
            expanded=sql.replace('$1::jsonb',"'"+params[0].replaceAll("'","''")+"'::jsonb");
          }
          if(sql.startsWith('SELECT awe_'))lastFunction=sql.match(/SELECT ([^(]+)/)?.[1];
          const mode=sql==='COMMIT' && fault && (!fault.fn || lastFunction?.endsWith('.'+fault.fn))?fault.mode:null;
          if(mode)fault=null;
          if(mode==='before'){child.kill();throw Error('INJECTED_COMMIT_CONNECTION_LOSS_BEFORE_SEND');}
          const started=new Date().toISOString();
          try {
            const text=await execute(expanded);
            record({sql,parameters:params,started,exit:0,result:text});
            if(mode==='after'){child.kill();throw Error('INJECTED_COMMIT_ACK_LOSS_AFTER_REAL_COMMIT');}
            return {rows:text?[{result:JSON.parse(text)}]:[]};
          } catch(e) {record({sql,parameters:params,started,exit:1,error:e.message});throw e;}
        },
        release(){if(!closed)child.stdin.end('\\q\n');}
      };
    }
  };
}
