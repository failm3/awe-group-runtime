import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';

// Test supervisor owns bootstrap credentials. Its returned client has only a
// run-ID RPC; the child alone receives the evaluator credential via stdin.
export function createEvaluatorTransport({pg,env,record}) {
  let fault=null,fail=false,dropResponse=false;
  const client=Object.freeze({async evaluateRun(request) {
    if(!request || Object.getPrototypeOf(request)!==Object.prototype || Object.keys(request).sort().join()!=='project_id,run_id,task_id')throw Error('EVALUATOR_REQUEST_INVALID');
    const config={pg,request:structuredClone(request),fault,failBeforeEvaluation:fail};
    const loseResponse=dropResponse;fault=null;fail=false;dropResponse=false;
    return new Promise((resolve,reject)=>{
      const argv=['--require',fileURLToPath(new URL('./egress-guard.cjs',import.meta.url)),fileURLToPath(new URL('./evaluator-process.mjs',import.meta.url))];
      const child=spawn(process.execPath,argv,{env,stdio:['pipe','pipe','pipe'],windowsHide:true});
      let stdout='',stderr='';const timer=setTimeout(()=>{child.kill();const error=Error('EVALUATOR_PROCESS_TIMEOUT');error.outcomeUnknown=true;reject(error);},30000);
      child.stdin.on('error',()=>{});child.stdout.on('data',x=>stdout+=x);child.stderr.on('data',x=>stderr+=x);
      child.on('error',error=>{clearTimeout(timer);reject(error);});
      child.on('close',exit=>{
        clearTimeout(timer);let response;
        try{response=JSON.parse(stdout);}catch{record({tool:'evaluator-process',argv,exit,error:stderr});const error=Error('EVALUATOR_PROCESS_INVALID_RESPONSE');error.outcomeUnknown=true;return reject(error);}
        record({tool:'evaluator-process',argv,request:config.request,exit,...response});
        if(loseResponse || (response.ok && exit!==0)){const error=Error('EVALUATOR_RESPONSE_OUTCOME_UNKNOWN');error.outcomeUnknown=true;reject(error);}
        else if(!response.ok){const error=new Error(response.error);error.outcomeUnknown=response.outcomeUnknown;reject(error);}
        else resolve({...response.value,evaluator_process_id:response.process_id});
      });
      child.stdin.end(JSON.stringify(config));
    });
  }});
  return {client,control:Object.freeze({
    faultNextCommit(mode='after',fn='finish_qa'){fault={mode,fn};},
    failBeforeEvaluationOnce(){fail=true;}
    ,dropResponseOnce(){dropResponse=true;}
  })};
}
