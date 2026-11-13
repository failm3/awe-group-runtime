import http from 'node:http';
import {randomBytes} from 'node:crypto';
import {check,CoordinatorError} from './errors.mjs';

/** Loopback staging authority. Credential issuance is a host-only method, with
 * no registration/impersonation HTTP endpoint. This is a bounded local service,
 * not proof of hostile Windows process isolation or production human login.
 */
export async function createAuthorityServer({coordinator,qaCoordinator,dispatchEffect,port=0}) {
  check(coordinator?.kind==='AWE_E1_DURABLE_COORDINATOR','A2_COORDINATOR_REQUIRED');
  const credentials=new Map(),contexts=new WeakMap();
  function issueCredential(principal) {
    check(principal.project_id===coordinator.project_id && ['OWNER','COORDINATOR','WORKER','QA','BROKER'].includes(principal.role) && typeof principal.principal_id==='string','A2_AUTHORITY_PRINCIPAL');
    check(principal.role!=='QA'||qaCoordinator?.project_id===principal.project_id,'A2_QA_PORT_REQUIRED');
    const token=randomBytes(32).toString('hex'),context=Object.freeze({});
    const record=Object.freeze(structuredClone(principal)); credentials.set(token,record); contexts.set(context,record);
    return Object.freeze({token,context});
  }
  function authenticateContext(context) { const principal=contexts.get(context); check(principal,'A2_AUTH_CONTEXT'); return principal; }
  function workerScope(principal,request) { check(principal.role==='WORKER'||principal.role==='BROKER','A2_WORKER_REQUIRED'); check(!request.worker_id||request.worker_id===principal.principal_id,'A2_WORKER_IMPERSONATION'); return {...request,worker_id:principal.principal_id}; }
  const server=http.createServer(async(req,res)=>{
    try {
      check(req.method==='POST'&&req.url==='/rpc','A2_RPC_PATH');
      const token=/^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization??'')?.[1],principal=credentials.get(token); check(principal,'A2_AUTH_REQUIRED');
      let bytes=0,body=''; for await (const chunk of req) {bytes+=chunk.length;check(bytes<=65536,'A2_RPC_SIZE');body+=chunk.toString('utf8');}
      const input=JSON.parse(body);check(Object.keys(input).sort().join(',')==='method,request'&&input.request&&typeof input.request==='object','A2_RPC_ENVELOPE');
      const {method}=input,request=input.request;
      check(!request.project_id||request.project_id===principal.project_id,'A2_PROJECT_SCOPE');
      let value;
      if(method==='claim') {
        const scoped=workerScope(principal,request),allowed=principal.capabilities??[];
        check(Array.isArray(scoped.capabilities)&&scoped.capabilities.every(cap=>allowed.includes(cap)),'A2_WORKER_CAPABILITY');
        value=await coordinator.claim(scoped);
      } else if(['heartbeat','complete','reserve','markSending','settle','unknown','failBeforeSend'].includes(method)) {
        value=await coordinator[method](workerScope(principal,request));
      } else if(method==='dispatchEffect') {
        const scoped=workerScope(principal,request);check(typeof dispatchEffect==='function','A2_EFFECT_ADAPTER_REQUIRED');
        const permit=await coordinator.markEffectSending(scoped);
        try {const receipt=await dispatchEffect(permit);value=await coordinator.confirmEffect({...scoped,...receipt});}
        catch {await coordinator.unknownEffect({...scoped,reason:'ADAPTER_RESPONSE_UNCERTAIN'});throw new CoordinatorError('A2_EFFECT_OUTCOME_UNKNOWN');}
      } else if(method==='qaEvaluate') {
        check(principal.role==='QA','A2_INDEPENDENT_QA_REQUIRED');check(!request.evaluator_id||request.evaluator_id===principal.principal_id,'A2_QA_IMPERSONATION');
        value=await qaCoordinator.qaEvaluate({...request,evaluator_id:principal.principal_id});
      } else if(['snapshot','events','getCursor'].includes(method)) {
        check(['OWNER','COORDINATOR','QA'].includes(principal.role),'A2_READ_SCOPE');const reader=principal.role==='QA'?qaCoordinator:coordinator;
        value=method==='getCursor'?await reader.getCursor(request.consumer_id):await reader[method](request);
      } else if(['cancel','revoke','revokeCapability'].includes(method)) {
        check(principal.role==='OWNER','A2_OWNER_REQUIRED');check(!request.owner_id||request.owner_id===principal.principal_id,'A2_OWNER_IMPERSONATION');value=await coordinator[method]({...request,owner_id:principal.principal_id});
      } else {throw new CoordinatorError('A2_RPC_METHOD_DENIED');}
      const output=JSON.stringify({ok:true,value});res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(output);
    } catch(error) {
      res.writeHead(403,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify({ok:false,error:error?.code?.startsWith('A2_')?error.code:'A2_RPC_REJECT'}));
    }
  });
  server.requestTimeout=15000;server.headersTimeout=10000;
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});
  return Object.freeze({url:'http://127.0.0.1:'+server.address().port,issueCredential,authenticateContext,
    revokeCredential(token){credentials.delete(token);},async close(){credentials.clear();await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}});
}

export function createAuthorityClient({url,token}) {
  const endpoint=new URL(url);check(endpoint.protocol==='http:'&&endpoint.hostname==='127.0.0.1'&&endpoint.pathname==='/'&&!endpoint.username&&!endpoint.password&&!endpoint.search&&!endpoint.hash,'A2_AUTHORITY_ENDPOINT');
  check(/^[a-f0-9]{64}$/.test(token),'A2_AUTHORITY_TOKEN');
  const call=async(method,request={})=>{
    let response;try{response=await fetch(new URL('/rpc',endpoint),{method:'POST',headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({method,request}),redirect:'error',signal:AbortSignal.timeout(15000)});}catch{throw new CoordinatorError('A2_AUTHORITY_TRANSPORT_UNKNOWN');}
    const result=await response.json();check(result.ok,result.error??'A2_AUTHORITY_REJECT');return result.value;
  };
  return Object.freeze({call,...Object.fromEntries(['claim','heartbeat','complete','reserve','markSending','settle','unknown','failBeforeSend','dispatchEffect','qaEvaluate','snapshot','events','cancel','revoke','revokeCapability'].map(method=>[method,request=>call(method,request)]))});
}
