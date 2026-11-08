import http from 'node:http';
import https from 'node:https';
import {TextDecoder} from 'node:util';
import {validateTransportConfig} from './config.mjs';
import {compileChat,decodeProviderReply} from './protocol.mjs';
import {copy,exact,need,opaqueId,bytesHash,safeCode,usage} from './common.mjs';
// Real HTTP/HTTPS protocol engine. PREPARED_LIVE can encode but cannot obtain dispatch permission.
// No SDK, key reader, environment lookup, redirect, DNS, retry or provider fallback.
export function createOpenAITransport(raw,{now=Date.now}={}) {
 const config=validateTransportConfig(raw,now()),prepared=new WeakMap();
 let requests=0,inFlight=0;const window=[];
 return Object.freeze({
  config:()=>copy(config),
  prepare(input) {
   exact(input,['messages','toolSchemas','jsonSchema','maxOutput','features']);
   const compiled=compileChat({...copy(input),model:config.modelId});
   need(Buffer.byteLength(compiled.bytes)<=config.maxRequestBytes,'REQUEST_BYTES_EXCEEDED');
   const handle=Object.freeze({});prepared.set(handle,compiled);
   return {handle,requestHash:compiled.requestHash,requestBytes:Buffer.byteLength(compiled.bytes),body:copy(compiled.body)};
  },
  async send(handle,{clientRequestId,signal,timeoutMs=config.timeoutMs,bounds,maxToolCalls}) {
   const p=prepared.get(handle);need(p&&!p.used,'TRANSPORT_HANDLE_REQUIRED');
   const limits=copy(bounds);usage(limits);need(Number.isSafeInteger(maxToolCalls)&&maxToolCalls>=0&&maxToolCalls<=1,'TOOL_BOUND_INVALID');
   need(opaqueId(clientRequestId),'CLIENT_REQUEST_ID_INVALID');
   need(Number.isSafeInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=config.timeoutMs,'TIMEOUT_INVALID');
   if(config.mode!=='LOOPBACK_MOCK')return {ok:false,code:'LIVE_ADMISSION_REQUIRED',sent:false,requestHash:p.requestHash,physicalDecision:'DENY'};
   if(signal?.aborted)return {ok:false,code:'CANCELLED_BEFORE_SEND',sent:false,requestHash:p.requestHash};
   const clock=now();while(window.length&&window[0]<=clock-config.windowMs)window.shift();
   if(requests>=config.maxSessionRequests||window.length>=config.maxWindowRequests||inFlight>=config.maxConcurrent)return {ok:false,code:'REQUEST_LIMIT',sent:false,requestHash:p.requestHash};
   p.used=true;requests++;inFlight++;window.push(clock);
   const receipt={requestHash:p.requestHash,clientRequestId,providerRequestId:null,completionId:null,responseHash:null,httpStatus:null,sent:true,evidence:'LOOPBACK_HTTP_MOCK',physicalDecision:'DENY'};
   let request,timer;
   try {
    return await new Promise(resolve=>{
     let finished=false;
     const done=result=>{if(finished)return;finished=true;clearTimeout(timer);signal?.removeEventListener('abort',abort);resolve({...receipt,...result});};
     const fail=code=>{done({ok:false,code});request?.destroy();};
     const abort=()=>fail('CANCELLED_AFTER_SEND');
     timer=setTimeout(()=>fail('PROVIDER_TIMEOUT'),timeoutMs);
     signal?.addEventListener('abort',abort,{once:true});
     try {
      const endpoint=new URL(config.endpoint),engine=endpoint.protocol==='https:'?https:http;
      request=engine.request(endpoint,{method:'POST',agent:false,maxHeaderSize:8192,headers:{'Content-Type':'application/json','Accept':'application/json','Content-Length':Buffer.byteLength(p.bytes),'X-Client-Request-Id':clientRequestId}},res=>{
       receipt.httpStatus=res.statusCode;
       const requestId=res.headers['x-request-id'];
       if(opaqueId(requestId))receipt.providerRequestId=requestId;
       const chunks=[];let size=0;
       if(res.statusCode!==200){res.resume();return fail(res.statusCode>=300&&res.statusCode<400?'REDIRECT_DENIED':res.statusCode===429?'PROVIDER_RATE_LIMIT':'PROVIDER_HTTP_ERROR');}
       if(!receipt.providerRequestId){res.resume();return fail('PROVIDER_REQUEST_ID_MISSING');}
       if(!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(res.headers['content-type']??'')||res.headers['content-encoding']&&res.headers['content-encoding']!=='identity'){res.resume();return fail('RESPONSE_MEDIA_UNSUPPORTED');}
       res.on('data',chunk=>{size+=chunk.length;if(size>config.maxResponseBytes)fail('RESPONSE_BYTES_EXCEEDED');else chunks.push(chunk);});
       res.on('aborted',()=>fail('RESPONSE_TRUNCATED'));res.on('error',()=>fail('RESPONSE_TRUNCATED'));
       res.on('end',()=>{
        if(finished)return;
        try {
         need(res.complete,'RESPONSE_TRUNCATED');
         const bytes=Buffer.concat(chunks);receipt.responseHash=bytesHash(bytes);
         const raw=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
         if(opaqueId(raw.id))receipt.completionId=raw.id;
         const decoded=decodeProviderReply(raw,{model:config.modelId,toolSchemas:p.toolSchemas,jsonSchema:p.jsonSchema,bounds:limits,maxToolCalls});
         done({ok:true,code:'COMPLETE',decoded});
        }catch(e){fail(safeCode(e));}
       });
      });
      request.on('error',()=>fail('PROVIDER_CONNECTION_ERROR'));
      request.end(p.bytes);
     }catch{fail('PROVIDER_CONNECTION_ERROR');}
    });
   }finally{clearTimeout(timer);inFlight--;}
  },
  physicalDispatch:()=>({decision:'DENY',code:'LIVE_ADMISSION_REQUIRED'}),
  inspect:()=>({requests,inFlight,mode:config.mode,sdkRetries:0,liveCalls:0})
 });
}
