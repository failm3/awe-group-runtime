import {fixture,query,approve,toolReply,toolSchema} from './tests/fixtures.mjs';
import {bytesHash} from './common.mjs';
const f=await fixture({script:[{}, {reply:toolReply()}]});
try {
 const main=f.broker.plan('main',query('demo-main'));
 const a=await f.broker.run(main.handle,approve(f,main),'grant-main');
 if(a.status!=='SUCCEEDED')throw Error('MAIN_DEMO_FAILED');
 const held=f.broker.plan('child',query('blocked-child'));
 await f.d09.settle(main,'50');await f.broker.refreshAccounting(main.handle);
 const child=f.broker.plan('child',query('demo-child',{features:{tools:true,json:false,stream:false},toolSchemas:{weather:toolSchema},bounds:{uncachedInput:3000,cacheRead:0,cacheWrite:0,output:20,toolCalls:1}}));
 const b=await f.broker.run(child.handle,approve(f,child),'grant-child');
 if(b.status!=='SUCCEEDED')throw Error('CHILD_DEMO_FAILED');
 const receipt={version:'LLM02_EXECUTION_EVIDENCE_V1',recordedAt:new Date().toISOString(),evidence:'OBSERVED_LOOPBACK_HTTP_AND_UNMODIFIED_D09_JS_PORT_WITH_SCRIPTED_PG_POOL',
  physicalDecision:'DENY',liveCalls:0,apiKeysUsed:0,realDatabase:'NOT_RUN',accepted:false,
  main:{status:a.status,outputReleased:a.outputReleased,receipt:f.broker.evidence(main.handle).receipt},
  heldChild:{decision:held.decision,code:held.code},child:{status:b.status,outputReleased:b.outputReleased,receipt:b.receipt,tools:b.output.tools},
  observedHTTP:f.server.calls.map(c=>({method:c.method,path:c.path,requestHash:bytesHash(c.bytes),contentLength:c.headers['content-length'],clientRequestId:c.headers['x-client-request-id'],authorizationHeaderPresent:Object.hasOwn(c.headers,'authorization'),model:c.body.model,stream:c.body.stream,store:c.body.store})),
  observedD09:f.d09.calls,balances:f.d09.balances(),usage:f.broker.usageByAgent('main'),owners:f.broker.owners()};
 console.log(JSON.stringify(receipt,null,2));
}finally{await f.close();}
