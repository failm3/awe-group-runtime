import test from 'node:test';
import assert from 'node:assert/strict';
import {createRouterCheapHostTransport,isRouterCheapHostTransport} from '../host/router-cheap/transport.mjs';
import {createRouterCheapHostPolicy,isRouterCheapHostPolicy,getRouterCheapHostPolicySnapshot,routerCheapPaidReadiness} from '../host/router-cheap/host-policy.mjs';

test('QA3 genuine host transport cannot dispatch a paid request or verify an invented input bound',async()=>{
 const transport=createRouterCheapHostTransport();assert.equal(isRouterCheapHostTransport(transport),true);assert.equal(isRouterCheapHostTransport({...transport}),false);assert.ok(Object.isFrozen(transport));
 assert.equal(transport.verifyInputBound({max_input_tokens:1}),false);
 await assert.rejects(transport.send({url:'https://router.cheap/v1/chat/completions',body:{model:'invented'}}),{code:'CLOUD_PAID_TRANSPORT_DISABLED'});
 // preflight() is intentionally never called by QA: it owns actual key access.
});
test('QA3 raw policy JSON and spend proposals cannot mint authenticated host policy',()=>{
 const proposal={schema:'awe.e1.router-cheap.host-policy/1',total_cap_micros:'30000000',per_attempt_cap_micros:'3000000',max_attempts:15,enabled:true};
 assert.equal(isRouterCheapHostPolicy(proposal),false);assert.throws(()=>getRouterCheapHostPolicySnapshot(proposal));assert.throws(()=>createRouterCheapHostPolicy(proposal),{code:'CLOUD_PROVIDER_ACTUAL_HARD_CAP_UNVERIFIED'});
 const ready=routerCheapPaidReadiness();assert.equal(ready.spending_enabled,false);assert.equal(ready.actual_charge_limit,'UNVERIFIED');assert.equal(ready.owner_spending_grant,'NOT_ISSUED');assert.equal(ready.charged_ack_contract,'UNVERIFIED');assert.equal(ready.provider_input_bound,'UNVERIFIED');
});
