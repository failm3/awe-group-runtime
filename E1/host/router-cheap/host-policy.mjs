import {need} from '../../contracts/index.mjs';
// These are host capabilities, never serialized permissions. No policy is
// minted while the provider's actual-charge limit semantics remain unverified.
const policies=new WeakMap();
export function isRouterCheapHostPolicy(value){return Boolean(value&&policies.has(value));}
export function getRouterCheapHostPolicySnapshot(value){need(isRouterCheapHostPolicy(value),'CLOUD_HOST_POLICY_REQUIRED');return policies.get(value);}
export function createRouterCheapHostPolicy(){
  // The observed subscription field hard_limit_usd=10 does not establish that
  // multiplied balance charges (rather than base usage) enforce that ceiling.
  // Neither a boolean, an issue proposal, nor a caller-supplied JSON is proof.
  throw Object.assign(new Error('CLOUD_PROVIDER_ACTUAL_HARD_CAP_UNVERIFIED'),{code:'CLOUD_PROVIDER_ACTUAL_HARD_CAP_UNVERIFIED'});
}
export function routerCheapPaidReadiness(){return Object.freeze({schema:'awe.e1.router-cheap.paid-readiness/1',spending_enabled:false,paid_transport:'DISABLED_PENDING_PROVIDER_CONTRACT',provider_nominal_key_limit_usd:10,actual_charge_limit:'UNVERIFIED',owner_spending_grant:'NOT_ISSUED',charged_ack_contract:'UNVERIFIED',provider_input_bound:'UNVERIFIED',reasons:['Provider key cap after source coefficients has not been verified.','No authenticated bounded spending grant exists.','Exact source/charge receipt and input-token bound contracts are not verified.']});}
