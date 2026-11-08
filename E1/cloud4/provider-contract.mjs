import {immutable} from '../contracts/index.mjs';
/** Public docs establish HTTP compatibility/request IDs, not an actual debit
 * ceiling after source/balance coefficients. Unknown fields may be ignored.
 * No boolean/JSON document or owner approval can override this technical gate.
 */
export function routerCheapCloud4ProviderContract(){return immutable({schema:'awe.e1.cloud4.provider-contract/1',provider:'router.cheap',observed_public_reference_digest:'sha256:8fc49ae8803a5a763a55600364139e201b7d9d3f1eca281689066bce1102645c',observed_public_pricing_digest:'sha256:383911469159ab647f0133f587fa329a2e944bc02b2857203614a20fd8ee8bdc',actual_account_debit_cap:'UNVERIFIED',per_request_actual_debit_cap:'UNDOCUMENTED',source_and_actual_charge_ack:'UNDOCUMENTED',input_token_upper_bound:'UNVERIFIED',price_conversion_after_coefficients:'UNVERIFIED',paid_send:'DISABLED',blocker:'PROVIDER_ACTUAL_CHARGE_CAP_AND_ACK_NOT_PROVEN'});}
export function createCloud4LiveBinding({accounting,authorization,provider_contract}={}){
  const contract=routerCheapCloud4ProviderContract();
  return Object.freeze({kind:'CLOUD4_PROVIDER_BLOCKED_BINDING',async invoke(){return immutable({decision:'BLOCKED',reason:contract.blocker,owner_consent:'ISSUED',provider_contract:contract,wire_attempts:0,actual_paid_calls:0,spending_enabled:false,native_accounting_bound:accounting?.kind==='CLOUD4_BOUND_NATIVE_ACCOUNTING',owner_authorization_present:Boolean(authorization),caller_proof_cannot_enable:Boolean(provider_contract)});}});
}
