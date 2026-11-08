import {createHash} from 'node:crypto';
export {copy,hash} from '../awe/model_gateway/profiles.mjs';
export {brokerId as id,exact} from '../awe/model_gateway/broker-config.mjs';
export {money,integer,usage,quoteCost} from '../awe/budget/money.mjs';
export class ProviderError extends Error {constructor(code){super(code);this.code=code;}}
export function need(test,code){if(!test)throw new ProviderError(code);}
export const bytesHash=b=>'sha256:'+createHash('sha256').update(b).digest('hex');
export const opaqueId=x=>typeof x==='string'&&/^[A-Za-z0-9_.:-]{1,128}$/.test(x);
export const failResult=(code,status='DENY')=>({status,code,physicalDecision:'DENY',output:null,outputReleased:false,accepted:false});
// Never forward an arbitrary provider, persistence, socket or host exception message/code.
export const safeCode=e=>e instanceof ProviderError?e.code:'CONTRACT_REJECTED';
