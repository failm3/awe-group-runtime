import {copy,hash,exact,need,integer,money,quoteCost} from './common.mjs';
export function validateTransportConfig(raw,now=Date.now()) {
 const c=copy(raw);
 exact(c,['version','mode','provider','protocol','endpoint','modelId','routeId','modelRevision','timeoutMs','maxRequestBytes','maxResponseBytes','maxSessionRequests','maxWindowRequests','windowMs','maxConcurrent','price','review']);
 need(c.version==='LLM02_TRANSPORT_V1'&&['LOOPBACK_MOCK','PREPARED_LIVE'].includes(c.mode),'LIVE_ADMISSION_REQUIRED');
 need(c.provider==='OpenAI'&&c.protocol==='OPENAI_CHAT_SUBSET_V1','PROVIDER_PROTOCOL_UNSUPPORTED');
 if(c.mode==='LOOPBACK_MOCK'){
  need(typeof c.endpoint==='string'&&/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}\/v1\/chat\/completions$/.test(c.endpoint),'EXTERNAL_ENDPOINT_DISABLED');
  const url=new URL(c.endpoint);need(Number(url.port)>0&&Number(url.port)<=65535&&url.href===c.endpoint,'ENDPOINT_INVALID');
 } else need(c.endpoint==='https://api.openai.com/v1/chat/completions','REVIEWED_PROVIDER_ENDPOINT_REQUIRED');
 need(typeof c.modelId==='string'&&/^[a-zA-Z0-9_.:-]{1,128}$/.test(c.modelId)&&typeof c.modelRevision==='string'&&c.modelRevision.length>0,'MODEL_PIN_REQUIRED');
 need(typeof c.routeId==='string'&&/^[a-zA-Z0-9_.:-]{1,128}$/.test(c.routeId),'ROUTE_PIN_REQUIRED');
 for(const k of ['timeoutMs','maxRequestBytes','maxResponseBytes','maxSessionRequests','maxWindowRequests','windowMs','maxConcurrent']){integer(c[k]);need(c[k]>0,'LIMIT_INVALID');}
 need(c.timeoutMs<=30000&&c.maxRequestBytes<=60000&&c.maxResponseBytes<=60000&&c.maxConcurrent<=8&&c.windowMs<=3600000,'LIMIT_INVALID');
 need(c.maxWindowRequests<=c.maxSessionRequests,'LIMIT_INVALID');
 exact(c.review,['evidence','region','privacy','qualityLowerBoundBps','contextTokens','outputTokens','validUntil']);
 need(c.review.evidence==='SYNTHETIC_ONLY'&&typeof c.review.region==='string'&&typeof c.review.privacy==='string','REVIEW_EVIDENCE_INVALID');
 for(const k of ['qualityLowerBoundBps','contextTokens','outputTokens','validUntil'])integer(c.review[k]);
 need(c.review.qualityLowerBoundBps<=10000&&c.review.outputTokens>0&&c.review.contextTokens>=c.review.outputTokens&&now<c.review.validUntil,'REVIEW_LIMIT_OR_EXPIRY_INVALID');
 // This candidate deliberately uses the existing pure D06 quote function, never its ledger.
 // SYNTHETIC_QUOTED is required: these rates cannot masquerade as a reviewed LIVE price.
 const bound=quoteCost(c.price,{uncachedInput:1,cacheRead:1,cacheWrite:0,output:1,toolCalls:0},now);
 need(c.price.budgetCurrency==='RUB'&&money(bound)>0n,'PRICE_CURRENCY_OR_BOUND_INVALID');
 return c;
}
export const configHash=c=>hash(c);
