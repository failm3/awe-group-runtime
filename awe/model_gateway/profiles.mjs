import {canonicalize, digest} from '../../contracts/canonical.mjs';
import {requireThat as need, integer, quoteCost, money} from '../budget/money.mjs';
export const copy = x => JSON.parse(canonicalize(x));
export const hash = x => digest(x);
export const OWNER = 'D06_RouteBroker';
export function validateProfile(raw) {
  const p=copy(raw);
  need(p.version==='LLM01_MODEL_V1' && p.physicalDecision==='DENY','PROFILE_VERSION');
  for(const k of ['id','provider','modelId','alias','source','policyHash','routeHash'])need(typeof p[k]==='string' && p[k].length>0,'PROFILE_PIN_REQUIRED');
  for(const k of ['policyHash','routeHash'])need(/^sha256:[a-f0-9]{64}$/.test(p[k]),'PROFILE_HASH_INVALID');
  need(p.mode==='SYNTHETIC_ONLY' && p.evidence==='SYNTHETIC' && p.eligible===true,'LIVE_PROFILE_DISABLED');
  need(p.retryOwner===OWNER && p.sdkRetries===0 && p.gatewayRetries===0 && p.hermesRetries===0,'RETRY_OWNER_CONFLICT');
  for(const k of ['contextTokens','outputTokens','validUntil'])integer(p[k]);
  need(p.contextTokens>=p.outputTokens && p.outputTokens>0,'PROFILE_CONTEXT_INVALID');
  need(p.schemaDialect==='D06_FLAT_V1','SCHEMA_DIALECT_UNSUPPORTED');
  need(Object.keys(p.features).sort().join()==='json,stream,tools' && Object.values(p.features).every(x=>typeof x==='boolean'),'PROFILE_CAPABILITY_INVALID');
  need(p.quality && Number.isSafeInteger(p.quality.lowerBoundBps) && p.quality.lowerBoundBps>=0 && p.quality.lowerBoundBps<=10000
    && Number.isSafeInteger(p.quality.reliabilityBps) && p.quality.reliabilityBps>=0 && p.quality.reliabilityBps<=10000,'QUALITY_EVIDENCE_INVALID');
  money(p.quality.acceptedCostMicros);
  return p;
}
// This is a fixture constructor, never a promotion path for vendor claims.
export function syntheticProfile(route, {quality={lowerBoundBps:8000,reliabilityBps:9900,acceptedCostMicros:'100'},validUntil=8000}={}) {
  return validateProfile({version:'LLM01_MODEL_V1',id:'profile-'+route.id,provider:route.provider,modelId:route.modelId,alias:route.alias,
    mode:'SYNTHETIC_ONLY',evidence:'SYNTHETIC',eligible:true,physicalDecision:'DENY',source:'LOCAL_SYNTHETIC_FIXTURE',
    policyHash:hash({privacy:route.privacy,upstreamPrivacy:route.upstreamPrivacy,region:route.region,upstreamRegion:route.upstreamRegion}),
    routeHash:hash(route),contextTokens:route.capabilities.contextTokens,outputTokens:route.capabilities.outputTokens,
    features:Object.fromEntries(['json','stream','tools'].map(k=>[k,route.capabilities[k]])),schemaDialect:'D06_FLAT_V1',
    retryOwner:OWNER,sdkRetries:0,gatewayRetries:0,hermesRetries:0,quality,validUntil});
}
export function rankRoutes({profiles,routes,request,now}) {
  integer(now);const accepted=[],rejected=[];
  for(const raw of profiles) {
    try {
      const p=validateProfile(raw),r=routes.find(x=>hash(x)===p.routeHash);
      need(r && r.modelId===p.modelId && r.provider===p.provider && r.alias===p.alias,'PROFILE_ROUTE_MISMATCH');
      need(p.contextTokens===r.capabilities.contextTokens && p.outputTokens===r.capabilities.outputTokens
        && Object.keys(p.features).every(k=>p.features[k]===r.capabilities[k]),'PROFILE_CAPABILITY_MISMATCH');
      need(request.allowedRoutes.includes(r.id) && request.alias===p.alias && request.modelPins[r.id]===p.modelId,'MODEL_PIN_MISMATCH');
      need(now<p.validUntil,'PROFILE_STALE');
      need(request.bounds.uncachedInput+request.bounds.cacheRead+request.bounds.cacheWrite+request.bounds.output<=p.contextTokens
        && request.bounds.output<=p.outputTokens,'CONTEXT_OR_OUTPUT_LIMIT');
      for(const k of ['tools','stream','json'])need(!request.features[k]||p.features[k],'CAPABILITY_UNSUPPORTED');
      const boundMicros=quoteCost(r.price,request.bounds,now);
      accepted.push({p,r,boundMicros});
    } catch(e) {rejected.push({profileId:raw?.id??null,code:e.code??'INVALID_PROFILE'});}
  }
  // Hard eligibility/capability gates first. Quality lower bound, reliability, accepted-result cost; never token price alone.
  accepted.sort((a,b)=>b.p.quality.lowerBoundBps-a.p.quality.lowerBoundBps || b.p.quality.reliabilityBps-a.p.quality.reliabilityBps
    || (money(a.p.quality.acceptedCostMicros)<money(b.p.quality.acceptedCostMicros)?-1:money(a.p.quality.acceptedCostMicros)>money(b.p.quality.acceptedCostMicros)?1:0)
    || a.r.id.localeCompare(b.r.id));
  need(accepted.length>0,rejected[0]?.code??'NO_QUALIFIED_ROUTE');
  return {accepted,rejected};
}
export function chooseRoute(input) {
  const {accepted,rejected}=rankRoutes(input);return {...accepted[0],rejected};
}
