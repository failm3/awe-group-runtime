// Documentation observations as of 2026-11-05. NOT account quotes or runtime eligibility.
// Integer USD micros per million tokens; null = UNKNOWN, never free. These cannot pass validateProfile().
const observed=(id,provider,modelId,source,contextTokens,outputTokens,inputMicros,outputMicros,extra={})=>Object.freeze({
  version:'LLM01_DOCUMENTED_MODEL_V1',id,provider,modelId,source,verifiedDate:'2026-11-05',evidence:'DOCUMENTATION',
  mode:'DISABLED',physicalDecision:'DENY',eligible:false,contextTokens,outputTokens,
  usdMicrosPerMillion:{input:inputMicros,output:outputMicros},accountEligibility:'UNKNOWN',snapshotVerification:'NOT_RUN',
  quality:'LIVE_BENCH_NOT_RUN',...extra});
export const DOCUMENTED_MODELS=Object.freeze([
  observed('rc-sol','router.cheap','gpt-6.1-sol','https://router.cheap/openai-compatible-api',null,null,null,null,{modelEvidence:'LOCAL_CONFIG_ALIAS_ONLY',upstreamIdentity:'UNKNOWN',protocols:['chat/completions','responses']}),
  observed('or-sol','OpenRouter','openai/gpt-6.1-sol','https://openrouter.ai/openai/gpt-6.1-sol',null,null,null,null,{modelEvidence:'PUBLIC_PAGE_TITLE_ONLY',upstreamIdentity:'UNKNOWN',protocols:['chat/completions','responses']}),
  observed('or-sonnet','OpenRouter','anthropic/claude-sonnet-5.5','https://openrouter.ai/anthropic/claude-sonnet-5.5',null,null,null,null,{modelEvidence:'PUBLIC_PAGE_TITLE_ONLY',upstreamIdentity:'UNKNOWN',protocols:['chat/completions','responses']}),
  observed('direct-sol','OpenAI','gpt-6.1-sol','https://developers.openai.com/api/docs/models/gpt-6.1-sol',1050000,128000,'2000000','10000000',{cachedInputMicros:'100000',pricingTier:'STANDARD_SHORT_CONTEXT',protocols:['chat/completions','responses'],snapshotVerification:'ALIAS_ONLY_NO_DATED_SNAPSHOT_CONFIRMED'}),
  observed('direct-opus','Anthropic','claude-opus-5-5','https://platform.claude.com/docs/en/models/overview',1000000,128000,'4000000','20000000',{cachedInputMicros:'200000',cacheWrite5mMicros:'5000000',cacheWrite1hMicros:'8000000',protocols:['messages']}),
  observed('direct-sonnet','Anthropic','claude-sonnet-5-5','https://platform.claude.com/docs/en/models/overview',1000000,128000,'2000000','10000000',{cachedInputMicros:'100000',cacheWrite5mMicros:'2500000',cacheWrite1hMicros:'4000000',protocols:['messages']}),
  observed('direct-fable','Anthropic','claude-fable-5-1','https://platform.claude.com/docs/en/models/overview',1000000,128000,'10000000','50000000',{protocols:['messages']}),
  observed('direct-ds-flash','DeepSeek','deepseek-flash','https://api-docs.deepseek.com/quick_start/pricing/',1000000,384000,'300000','1200000',{publishedVersion:'DeepSeek-V4.1-Flash-1017',cachedInputMicros:'6000',pricingTier:'PEAK',offPeak:{input:'150000',output:'600000',cached:'3000'},protocols:['chat/completions','responses','messages']}),
  observed('direct-ds-pro','DeepSeek','deepseek-v4-pro','https://api-docs.deepseek.com/quick_start/pricing/',1000000,384000,'1320000','3960000',{publishedVersion:'DeepSeek-V4-Pro-0813',cachedInputMicros:'44000',pricingTier:'PEAK',offPeak:{input:'660000',output:'1980000',cached:'22000'},protocols:['chat/completions','responses','messages']})
]);
