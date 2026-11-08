import {deny,freeze} from './protocol.mjs';
// Reviewed mapping target, NOT Hermes wire compatibility. Empty allowed_toolsets
// in the installed lifecycle API inherits parent tools, so it cannot implement DENY.
export const nativeBinding=freeze({hermes_commit:'7058601bf5cdc35502676a9b8aec0480e7e80127',contract_version:1,
 interface:'PluginContext.subagent_lifecycle',methods:{launchChild:'launch(SubagentLaunchRequest)',streamEvents:'status/result polling (no native stream)',
 cancel:'cancel(reason) + wait/result proof',join:'wait(timeout_seconds) + result',checkpoint:'AWE/D09 checkpoint; no native checkpoint',reconcile:'reconnect(handle) (same process only)'},
 required_changes:['TR01 proposal-only nonempty toolset and exact parent tool allowlist','LLM01 broker with pinned model revision and all retry/fallback layers disabled',
 'SEC01 isolated OS process principal and egress','D09 durable parent-child issuer lineage','D05/D07 context projection','D08 independent result verification'],
 unsupported:['cross-process native child recovery','native durable checkpoint','native empty-toolset deny','native project identity authority','native model revision attestation']});
export function createNativeHermesTransport(){return Object.freeze({mode:'REAL_HERMES_BLOCKED',launchChild:()=>deny('REAL_HERMES_NOT_RUN'),
 streamEvents:()=>deny('REAL_HERMES_NOT_RUN'),cancel:()=>deny('REAL_HERMES_NOT_RUN'),join:()=>deny('REAL_HERMES_NOT_RUN'),checkpoint:()=>deny('REAL_HERMES_NOT_RUN'),reconcile:()=>deny('REAL_HERMES_NOT_RUN')});}
