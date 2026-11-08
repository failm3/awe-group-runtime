export * from './contracts/index.mjs';
export * from './mission/ingress.mjs';
export * as infra from './infra/index.mjs';
export {buildManifest} from './release/build.mjs';

import {RELEASE,digest} from './contracts/index.mjs';
import {createMissionIngress} from './mission/ingress.mjs';
import {authorityPorts} from './mission/authority.mjs';
import {preflight,createReleaseManifest} from './infra/index.mjs';
import {buildManifest} from './release/build.mjs';

/** Contract/preflight composition only. D03/D09 dispatch binds in A2, after C1
 * live resource authorization. No runner, effect or acceptance port is exposed.
 */
export function createE1Composition({config,authority,capabilities,domainManifests,clock}){
 const host=preflight(config),auth=authorityPorts(authority);
 for(const [name,role] of [['owner','OWNER'],['coordinator','COORDINATOR'],['qa','QA']]){
  const principal=auth.lookup(config.principals[name].principal_id,host.project_id);
  if(principal.role!==role)throw new Error('E1_INFRA_PRINCIPAL_BINDING');
 }
 const ingress=createMissionIngress({authority,capabilities,domainManifests,clock,projectId:host.project_id});
 if(host.release!==RELEASE)throw new Error('E1_RELEASE_MISMATCH');
 const manifest=buildManifest();
 const registry_digest=digest(capabilities),policy_version='e1.preflight/1';
 const infrastructure_manifest=createReleaseManifest({config,build_digest:manifest.build_digest,registry_version:'e1.registry/1',policy_version});
 return Object.freeze({profile:'AWE_E1',release:RELEASE,manifest,infrastructure_manifest,
  mission:ingress.mission,plan:ingress.plan,snapshot:ingress.snapshot,history:ingress.history,
  health:()=>Object.freeze({profile:'AWE_E1',release:RELEASE,build_digest:manifest.build_digest,
   registry_digest,policy_version,manifest_digest:infrastructure_manifest.manifest_digest,
   state:'WAIT',ready:false,live_ready:false,accepted:false,external_effects:0,
   blockers:[...host.blockers,'DURABLE_COORDINATOR_NOT_BOUND'],
   evidence_level:'TESTED_OFFLINE'})});
}
