import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createE1Composition,createOfflineAuthority,contractSchema,CONTRACT_TYPES,infra} from './index.mjs';
import {createMissionFixture} from './examples/fixtures.mjs';

const read=filename=>{const bytes=readFileSync(filename);if(bytes.length>65536)throw new Error('E1_CLI_INPUT_TOO_LARGE');return JSON.parse(bytes);};
const template=()=>readFileSync(new URL('./infra/templates/awe-e1.offline.json',import.meta.url),'utf8');
export function exampleConfig(projectId,namespace='awe_e1_examples'){
 const config=JSON.parse(template());config.project_id=projectId;config.namespace=namespace;config.database.name=namespace;
 return infra.withLocalRoot(config,join(infra.LOCAL_ROOT,namespace));
}
/** Same bounded contract pipeline for fixture and supplied data. The host/opaque
 * contexts come from trusted local bootstrap, never from an untrusted payload.
 */
export function prepareMission(host,{spec,grant,plan},contexts){
 const created=host.mission.create({spec,grant},contexts.owner);
 const proposed=host.plan.propose({plan},contexts.head);
 const validated=host.plan.validate({mission_id:spec.mission_id,plan_digest:proposed.plan.digest},contexts.coordinator);
 const published=host.plan.publish({mission_id:spec.mission_id,plan_digest:proposed.plan.digest,validation_digest:validated.validation.digest},contexts.coordinator);
 return {profile:host.profile,release:host.release,build_digest:host.manifest.build_digest,
  project_id:spec.project_id,domain_manifest_digest:spec.domain_manifest.digest,
  spec_digest:created.spec.digest,grant_digest:created.grant.digest,plan_digest:published.plan_digest,
  decision:published.decision,task_count:plan.tasks.length,accepted:false,execution_authorized:false,external_effects:0,
  health:host.health()};
}
export function examples(){return ['A','B'].map(kind=>{
 const fixture=createMissionFixture(kind),host=createE1Composition({config:exampleConfig(fixture.spec.project_id),authority:fixture.authority,capabilities:fixture.capabilities,domainManifests:[fixture.domain_manifest],clock:fixture.clock});
 return {example:kind,clock_kind:'FIXED_SYNTHETIC_FIXTURE',...prepareMission(host,fixture,fixture.contexts)};
});}
export async function main(args=process.argv.slice(2)){
 const [command,...rest]=args;
 if(command==='examples'&&rest.length===0){for(const record of examples())console.log(JSON.stringify(record));return;}
 if(command==='preflight'&&rest.length<=1){
  const config=rest.length?infra.loadInfraConfig(rest[0]):exampleConfig('prj_e1_career');console.log(JSON.stringify(infra.preflight(config)));return;
 }
 if(command==='schema'&&rest.length===1&&CONTRACT_TYPES.includes(rest[0])){console.log(JSON.stringify(contractSchema(rest[0]),null,2));return;}
 if(command==='prepare'&&rest.length===3){
  // Local CLI/bootstrap is an administrator boundary, not remote AuthN. No live
  // identity, principal enrollment, credential or effects are established here.
  const bundle=read(rest[0]),bootstrap=read(rest[1]),config=infra.loadInfraConfig(rest[2]);
  if(Object.keys(bundle).sort().join(',')!=='grant,plan,spec'||Object.keys(bootstrap).sort().join(',')!=='actors,capabilities,domainManifests,principals'||Object.keys(bootstrap.actors).sort().join(',')!=='coordinator,head,owner')throw new Error('E1_CLI_BUNDLE_SHAPE');
  const authority=createOfflineAuthority(bootstrap.principals),contexts=Object.fromEntries(['owner','head','coordinator'].map(role=>[role,authority.issueContext(bootstrap.actors[role],config.project_id)]));
  const host=createE1Composition({config,authority,capabilities:bootstrap.capabilities,domainManifests:bootstrap.domainManifests,clock:()=>new Date().toISOString()});
  console.log(JSON.stringify(prepareMission(host,bundle,contexts)));return;
 }
 throw new Error('USAGE: node E1/cli.mjs examples | preflight [config.json] | schema <ContractType> | prepare <mission.json> <trusted-bootstrap.json> <infra-config.json>');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 main().catch(error=>{console.error(JSON.stringify({decision:error.disposition??'REJECT',code:/^(?:E1_|C1_)/.test(error.code??error.message)?error.code??error.message:'E1_CLI_INPUT_REJECTED'}));process.exitCode=1;});
}
