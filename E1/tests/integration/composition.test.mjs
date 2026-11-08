import test from 'node:test';
import assert from 'node:assert/strict';
import {createE1Composition,buildManifest,digest} from '../../index.mjs';
import {createMissionFixture} from '../../examples/fixtures.mjs';
import {exampleConfig,prepareMission,examples} from '../../cli.mjs';

const hostFor=fixture=>createE1Composition({config:exampleConfig(fixture.spec.project_id),authority:fixture.authority,capabilities:fixture.capabilities,domainManifests:[fixture.domain_manifest],clock:fixture.clock});
test('one ordinary contract composition validates independent A/B DAGs on the same build',()=>{
 const outcomes=['A','B'].map(kind=>{const f=createMissionFixture(kind),host=hostFor(f);return {f,host,result:prepareMission(host,f,f.contexts)};});
 assert.notEqual(outcomes[0].f.spec.project_id,outcomes[1].f.spec.project_id);
 assert.notEqual(outcomes[0].result.domain_manifest_digest,outcomes[1].result.domain_manifest_digest);
 assert.equal(outcomes[0].result.build_digest,outcomes[1].result.build_digest);
 for(const {f,host,result} of outcomes){
  assert.equal(result.decision,'PUBLISHED_PREFLIGHT_ONLY');assert.equal(result.accepted,false);assert.equal(result.execution_authorized,false);assert.equal(result.external_effects,0);
  assert(f.plan.tasks.some(t=>t.depends_on.length===2));assert.equal(host.health().state,'WAIT');assert.equal(host.health().ready,false);
  assert.equal(host.snapshot(f.contexts.owner).missions[0].published_digest,result.plan_digest);
  assert.equal('dispatch' in host,false);assert.equal('accept' in host,false);
 }
});
test('C1 namespace project fences the A1 ordinary ingress',()=>{
 const f=createMissionFixture('B');
 assert.throws(()=>{const host=createE1Composition({config:exampleConfig('prj_e1_career'),authority:f.authority,capabilities:f.capabilities,domainManifests:[f.domain_manifest],clock:f.clock});host.mission.create({spec:f.spec,grant:f.grant},f.contexts.owner);});
});
test('plain JSON actor cannot enter composition; frozen authority context is required',()=>{
 const f=createMissionFixture('A'),host=hostFor(f);
 assert.throws(()=>host.mission.create({spec:f.spec,grant:f.grant},{principal_id:f.spec.owner_id,project_id:f.spec.project_id}));
});
test('malformed E0 database config is rejected before creating any mission',()=>{
 const f=createMissionFixture('A'),config=structuredClone(exampleConfig(f.spec.project_id));config.database.name='g102c_authority';
 assert.throws(()=>createE1Composition({config,authority:f.authority,capabilities:f.capabilities,domainManifests:[f.domain_manifest],clock:f.clock}),{code:'C1_DATABASE_DENIED'});
});
test('C1 declared QA identity cannot be silently replaced at A1 composition',()=>{
 const f=createMissionFixture('A'),config=structuredClone(exampleConfig(f.spec.project_id));config.principals.qa.principal_id='id_e1_unenrolled_qa';
 assert.throws(()=>createE1Composition({config,authority:f.authority,capabilities:f.capabilities,domainManifests:[f.domain_manifest],clock:f.clock}));
});
test('grants cannot authorize unknown effects through the normal pipeline',()=>{
 const f=createMissionFixture('A'),host=hostFor(f);f.plan.tasks[0].effect.outcome='OUTCOME_UNKNOWN';
 assert.throws(()=>prepareMission(host,f,f.contexts),{code:'E1_RECONCILIATION_REQUIRED'});
 assert.equal(host.snapshot(f.contexts.owner).missions[0].published_digest,null);
});
test('author can neither publish an unvalidated proposal nor inject acceptance',()=>{
 const f=createMissionFixture('A'),host=hostFor(f);host.mission.create({spec:f.spec,grant:f.grant},f.contexts.owner);const p=host.plan.propose({plan:f.plan},f.contexts.head);
 assert.throws(()=>host.plan.publish({mission_id:f.spec.mission_id,plan_digest:p.plan.digest,validation_digest:'sha256:'+'0'.repeat(64)},f.contexts.coordinator));
 const other=createMissionFixture('B'),request={spec:other.spec,grant:other.grant,accepted:true};assert.throws(()=>hostFor(other).mission.create(request,other.contexts.owner));
});
test('CLI examples expose fixed fixture evidence and no secret/body state in health',()=>{
 const records=examples();assert.equal(records.length,2);for(const record of records){
  assert.equal(record.clock_kind,'FIXED_SYNTHETIC_FIXTURE');assert.equal(record.health.live_ready,false);
  for(const key of ['goal','facts','grant','token','password','private_key','receipts'])assert.equal(key in record.health,false);
 }
});
test('build manifest binds current source bytes and remains immutable',()=>{
 const manifest=buildManifest();const {build_digest,...payload}=manifest;assert.equal(build_digest,digest(payload));
 assert(Object.isFrozen(manifest.files));assert(manifest.files.some(f=>f.path==='awe/project_factory/factory.mjs'));
 assert(!manifest.files.some(f=>f.path.includes('/.local/')||f.path.includes('/.reference/')||f.path.includes('private-metadata')));
 assert.throws(()=>{manifest.files[0].digest='sha256:'+'0'.repeat(64);},TypeError);
});
