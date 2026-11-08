// Mission-control submission probe against the existing E1 A1 entrypoint.
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {exampleConfig, prepareMission} from '../cli.mjs';
import {createE1Composition} from '../index.mjs';
import {digest} from '../contracts/index.mjs';
import {createMissionFixture} from '../examples/fixtures.mjs';

const bytes = readFileSync(new URL('./ORACLE.json', import.meta.url));
const oracle = JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/, ''));
const oracleSha = createHash('sha256').update(bytes).digest('hex');
const fixture = createMissionFixture('A');
const {spec, grant, plan, contexts} = fixture;
const missionId = oracle.mission.toLowerCase();
spec.mission_id = grant.mission_id = plan.mission_id = missionId;
spec.goal = oracle.goal;
spec.criteria[0].text = 'Produce five distinct current ranked listings with joined source and synthetic fact evidence, five tied drafts and zero sends.';
spec.criteria[1].text = 'Independent QA applies the frozen SANDBOX-RECRUIT-01 oracle at SHA-256 ' + oracleSha;
const facts = {fictional: true, source: oracle.synthetic_input.applicant, confirmed_claims: oracle.synthetic_input.facts.map(fact => fact.claim)};
const factRef = spec.facts_refs[0];
factRef.mission_id = missionId;
factRef.digest = digest(facts);
factRef.uri = 'artifact:sandbox-recruit/facts';
grant.spec_digest = plan.spec_digest = digest(spec);
plan.grant_digest = digest(grant);
for (const task of plan.tasks) {
  task.effect.mission_id = missionId;
  task.origin.source_digests = [factRef.digest];
}
const host = createE1Composition({
  config: exampleConfig(spec.project_id),
  authority: fixture.authority,
  capabilities: fixture.capabilities,
  domainManifests: [fixture.domain_manifest],
  clock: fixture.clock,
});
const result = prepareMission(host, {spec, grant, plan}, contexts);
console.log(JSON.stringify({
  cycle: 0, observed_at: new Date().toISOString(), mission: oracle.mission,
  oracle_sha256: oracleSha, probe_authority: 'SYNTHETIC_PROCESS_LOCAL', clock: 'FIXED_FIXTURE',
  mission_id: missionId, runtime_entry: 'E1/cli.mjs#prepareMission',
  project_id: result.project_id, release: result.release, build_digest: result.build_digest,
  spec_digest: result.spec_digest, grant_digest: result.grant_digest, plan_digest: result.plan_digest,
  a1: result.decision, execution_authorized: result.execution_authorized, accepted: result.accepted,
  external_effects: result.external_effects, a2_admission: 'NOT_ATTEMPTED_NO_RECRUIT_HOST_ENTRYPOINT_AT_BASE',
  a3_dispatch: 'NOT_RUN', network: 'QA3_OFFLINE_GUARD', actual_model_requests: 0,
  mission_outcome: 'BLOCKED_AT_PREFLIGHT',
}, null, 2));

