import assert from 'node:assert/strict';
import test from 'node:test';
import {digest} from '../../contracts/index.mjs';
import {createCodingGrantAuthority} from '../../host/coding/grant-authority.mjs';
import {createCodingMission} from '../../host/coding/mission.mjs';
import {CODING_PERMISSIONS, CODING_CONTRACT_VERSION_V2, PATCH_PROPOSAL_SCHEMA_DIGEST} from '../../executors/coding/contracts.mjs';

function fixture(verifyNativeClaim) {
  let clock = '2026-11-08T08:00:00.000Z';
  const repository = {owner:'example',name:'synthetic-g1'};
  const issueValue = {repository,issue_number:1,title:'QA authority boundary',body:'Synthetic static scope.'};
  const issue = {...issueValue,digest:digest(issueValue)}, profile = digest('offline test profile');
  const f = createCodingMission({run_id:'authority_races',issue,rubric:{checks:['schema','sources','scope']},now:clock,clock:()=>clock});
  const g = {contract_version:CODING_CONTRACT_VERSION_V2, grant_id:'g1_qa_race', owner_id:f.spec.owner_id,
    project_id:f.spec.project_id, mission_id:f.spec.mission_id, task_id:'code_r01', producer_id:'e1_worker', repository, issue_number:1,
    base_sha:'a'.repeat(40),issue_digest:issue.digest,branch_prefix:'codex/',path_allowlist:['cli.py','normalizer.py'],
    read_allowlist:['cli.py','normalizer.py'],test_profile_digest:profile,
    model_capability:{capability_id:'e1.coding.patch',version:'1.0.0',route_id:'ollama.local.qwen3-4b-instruct',output_schema_digest:PATCH_PROPOSAL_SCHEMA_DIGEST},
    test_capabilities:[{capability_id:'e1.coding.public-tests',version:'1.0.0',command_digest:profile,timeout_ms:20000}],
    issued_at:clock,expires_at:f.spec.deadline,budget:{currency:'NONE',amount_micros:0},max_steps:16,max_files:2,max_model_attempts:1,max_patch_bytes:32768,permissions:[...CODING_PERMISSIONS]};
  const policy = {schema:'awe.e1.coding-host-policy/1',repository,issue_digest:issue.digest,base_sha:g.base_sha,path_allowlist:[...g.path_allowlist],read_allowlist:[...g.read_allowlist],test_profile_digest:profile,owner_grant_digest:digest(f.grant),model_capability_id:'e1.coding.patch'};
  const auth = createCodingGrantAuthority({authority:f.authority,spec:f.spec,ownerGrant:f.grant,policy,verifyNativeClaim,clock:()=>clock});
  return {...f,auth,policy,g,expire:()=>{clock='2026-11-09T08:00:00.000Z';}};
}

for (const race of ['revoke grant','revoke principal','expire']) {
  test('authority denies ' + race + ' while native verifier is awaiting its result', async () => {
    let checked, release;
    const started = new Promise(resolve => { checked=resolve; });
    const f = fixture(async () => {checked(); return new Promise(resolve=>{release=resolve;});});
    const ref = f.auth.issue(f.g,f.contexts.owner);
    const pending = f.auth.resolve(ref,f.contexts.executor);
    await started;
    if (race === 'revoke grant') f.auth.revoke(ref,f.contexts.owner);
    else if (race === 'revoke principal') f.authority.revokePrincipal('e1_worker');
    else f.expire();
    release(true);
    assert.equal(await pending.catch(()=>null),null);
  });
}
test('mutation of constructor policy cannot issue grant for an alternate repository base', () => {
  const f = fixture(async()=>true);
  f.policy.base_sha = 'b'.repeat(40);
  assert.throws(()=>f.auth.issue({...f.g,base_sha:f.policy.base_sha},f.contexts.owner));
});
test('forged executor context is rejected before native checker, explicit stale result denied', async () => {
  let count=0;
  const f=fixture(async()=>{count++; return false;}),ref=f.auth.issue(f.g,f.contexts.owner);
  await assert.rejects(f.auth.resolve(ref,{...f.contexts.executor})); assert.equal(count,0);
  await assert.rejects(f.auth.resolve(ref,f.contexts.executor)); assert.equal(count,1);
});
