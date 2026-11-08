import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../../contracts/index.mjs';
import {CODING_PERMISSIONS, PATCH_PROPOSAL_SCHEMA_DIGEST, byteDigest} from '../../executors/coding/contracts.mjs';
import {MODEL_POLICY} from '../../broker/schemas.mjs';
import {createCodingExecutor, createOfflineCodingExecutorForTests} from '../../executors/coding/executor.mjs';

const NOW='2026-11-08T00:00:00.000Z', base='a'.repeat(40), head='b'.repeat(40),tree='c'.repeat(40);
const repository={owner:'synthetic-owner',name:'contract-fixture'};
const scope={mission_id:'mission_fixture',task_id:'code',worker_id:'worker',attempt_id:'attempt_fixture',logical_request_id:'request_fixture',fence:1};
const cap={capability_id:'fixture.test',version:'1.0.0',command_digest:digest({command:'fixed test double'}),timeout_ms:1000};
// Entire fixture below is OFFLINE_TEST_DOUBLE; its success is not live proof.
function fixture(options={}) {
  const events=[], issue={repository,issue_number:1,title:'Text fixture',body:'Change only approved text.'};issue.digest=digest(issue);
  const grant={contract_version:'awe.e1.coding-executor/2',grant_id:'grant_fixture',owner_id:'owner',project_id:'project_fixture',mission_id:scope.mission_id,task_id:scope.task_id,producer_id:scope.worker_id,repository,issue_number:1,issue_digest:issue.digest,base_sha:base,branch_prefix:'codex/',path_allowlist:['a.txt'],read_allowlist:['a.txt'],test_profile_digest:digest({profile:'fixed'}),model_capability:{capability_id:'e1.coding.patch',version:'1.0.0',route_id:MODEL_POLICY.route_id,output_schema_digest:PATCH_PROPOSAL_SCHEMA_DIGEST},test_capabilities:[cap],budget:{currency:'NONE',amount_micros:0},issued_at:NOW,expires_at:'2026-11-09T00:00:00.000Z',max_steps:16,max_model_attempts:1,max_patch_bytes:4096,max_files:1,permissions:[...CODING_PERMISSIONS]};
  const proposal={base_sha:base,summary:'Fixture patch',changes:[{path:'a.txt',before_digest:byteDigest('before'),after_text:'after'}]};let revoked=false;
  const readback={isolated:true,clean:true,committed:true,base_sha:base,head_sha:head,tree_sha:tree,files:[{path:'a.txt',digest:byteDigest('after'),kind:'file',ancestor_symlinks:false}]};
  const ports={clock:()=>NOW,authority:{kind:'OWNER_TASK_GRANT_AUTHORITY',resolve:async()=>revoked?null:grant},
    githubReader:{kind:'SCOPED_GITHUB_ISSUE_READER',mode:'OFFLINE_TEST_DOUBLE',async readIssue(){events.push('issue');const value=structuredClone(issue);if(options.issueChange){value.body='Another self-consistently hashed issue';const {digest:d,...raw}=value;value.digest=digest(raw);}return value;}},
    modelPort:{kind:'ACCOUNTED_PATCH_MODEL_PORT',mode:'OFFLINE_TEST_DOUBLE',capability_id:'e1.coding.patch',route_id:MODEL_POLICY.route_id,async proposePatch(){events.push('model');if(options.revokeAfterModel)revoked=true;if(options.unknown)return {reason:'A3_OUTCOME_UNKNOWN',accounting_status:'UNKNOWN',wire_attempts:1,attempt_id:scope.attempt_id};if(options.truncated)return {decision:'REPAIR',reason:'A3_OUTPUT_TRUNCATED',accounting_status:'CONFIRMED',wire_attempts:1};return {proposal,accounting_status:'CONFIRMED',wire_attempts:1,route_id:MODEL_POLICY.route_id,attempt_id:scope.attempt_id,actual_cost_micros:0,usage:{input_tokens:1,output_tokens:1},model:{id:MODEL_POLICY.model,digest:MODEL_POLICY.digest},evidence_level:'OFFLINE_TEST_DOUBLE'};}},
    gitPort:{kind:'ISOLATED_GIT_WORKTREE_PORT',mode:'OFFLINE_TEST_DOUBLE',isolation:'ISOLATED_WORKTREE',async inspectBase(){events.push('base');return {base_sha:base,files:[{path:'a.txt',kind:'file',mode:'100644',content_utf8:'before',digest:byteDigest('before'),ancestry_verified:true,ancestor_symlinks:false}]};},async createWorktree(request){events.push('worktree');return {isolated:true,base_sha:base,branch:request.branch,worktree_id:'fixture'};},async applyPatch(request){events.push('apply');return {patch_digest:request.patch.patch_digest};},async readback(){events.push('readback');return readback;}},
    testRunner:{kind:'FIXED_SANDBOX_TEST_RUNNER',mode:'OFFLINE_TEST_DOUBLE',isolation:'ALLOWLISTED_OS_SANDBOX',network:'DENY',async run(request){events.push('test');return {capability_id:cap.capability_id,command_digest:cap.command_digest,sandbox_enforced:true,network:'DENY',exit_code:options.testFail?1:0,output_digest:digest({output:'fixture'}),timeout_ms:1000,tested_head_sha:request.expected_head_sha,tested_tree_sha:options.staleTree?'d'.repeat(40):request.expected_tree_sha,profile_digest:request.profile_digest,invocation_id:options.staleNonce?'old':request.invocation_id};}},
    lifecycle:{async persistArtifact(value){events.push('persist:'+value.product_status);},async recordOutcome(value){events.push('outcome:'+value.decision);}},
    qaPort:{kind:'INDEPENDENT_FROZEN_ARTIFACT_QA',mode:'OFFLINE_TEST_DOUBLE',principal_id:'qa',rubric_digest:digest({rubric:'fixture'}),async evaluate({artifact}){events.push('qa');return {artifact_digest:artifact.artifact_digest,rubric_digest:artifact.rubric_digest,evaluator_id:'qa',producer_id:'worker',verdict:'PASS',accepted:false};}},
    publisher:{kind:'SCOPED_DRAFT_PR_INTENT_PUBLISHER',mode:'OFFLINE_TEST_DOUBLE',async prepareDraftIntent({intent_digest}){events.push('intent');return {status:'DRAFT_PR_INTENT',intent_digest,external_mutations:0};}}
  };
  return {ports,grant,events,request:{grant_ref:'fixture',context:{},attempt_scope:scope},run:()=>createOfflineCodingExecutorForTests(ports,{label:'OFFLINE_TEST_DOUBLE'}).run({grant_ref:'fixture',context:{},attempt_scope:scope})};
}
test('v2 offline control binds tree and persists raw-capable artifact before QA',async()=>{
  const f=fixture(),result=await f.run();assert.equal(result.decision,'DRAFT_PR_INTENT');assert.equal(result.artifact.tree_sha,tree);assert.ok(f.events.indexOf('persist:PENDING_INDEPENDENT_QA')<f.events.indexOf('qa'));assert.equal(result.profile,'OFFLINE_TEST_DOUBLE');
});
test('v2 rejects self-hashed changed issue before model or Git mutation',async()=>{
  const f=fixture({issueChange:true}),result=await f.run();assert.equal(result.reason,'CODING_APPROVED_BRIEF_MISMATCH');assert.equal(f.events.includes('model'),false);assert.equal(f.events.includes('worktree'),false);
});
test('v2 rejects stale tree or reused test nonce before persistence/QA',async()=>{
  for(const option of [{staleTree:true},{staleNonce:true}]){const f=fixture(option),r=await f.run();assert.equal(r.reason,'CODING_STALE_TEST_RECEIPT');assert.equal(f.events.includes('qa'),false);assert.equal(f.events.some(e=>e.startsWith('persist:')),false);}
});
test('v2 retains UNKNOWN as HOLD with original attempt and no second invocation',async()=>{
  const f=fixture({unknown:true}),r=await f.run();assert.equal(r.decision,'HOLD');assert.equal(r.model_receipt.attempt_id,scope.attempt_id);assert.equal(f.events.filter(e=>e==='model').length,1);assert.equal(f.events.includes('worktree'),false);assert.ok(f.events.includes('outcome:HOLD'));
});
test('v2 confirmed truncation remains repair with receipt and no candidate changes',async()=>{
  const f=fixture({truncated:true}),r=await f.run();assert.equal(r.decision,'REPAIR');assert.equal(r.reason,'A3_OUTPUT_TRUNCATED');assert.equal(r.model_receipt.accounting_status,'CONFIRMED');assert.equal(f.events.includes('worktree'),false);
});
test('v2 failed producer tests persist failure, skip QA/publish and request no retry',async()=>{
  const f=fixture({testFail:true}),r=await f.run();assert.equal(r.decision,'REPAIR');assert.ok(f.events.includes('persist:PRODUCER_TEST_FAILED'));assert.equal(f.events.includes('qa'),false);assert.equal(f.events.includes('intent'),false);assert.equal(f.events.filter(e=>e==='model').length,1);
});
test('v2 revocation after model blocks first worktree mutation',async()=>{
  const f=fixture({revokeAfterModel:true}),r=await f.run();assert.equal(r.reason,'CODING_GRANT_CHANGED_OR_REVOKED');assert.equal(f.events.includes('worktree'),false);
});
test('public factory requires v2 grant and native lifecycle before model',async()=>{
  const f=fixture();for(const name of ['githubReader','modelPort','gitPort','testRunner','qaPort','publisher'])f.ports[name].mode='LIVE_SCOPED_HOST';
  f.grant.contract_version='awe.e1.coding-executor/1';delete f.grant.issue_digest;delete f.grant.read_allowlist;delete f.grant.test_profile_digest;
  const r=await createCodingExecutor(f.ports).run(f.request);assert.equal(r.reason,'CODING_LIVE_V2_GRANT_REQUIRED');assert.equal(f.events.includes('model'),false);
});
