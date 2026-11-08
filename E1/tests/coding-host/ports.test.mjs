import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {digest, validateBoundValue} from '../../contracts/index.mjs';
import {validatePatchProposal, byteDigest, PATCH_PROPOSAL_SCHEMA, PATCH_PROPOSAL_SCHEMA_DIGEST} from '../../executors/coding/contracts.mjs';
import {MODEL_POLICY} from '../../broker/schemas.mjs';
import {createGitPort} from '../../host/coding/git-port.mjs';
import {createIssueReader} from '../../host/coding/issue-reader.mjs';
import {createRepositoryContext} from '../../host/coding/repository-context.mjs';
import {createAccountedPatchModelPort} from '../../host/coding/model-port.mjs';
import {completeCodingResult, rawPatchProposal} from '../../host/coding/coordinator-binding.mjs';
import {createLocalDraftIntentPublisher} from '../../host/coding/publisher-intent.mjs';

const repository = {owner: 'synthetic-owner', name: 'coding-port-fixture'};
const deadline = '2099-11-08T00:00:00.000Z';
const scope = {mission_id: 'mission_fixture', task_id: 'code', worker_id: 'worker', fence: 1, logical_request_id: 'request_fixture', attempt_id: 'attempt_fixture'};
function fixture(t) {
  const parent = path.resolve(os.tmpdir()), root = fs.mkdtempSync(path.join(parent, 'awe-coding-host-test-'));
  t.after(() => { const target = path.resolve(root); assert.ok(target.startsWith(parent + path.sep) && path.basename(target).startsWith('awe-coding-host-test-')); fs.rmSync(target, {recursive: true, force: true}); });
  const repo = path.join(root, 'repo'); fs.mkdirSync(repo);
  const env = Object.fromEntries(['SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP'].filter(k=>process.env[k]).map(k=>[k,process.env[k]]));
  const git = (args,cwd=repo) => execFileSync('git', ['-c','core.autocrlf=false','-c','user.name=AWE Port Fixture','-c','user.email=fixture@localhost.invalid',...args], {cwd,env,encoding:'utf8',windowsHide:true,stdio:['ignore','pipe','pipe']}).trim();
  git(['init','--initial-branch=main']); fs.writeFileSync(path.join(repo,'a.txt'),'before a\n'); fs.writeFileSync(path.join(repo,'b.txt'),'before b\n');
  git(['add','--','a.txt','b.txt']); git(['commit','-m','Non-candidate text fixture']);
  const base = git(['rev-parse','HEAD']), opts = {repositoryRoot:repo,worktreesRoot:path.join(root,'worktrees'),journalRoot:path.join(root,'journal'),repository,allowedPaths:['a.txt','b.txt']};
  const port = createGitPort(opts);
  return {root,repo,git,base,opts,port};
}
async function prepared(f) {
  const baseline = await f.port.inspectBase({repository,base_sha:f.base,paths:['a.txt','b.txt']});
  const proposal = {base_sha:f.base,summary:'Update fixture text only',changes:baseline.files.map((file,i)=>({path:file.path,before_digest:file.digest,after_text:`after ${i}\n`}))};
  const patch = validatePatchProposal(proposal,{grant:{base_sha:f.base,path_allowlist:['a.txt','b.txt'],max_files:2,max_patch_bytes:4096},baseline});
  const isolated = await f.port.createWorktree({repository,base_sha:f.base,branch:'codex/port-fixture',grant_ref:'owner-fixture',deadline});
  return {baseline,proposal,patch,isolated,request:{worktree_id:isolated.worktree_id,base_sha:f.base,patch,grant_ref:'owner-fixture',deadline}};
}
test('actual Git port applies two files, verifies blobs and preserves original branch',async t=>{
  const f=fixture(t),p=await prepared(f); await f.port.applyPatch(p.request);
  const r=await f.port.readback({worktree_id:p.isolated.worktree_id,base_sha:f.base});
  assert.equal(r.files.length,2); assert.match(r.tree_sha,/^[a-f0-9]{40}$/); assert.notEqual(r.head_sha,f.base);
  for(const file of r.files){assert.match(file.blob_sha,/^[a-f0-9]{40}$/);assert.equal(file.digest,byteDigest(file.content_utf8));}
  assert.equal(f.git(['rev-parse','HEAD']),f.base);assert.equal(f.git(['status','--porcelain']),'');assert.equal(fs.readFileSync(path.join(f.repo,'a.txt'),'utf8'),'before a\n');
});
test('actual Git before mismatch rejects the complete multi-file operation',async t=>{
  const f=fixture(t),p=await prepared(f);const bad=structuredClone(p.patch);bad.changes[1].before_digest='sha256:'+'0'.repeat(64);const {patch_digest,...payload}=bad;bad.patch_digest=digest(payload);
  await assert.rejects(f.port.applyPatch({...p.request,patch:bad}),/CODING_GIT_BEFORE_DIGEST/);
  const r=f.port.resolveWorktree(p.isolated.worktree_id);assert.equal(r.head_sha,f.base);assert.equal(r.files.length,0);
});
test('journal resumes after first file rename without exposing a partial committed result',async t=>{
  const f=fixture(t),p=await prepared(f);let crashed=false;
  const faulty=createGitPort({...f.opts,faultInjector(point,{index}={}){if(point==='AFTER_FILE_RENAME'&&index===0&&!crashed){crashed=true;throw Error('INJECTED_CRASH');}}});
  await assert.rejects(faulty.applyPatch(p.request),/INJECTED_CRASH/);
  assert.throws(()=>faulty.resolveWorktree(p.isolated.worktree_id),/CODING_GIT_DIRTY_READBACK/);
  const restored=createGitPort(f.opts);await restored.applyPatch(p.request);const r=await restored.readback({worktree_id:p.isolated.worktree_id,base_sha:f.base});assert.equal(r.files.length,2);assert.equal(f.git(['rev-list','--count',f.base+'..'+r.head_sha]),'1');
});
test('journal reconciles commit-before-ACK without a duplicate commit',async t=>{
  const f=fixture(t),p=await prepared(f);const faulty=createGitPort({...f.opts,faultInjector(point){if(point==='AFTER_COMMIT_BEFORE_ACK')throw Error('INJECTED_ACK_LOSS');}});
  await assert.rejects(faulty.applyPatch(p.request),/INJECTED_ACK_LOSS/);const head=f.git(['rev-parse','codex/port-fixture']);
  const repeat=await createGitPort(f.opts).applyPatch(p.request);assert.equal(repeat.repeated,true);assert.equal(repeat.head_sha,head);assert.equal(f.git(['rev-list','--count',f.base+'..'+head]),'1');
});
test('actual Git port refuses unplanned mutation during interrupted application',async t=>{
  const f=fixture(t),p=await prepared(f);const r=f.port.resolveWorktree(p.isolated.worktree_id);fs.writeFileSync(path.join(r.root,'foreign.txt'),'unplanned');
  await assert.rejects(f.port.applyPatch(p.request),/CODING_GIT_PRE_APPLY_DIRTY/);assert.equal(f.git(['rev-parse','HEAD'],r.root),f.base);
});
test('actual hardlinked file is rejected before model context is read',async t=>{
  const f=fixture(t);fs.linkSync(path.join(f.repo,'a.txt'),path.join(f.root,'outside.txt'));
  await assert.rejects(f.port.inspectBase({repository,base_sha:f.base,paths:['a.txt','b.txt']}),/CODING_GIT_HARDLINK_OR_TYPE/);
});
test('actual remote configuration disqualifies a disposable Git repository',t=>{
  const f=fixture(t);f.git(['remote','add','origin','https://example.invalid/never-accessed']);assert.throws(()=>createGitPort(f.opts),/CODING_GIT_BASE_NOT_DISPOSABLE_CLEAN/);
});
test('snapshot digest pins approved content and rejects caller issue substitution',async()=>{
  const snapshot={repository,issue_number:1,title:'Synthetic fixture',body:'Update only text fixtures.'};const reader=createIssueReader({snapshot,expectedDigest:digest(snapshot)});
  assert.equal((await reader.readIssue({repository,issue_number:1})).digest,digest(snapshot));await assert.rejects(reader.readIssue({repository,issue_number:2}),/CODING_ISSUE_SCOPE/);
  snapshot.body='Changed after approval';await assert.rejects(reader.readIssue({repository,issue_number:1}),/CODING_BRIEF_CHANGED/);
});
test('bounded repository context rejects stale bytes and oversize input',()=>{
  const builder=createRepositoryContext();const baseline={base_sha:'a'.repeat(40),files:[{path:'a.txt',kind:'file',content_utf8:'small',digest:byteDigest('small'),ancestry_verified:true,ancestor_symlinks:false}]};
  assert.match(builder.build({issue:{title:'fixture',body:'small',digest:digest({})},baseline}).instruction,/small/);
  baseline.files[0].content_utf8='substitute';assert.throws(()=>builder.build({issue:{title:'fixture',body:'small'},baseline}),/CODING_CONTEXT_BYTES/);
  baseline.files[0].content_utf8='small';assert.throws(()=>builder.build({issue:{title:'fixture',body:'x'.repeat(8192)},baseline}),/CODING_CONTEXT_TOO_LARGE/);
});
function modelFixture(options={}) {
  // Labelled test double for adapter validation, NOT an AWE runtime proof.
  const proposal={base_sha:'a'.repeat(40),summary:'Fixture only',changes:[{path:'a.txt',before_digest:byteDigest('x'),after_text:'y'}]};
  const response={decision:'PROPOSED',accounting_status:'CONFIRMED',evidence_level:'LIVE_LOCAL_MODEL',wire_attempts:1,output:proposal,usage:{input_tokens:1,output_tokens:2},request_hash:digest({fixture:true}),model:{id:MODEL_POLICY.model,digest:MODEL_POLICY.digest}};
  const native={...scope,route_id:MODEL_POLICY.route_id,state:'CONFIRMED',actual_cost:0,usage:response.usage,request_hash:response.request_hash};let calls=0;
  if(options.response)Object.assign(response,options.response);if(options.native)Object.assign(native,options.native);
  const port=createAccountedPatchModelPort({broker:{async invoke(){calls++;return response;}},spec:{},grant:{},verifyNativeAttempt:async()=>native,contextBuilder:{build:()=>({instruction:'fixture',context_digest:digest({})})}});
  const request={attempt_scope:scope,issue:{},baseline:{},output_schema_digest:PATCH_PROPOSAL_SCHEMA_DIGEST,max_attempts:1,budget_cap_micros:0};
  return {port,request,response,native,calls:()=>calls};
}
test('model adapter preserves inner provider evidence and verifies native row',async()=>{
  const f=modelFixture(),r=await f.port.proposePatch(f.request);assert.equal(r.evidence_level,'LIVE_SCOPED_HOST');assert.equal(r.native_receipt.response.evidence_level,'LIVE_LOCAL_MODEL');assert.equal(r.host_binding_digest,digest(r.native_receipt));assert.equal(f.calls(),1);
});
test('model adapter rejects native route, usage, fence and request substitution',async()=>{
  for(const native of [{route_id:'unapproved'},{usage:{input_tokens:8,output_tokens:9}},{fence:2},{request_hash:digest({other:true})},{actual_cost:1}]){const f=modelFixture({native});await assert.rejects(f.port.proposePatch(f.request),/CODING_NATIVE_MODEL_RECEIPT/);assert.equal(f.calls(),1);assert.ok(f.port.lastReceipt);}
});
test('UNKNOWN model outcome is preserved with native reference and no fallback',async()=>{
  const f=modelFixture({response:{decision:'WAIT',reason:'A3_OUTCOME_UNKNOWN',accounting_status:'UNKNOWN',wire_attempts:1},native:{state:'OUTCOME_UNKNOWN'}});const r=await f.port.proposePatch(f.request);assert.equal(r.accounting_status,'UNKNOWN');assert.equal(r.native_receipt.native_attempt.attempt_id,scope.attempt_id);assert.equal(f.calls(),1);
});
test('native completion stores raw schema-shaped patch and enriched evidence separately',async()=>{
  const proposal={base_sha:'a'.repeat(40),summary:'fixture',changes:[{path:'a.txt',before_digest:byteDigest('x'),after_text:'y'}]};const patch={...proposal,changes:proposal.changes.map(c=>({...c,after_digest:byteDigest(c.after_text)})),patch_bytes:1,patch_digest:digest({fixture:true})};const artifact={patch,artifact_digest:digest({artifact:true})};let saved;
  const r=await completeCodingResult({async complete(value){saved=value;return {status:'WAIT_QA'};}},scope,{proposal,artifact,model_receipt:{test_double:true}});
  validateBoundValue(PATCH_PROPOSAL_SCHEMA,saved.result.output);assert.equal(saved.result.output.patch_bytes,undefined);assert.equal(saved.result.evidence.coding_artifact.patch.patch_bytes,1);assert.equal(r.result_hash,digest(saved.result));assert.deepEqual(rawPatchProposal(patch),proposal);
});
test('local draft publisher persists idempotently and denies automatic merge',async t=>{
  const f=fixture(t),publisher=createLocalDraftIntentPublisher({directory:path.join(f.root,'intents')});const qa={verdict:'PASS'},intent={draft:true,automatic_merge:false,production_release:false,qa_digest:digest(qa)};
  const request={intent,intent_digest:digest(intent),qa};assert.equal((await publisher.prepareDraftIntent(request)).status,'DRAFT_PR_INTENT');await publisher.prepareDraftIntent(request);assert.equal(fs.readdirSync(path.join(f.root,'intents')).length,1);
  intent.automatic_merge=true;await assert.rejects(publisher.prepareDraftIntent({intent,intent_digest:digest(intent),qa}),/CODING_INTENT_SCOPE/);
});
