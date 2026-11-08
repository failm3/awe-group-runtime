import test from 'node:test';
import assert from 'node:assert/strict';
import {compareStream,verifyProgramReceipt} from '../../qa-coding/oracle.mjs';
import {gitOid,treeFromFiles,diagnosticTree,sha256} from '../../qa-coding/tree-proof.mjs';
import {PROGRAM_PROFILE,PROGRAM_PROFILE_DIGEST,validateProgramRequest} from '../../host/program-runner/profiles.mjs';
import {digest} from '../../contracts/index.mjs';

const expected=[{id:'KEY',kind:'case'},{id:'k',kind:'x'}];
const output={stdout:'{"kind":"case","id":"KEY"}\n{"id":"k","kind":"x"}\n',stderr:'',exit_code:0};
test('external comparator accepts matching values with different key order',()=>assert.ok(compareStream(output,expected)));
for (const [name,overrides] of [
  ['fake PASS', {stdout:'PASS\n'}],['diagnostic stdout',{stdout:output.stdout+'OK\n'}],['diagnostic stderr',{stderr:'PASS'}],
  ['nonzero exit',{exit_code:7}],['truncated answer',{stdout:output.stdout.split('\n')[0]}],['swapped order',{stdout:'{"id":"k","kind":"x"}\n{"id":"KEY","kind":"case"}'}],
  ['extra property',{stdout:output.stdout.replace('"id":"KEY"','"id":"KEY","accepted":true')}],
]) test('external comparator rejects '+name,()=>assert.equal(compareStream({...output,...overrides},expected),false));

test('QA tree digest identifies each complete two-file revision and prevents blob/subtree substitution', () => {
  const files=[{path:'cli.py',mode:'100644',content_utf8:'# test stub\n'},{path:'normalizer.py',mode:'100644',content_utf8:'# base fixture only\n'}];
  const prior=treeFromFiles(files),derived=diagnosticTree(files,'a'.repeat(40),'probe');
  assert.equal(derived.tree_sha,prior); assert.equal(derived.projection,'probe');
  assert.notEqual(prior,treeFromFiles(files.map(f=>({...f,content_utf8:f.content_utf8+'\n'}))));
  assert.throws(()=>treeFromFiles([files[0],{...files[1],blob_sha:gitOid('blob','different')}]));
  assert.throws(()=>treeFromFiles([files[0],{...files[1],path:'qa.py'}]));
});

function attestation(){
  const request={files:[{path:'cli.py',content_utf8:'# stub'},{path:'normalizer.py',content_utf8:'# stub'}],stdin:'fixture',entrypoint:'cli.py',
    binding:{tested_head_sha:'b'.repeat(40),tested_tree_sha:'c'.repeat(40),invocation_id:'qa_test'}};
  const {source_files,source_digest,stdin_digest}=validateProgramRequest(request);
  const rawOutput={stdout:'PASS',stderr:'',exit_code:0,timed_out:false,output_truncated:false};
  const boundary=Object.fromEntries(['home_absent','windows_absent','repository_absent','private_absent','source_readonly','network_namespace','mount_namespace','pid_namespace','socket_denied','fork_denied','exec_denied','seccomp_enforced','no_new_privileges','tmpfs_bounded'].map(k=>[k,true]));
  const evidence={schema:'awe.e1.program-receipt/1',status:'EXECUTED',sandbox_enforced:true,network:'DENY',boundary,...rawOutput,
    ...request.binding,limits:PROGRAM_PROFILE.limits,profile_digest:PROGRAM_PROFILE_DIGEST,source_files,source_digest,stdin_digest,entrypoint:request.entrypoint,
    output_encoding_valid:true,stdout_bytes_digest:sha256(rawOutput.stdout),stderr_bytes_digest:sha256(rawOutput.stderr),output_digest:digest(rawOutput),toolchain:{platform:'linux-x86_64',bwrap_version:'test-only',python_version:'3.12.0',python_digest:sha256('fixture')}};
  return {request,evidence};
}
test('synthetic receipt is checked against trusted request; stdout cannot provide verdict',()=>{
  const {request,evidence}=attestation();
  const receipt={...evidence,receipt_digest:digest(evidence)};
  verifyProgramReceipt(receipt,request,PROGRAM_PROFILE_DIGEST);
  assert.equal(compareStream(receipt,expected),false);
});
for (const [key,value] of [['tested_head_sha','d'.repeat(40)],['tested_tree_sha','d'.repeat(40)],['invocation_id','other'],['stdin_digest',sha256('tampered')],['sandbox_enforced',false]]) {
  test('even a rehashed synthetic receipt with changed '+key+' is rejected',()=>{
    const {request,evidence}=attestation(),changed={...evidence,[key]:value};
    assert.throws(()=>verifyProgramReceipt({...changed,receipt_digest:digest(changed)},request,PROGRAM_PROFILE_DIGEST));
  });
}
