import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../../contracts/index.mjs';
import {verifyPersistedTaskArtifact,modelRequestIds} from '../../host/artifact-binding.mjs';
const output_schema={type:'object',properties:{text:{type:'string',minLength:1,maxLength:100}},required:['text'],additionalProperties:false};
const schema=digest(output_schema);
function fixture(){const output={text:'frozen'};const result={output,artifact_digest:digest(output),output_schema_digest:schema};return {result,result_hash:digest(result),output_schema:structuredClone(output_schema),document:{capability:{output_schema:{digest:schema}}}};}
test('stored result and artifact commitment both bind the independent QA input',()=>assert.equal(verifyPersistedTaskArtifact(fixture()),digest({text:'frozen'})));
test('persisted output substituted with an unchanged result commitment is rejected',()=>{const t=fixture();t.result.output.text='substituted';assert.throws(()=>verifyPersistedTaskArtifact(t),/E1_STORED_RESULT_DIGEST/);});
test('recomputed result cannot conceal a stale artifact commitment',()=>{const t=fixture();t.result.output.text='substituted';t.result_hash=digest(t.result);assert.throws(()=>verifyPersistedTaskArtifact(t),/E1_STORED_ARTIFACT_DIGEST/);});
test('schema commitment substitution is rejected independently of result hash',()=>{const t=fixture();t.result.output_schema_digest='sha256:'+'b'.repeat(64);t.result_hash=digest(t.result);assert.throws(()=>verifyPersistedTaskArtifact(t),/E1_STORED_SCHEMA_BINDING/);});
test('stored schema content must match the frozen capability commitment',()=>{const t=fixture();t.output_schema.properties.text.type='number';assert.throws(()=>verifyPersistedTaskArtifact(t),/E1_STORED_SCHEMA_DIGEST/);});
test('hash-consistent but schema-invalid output is rejected on cold readback',()=>{const t=fixture();t.result.output.text=7;t.result.artifact_digest=digest(t.result.output);t.result_hash=digest(t.result);assert.throws(()=>verifyPersistedTaskArtifact(t));});
test('model request IDs differ across missions and remain bounded for maximum task IDs',()=>{const a=modelRequestIds('mission_a','t'.repeat(80)),b=modelRequestIds('mission_b','t'.repeat(80));assert.notEqual(a.attempt_id,b.attempt_id);assert.notEqual(a.logical_request_id,b.logical_request_id);assert.deepEqual(a,modelRequestIds('mission_a','t'.repeat(80)));for(const v of Object.values(a))assert.match(v,/^[a-z][a-z0-9_]{0,127}$/);});
