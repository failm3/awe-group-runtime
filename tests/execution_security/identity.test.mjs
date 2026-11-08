import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {fixture,text} from './fixtures.mjs';
import {createIdentityVerifier} from '../../awe/execution_security/identity.mjs';
import {canonicalize,digest,parseIntent} from '../../awe/execution_security/common.mjs';
const decode=t=>JSON.parse(Buffer.from(t.split('.')[0],'base64url'));
test('AuthN positive: human, agent, subagent and service have distinct authenticated principals',()=>{
 const f=fixture();for(const id of ['user','owner','worker','child','verifier','evaluator','executor','provider']){
  const a=f.verifier.authenticate(f.token(id),f.peer(id),'prj_alpha');assert.equal(a.principal_id,id);assert.equal(a.assurance,undefined);
 }
});
test('AuthN positive: independent verifier instance verifies signed wire proof with pinned issuer',()=>{
 const f=fixture(),second=createIdentityVerifier(f.config);assert.equal(second.authenticate(f.token('worker'),f.peer('worker'),'prj_alpha').role,'WORKER');
});
for(const [name,make] of [
 ['LLM identity JSON',f=>text({role:'OWNER',principal_id:'owner'})],
 ['changed role retaining signature',f=>{const t=f.token('worker'),b=decode(t);b.role='OWNER';return Buffer.from(canonicalize(b)).toString('base64url')+'.'+t.split('.')[1];}],
 ['untrusted key',f=>{const b=decode(f.token('worker')),k=generateKeyPairSync('ed25519');const bytes=Buffer.from(canonicalize(b));return bytes.toString('base64url')+'.'+sign(null,bytes,k.privateKey).toString('base64url');}],
 ['wrong audience',f=>f.issuer.seal('identity','attacker',{principal_id:'worker'})],
 ['wrong proof kind',f=>f.rootGrant],
 ['base64 ambiguity',f=>f.token('worker')+'='],
 ['invalid UTF8/canonical encoding',f=>Buffer.from('{"kid":"local-key-1","kid":"evil"}').toString('base64url')+'.AAAA']
])test('AuthN deny '+name,()=>{const f=fixture();assert.throws(()=>f.verifier.authenticate(make(f),f.peer('worker'),'prj_alpha'));});
for(const [name,change] of [
 ['revoked principal',f=>f.principals.worker.active=false],
 ['generation changed',f=>f.principals.worker.generation++],
 ['membership removed',f=>f.principals.worker.projects=[]],
 ['issuer key revoked',f=>f.revokeKey()],
 ['AuthN outage',f=>f.setHealthy(false)],
 ['auth epoch advanced',f=>f.state.epochs.auth++],
 ['TTL elapsed',f=>f.setTime(f.time()+60000)],
 ['subject alias',f=>f.principals.evaluator.subject=f.principals.worker.subject],
 ['credential sharing',f=>f.principals.evaluator.database_login=f.principals.worker.database_login],
 ['channel sharing',f=>f.principals.owner.channel_binding=f.principals.worker.channel_binding]
])test('AuthN dispatch-time denial '+name,()=>{const f=fixture(),token=f.token('worker');change(f);assert.throws(()=>f.verifier.authenticate(token,f.peer('worker'),'prj_alpha'));});
test('AuthN session is bound to authenticated ingress, not caller principal JSON',()=>{
 const f=fixture();assert.throws(()=>f.verifier.authenticate(f.token('worker'),f.peer('owner'),'prj_alpha'),/CHANNEL_BINDING_DENIED/);
 assert.throws(()=>f.verifier.authenticate(f.token('foreign'),f.peer('foreign'),'prj_alpha'));
});
test('AuthN revoked proof and clock rollback deny',()=>{
 const f=fixture(),token=f.token('worker');f.revokeProof(decode(token).jti);assert.throws(()=>f.verifier.authenticate(token,f.peer('worker'),'prj_alpha'),/PROOF_REVOKED/);
 const g=fixture();g.verifier.now();g.setTime(g.time()-1);assert.throws(()=>g.verifier.now(),/CLOCK_ROLLBACK/);
});
test('LLM cannot reclassify itself as human owner or trusted evaluator',()=>{
 const f=fixture();assert.throws(()=>f.verifier.authenticate(f.token('worker'),f.peer('worker'),'prj_alpha','OWNER'),/ROLE_DENIED/);
 f.principals.owner.kind='AGENT';assert.throws(()=>f.verifier.authenticate(f.token('owner'),f.peer('owner'),'prj_alpha'),/OWNER_PRINCIPAL_KIND/);
});
test('strict boundary rejects duplicate decoded names, prototypes, unsafe integers and oversize input',()=>{
 for(const input of ['{"a":1,"\\u0061":2}','{"__proto__":{}}','{"amount":9007199254740993}','{"constructor":"evil"}','[1,]','{"x":"'+'a'.repeat(65536)+'"}'])assert.throws(()=>parseIntent(input));
});
test('grant positive: supervisor issues root, parent delegates restricted signed child',()=>{
 const f=fixture();const child=f.auth.control.issueGrant(f.token('worker'),f.peer('worker'),text({...f.grantRequest,subject_id:'child',max_attempts:1,max_cost_micros:'10',max_children:0,ttl_ms:30000}),f.rootGrant);
 const b=f.auth.grant(child);assert.equal(b.subject_id,'child');assert.equal(b.parent_id,f.auth.grant(f.rootGrant).grant_id);assert.equal(b.depth,1);
});
for(const [name,change] of [
 ['tool widening',r=>r.tools=[digest('other')]],['resource widening',r=>r.resources=['resource:foreign']],['risk widening',r=>r.risks=['DESTRUCTIVE']],
 ['domain widening',r=>r.domains=['evil.example']],['TTL widening',r=>r.ttl_ms=60001],['attempt oversubscription',r=>r.max_attempts=5],['money oversubscription',r=>r.max_cost_micros='101'],
 ['children widening',r=>r.max_children=3],['foreign project',r=>r.project_id='prj_beta'],['unknown subject',r=>r.subject_id='ghost']
])test('grant deny child '+name,()=>{const f=fixture(),r={...f.grantRequest,subject_id:'child',max_attempts:1,max_cost_micros:'10',max_children:0,ttl_ms:30000};change(r);assert.throws(()=>f.auth.control.issueGrant(f.token('worker'),f.peer('worker'),text(r),f.rootGrant));});
test('grant child allocations cannot overbook parent across siblings',()=>{
 const f=fixture(),r={...f.grantRequest,subject_id:'child',max_attempts:3,max_cost_micros:'80',max_children:0,ttl_ms:30000};
 f.auth.control.issueGrant(f.token('worker'),f.peer('worker'),text(r),f.rootGrant);
 assert.throws(()=>f.auth.control.issueGrant(f.token('worker'),f.peer('worker'),text({...r,subject_id:'child2'}),f.rootGrant),/CHILD_ALLOCATION_EXCEEDED/);
});
test('grant revocation cascades, issuer generation revokes lineage, wrong parent cannot delegate',()=>{
 const f=fixture(),r={...f.grantRequest,subject_id:'child',max_attempts:1,max_cost_micros:'10',max_children:0,ttl_ms:30000};
 assert.throws(()=>f.auth.control.issueGrant(f.token('owner'),f.peer('owner'),text(r),f.rootGrant),/DELEGATION_ACTOR_DENIED/);
 const child=f.auth.control.issueGrant(f.token('worker'),f.peer('worker'),text(r),f.rootGrant);
 f.auth.control.revokeGrant(f.auth.grant(f.rootGrant).grant_id);assert.throws(()=>f.auth.grant(child),/GRANT_REVOKED/);
 const g=fixture();g.principals.supervisor.generation++;assert.throws(()=>g.auth.grant(g.rootGrant),/GRANT_IDENTITY_REVOKED/);
});
