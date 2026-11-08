import {digest,copy,freeze,need} from '../execution_security/common.mjs';
// QA02 evidence credentials come from live SEC identities, never FixtureIssuer.
// This grants candidate test execution only; D08 and OWNER remain separate.
export function createSecProfileIssuer({verifier,issuer,roles,producerId}){
 const allowed=freeze(copy(roles)),sessions=new WeakSet();
 function principal(identity,peer,projectId){const a=verifier.authenticate(identity,peer,projectId,'VERIFIER');need(['EXAMINER','AUDITOR'].includes(allowed[a.principal_id]),'QA02_PROFILE_ROLE');need(a.principal_id!==producerId&&a.subject!==verifier.principal(producerId,projectId).subject,'SELF_QA_DENIED');return a;}
 return Object.freeze({
  credential(identity,peer,binding){const a=principal(identity,peer,binding.scope.project_id),session=freeze({identity,peer:copy(peer)});sessions.add(session);const grant=issuer.seal('profile_qa','awe.qa02',{project_id:binding.scope.project_id,task_id:binding.scope.task_id,principal_id:a.principal_id,generation:a.generation,binding:digest(binding),profile_role:allowed[a.principal_id]},60000);return {session,grant};},
  check(session,grant,action,binding){need(sessions.has(session)&&action==='VERIFY','QA02_CREDENTIAL_REQUIRED');const a=principal(session.identity,session.peer,binding.scope.project_id),g=verifier.open(grant,'profile_qa','awe.qa02');need(g.principal_id===a.principal_id&&g.generation===a.generation&&g.project_id===binding.scope.project_id&&g.task_id===binding.scope.task_id&&g.binding===digest(binding)&&g.profile_role===allowed[a.principal_id],'QA02_CREDENTIAL_BINDING');return freeze({id:a.principal_id,subject:a.subject,role:g.profile_role});}
 });
}
