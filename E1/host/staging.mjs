import {createAdmissionBridge,createCoordinator,createPsqlSession,createAuthorityServer} from '../coordinator/index.mjs';
import {authorityPorts} from '../mission/authority.mjs';
import {digest,immutable,need} from '../contracts/index.mjs';

/** Host-owned local staging composition. It never mints worker credentials from
 * JSON, creates clusters, imports E0 bindings, or publishes a repository. */
export async function createNativeE1Host({resource,authority,ingress,capabilities,domainManifests,ownerGrants,policy,clock=()=>new Date().toISOString()}){
  need(authority&&ingress&&Array.isArray(ownerGrants)&&ownerGrants.length>0,'E1_NATIVE_OWNER_SCOPE_REQUIRED');
  const auth=authorityPorts(authority),projectId=ownerGrants[0].project_id;
  const grants=new Map(ownerGrants.map(g=>[g.mission_id,immutable(g)]));
  need(ownerGrants.every(g=>g.project_id===projectId),'E1_NATIVE_PROJECT_SCOPE');
  const bridge=createAdmissionBridge({
    authenticate:context=>auth.verify(context),
    resolvePublication(request,principal){
      const view=ingress.snapshot(currentContext).missions.find(m=>m.mission_id===request.mission_id);
      need(view&&view.project_id===principal.project_id&&view.status==='ACTIVE','E1_NATIVE_PUBLICATION_SCOPE');
      const entry=view.plans.at(-1);
      need(entry?.status==='PUBLISHED_PREFLIGHT_ONLY'&&entry.contract.digest===view.published_digest,'E1_NATIVE_PUBLICATION_REQUIRED');
      return {spec:view.spec,grant:view.grant,plan:entry.contract,validation:entry.validation,
        publication:{decision:'PUBLISHED_PREFLIGHT_ONLY',plan_digest:entry.contract.digest,spec_digest:view.spec.digest,grant_digest:view.grant.digest,validation_digest:entry.validation.digest},
        capabilities,domainManifest:domainManifests.find(m=>m.project_id===view.project_id&&m.manifest_id===view.spec.value.domain_manifest.manifest_id)};
    },
    verifyGrant({spec,grant,principal}){
      const ownerGrant=grants.get(spec.mission_id);
      return Boolean(ownerGrant&&principal.project_id===projectId&&ownerGrant.owner_id===spec.owner_id&&digest(ownerGrant)===digest(grant)&&grant.spec_digest===digest(spec)&&grant.revoked_at===null&&grant.issued_at<=clock()&&clock()<grant.expires_at);
    },policy,clock});
  let currentContext=null;
  const db=await createPsqlSession(resource,{role:'coordinator'});
  let qaDb;
  try{qaDb=await createPsqlSession(resource,{role:'qa'});}catch(e){await db.close();throw e;}
  const coordinator=createCoordinator({db,admission:bridge,project_id:projectId}),qaCoordinator=createCoordinator({db:qaDb,project_id:projectId});
  let server;
  try{server=await createAuthorityServer({coordinator,qaCoordinator});}
  catch(e){await db.close();await qaDb.close();throw e;}
  return Object.freeze({profile:'AWE_E1_LOCAL_STAGING',project_id:projectId,coordinator,qaCoordinator,authority:server,
    async admitPublished(mission_id,context){
      const principal=auth.verify(context);need(['OWNER','COORDINATOR'].includes(principal.role)&&principal.project_id===projectId,'E1_NATIVE_ADMITTER');
      need(currentContext===null,'E1_NATIVE_ADMISSION_BUSY');currentContext=context;
      try{return await coordinator.admit({mission_id},context);}finally{currentContext=null;}
    },
    async health(){const state=await coordinator.snapshot();return immutable({profile:'AWE_E1_LOCAL_STAGING',resource_id:resource.resource_id,postgresql:'CONNECTED_VERIFIED',project_id:projectId,active_tasks:state.tasks.filter(t=>t.is_current&&['RUNNING','WAIT_QA'].includes(t.state)).length,held_attempts:state.attempts.filter(a=>['RESERVED','SENDING','OUTCOME_UNKNOWN'].includes(a.state)).length,owner_acceptance:'NOT_REQUESTED',production_ready:false});},
    async close(){await server.close();await db.close();await qaDb.close();}
  });
}
