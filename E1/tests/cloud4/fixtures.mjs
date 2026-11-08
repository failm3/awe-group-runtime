import {generateKeyPairSync,sign} from 'node:crypto';
import {canonicalize,digest} from '../../contracts/index.mjs';
import {createCloud4AuthorizationAuthority,issueCloud4Authorization} from '../../cloud4/authority.mjs';
export const clock=()=>new Date().toISOString();
export function authorityFixture({verifyMandate=()=>true,verifyIndependentCanary=()=>true,now=clock}={}){
  // Explicit synthetic in-memory signing key, unrelated to either WSL key.
  const {privateKey,publicKey}=generateKeyPairSync('ed25519'),spki=publicKey.export({format:'der',type:'spki'}).toString('base64'),trusted_public_key_digest=digest({spki_der:spki});
  const contexts={coordinator:Object.freeze({}),qa:Object.freeze({}),worker:Object.freeze({})};
  const authenticateContext=context=>{if(context===contexts.coordinator)return{role:'COORDINATOR',principal_id:'synthetic_host',project_id:'prj_cloud_authority4'};if(context===contexts.qa)return{role:'QA',principal_id:'synthetic_qa',project_id:'prj_cloud_authority4'};if(context===contexts.worker)return{role:'WORKER',principal_id:'synthetic_worker',project_id:'prj_cloud_authority4'};throw new Error('UNAUTHENTICATED_TEST_CONTEXT');};
  const signer={async sign(document){return{schema:'awe.e1.cloud4.signed-receipt/1',algorithm:'Ed25519',document,document_digest:digest(document),public_key_spki_der:spki,public_key_digest:trusted_public_key_digest,signature:sign(null,Buffer.from(canonicalize(document)),privateKey).toString('base64')};}};
  const authority=createCloud4AuthorizationAuthority({authenticateContext,mandate_digest:digest({label:'EXPLICIT_SYNTHETIC_OWNER_APPROVAL'}),verifyMandate,verifyIndependentCanary,signer,trusted_public_key_digest,clock:now});
  const request={key_binding_id:'synthetic_cloud4_authority',owner_id:'id_e1_owner',project_ids:['prj_cloud_authority4'],evidence_mode:'EXPLICIT_SYNTHETIC',expires_at:new Date(Date.now()+600000).toISOString()};
  return{authority,request,contexts,signer,trusted_public_key_digest,async issue(){return issueCloud4Authorization(authority,request,contexts.coordinator);}};
}
