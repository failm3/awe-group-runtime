// Pure projection of the existing CR01 full command and trusted plan digest.
// Parsing here is not AuthN, admission or data verification. The SEC adapter
// must still verify signatures, current authority, process and single-use proof.
import {parseNativeAdmission} from '../integration_v3/native-contract.mjs';
import {parseIntent,copy,freeze,digest,hashBytes,hash,need,unpack,subjectBinding,request} from './native-identity-contract.mjs';
export function bindPinnedNativeIdentityRequest({commandText,pinnedBinding,identityToken,grantTokens,expectedRole,permission,challengeId,expiresAt}){
 const command=parseIntent(commandText),body=command.body;
 need(body&&body.scope,'G101_FIELDS');
 const parsed=parseNativeAdmission(commandText,{project_id:body.scope.project_id,task_id:body.scope.task_id});
 hash(pinnedBinding);need(parsed.binding===pinnedBinding,'G101_REQUEST_BINDING');
 need(Array.isArray(grantTokens)&&grantTokens.length>0&&grantTokens.length<=4,'G101_LINEAGE');
 const cert=unpack(identityToken).body,leaf=unpack(grantTokens.at(-1)).body;
 need(cert.kind==='IDENTITY'&&cert.role===expectedRole&&leaf.kind==='GRANT','G101_SUBJECT_SCOPE');
 const scope={project_id:body.scope.project_id,task_id:body.scope.task_id,run_id:body.run.run_id};
 need(digest(cert.scope)===digest(scope)&&cert.parent_run_id===body.run.parent_run_id,'G101_SUBJECT_SCOPE');
 need(body.authority.subject_binding_hash===subjectBinding(cert)&&body.authority.grant_ref===leaf.grant_id&&body.authority.grant_lineage_digest===digest(grantTokens.map(t=>hashBytes(Buffer.from(t))))&&body.authority.policy_hash===permission.policy_hash,'G101_PROOF_BINDING');
 need(permission.action===body.kind&&expiresAt<=body.expires_at,'G101_CAPABILITY');
 const result={v:'g101.request.v1',principal_id:cert.principal_id,scope,expected_role:expectedRole,permission:copy(permission),native_binding:parsed.binding,state_pin_hash:digest(body.state_pin),expires_at:expiresAt,challenge_id:challengeId};
 request(result);return freeze(result);
}
