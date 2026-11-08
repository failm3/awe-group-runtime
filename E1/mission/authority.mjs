import {exact, immutable, need} from '../contracts/index.mjs';
const authorities = new WeakMap();
const roles = ['OWNER', 'HEAD', 'COORDINATOR', 'EXECUTOR', 'QA', 'AUDITOR'];
const identifier = value => typeof value === 'string' && /^[a-z][a-z0-9_.-]{0,79}$/.test(value);

/** Offline bootstrap credential issuer. Hold this outside untrusted ingress.
 * It does not authenticate a human, HTTP caller, or production identity.
 * A2/SEC must replace bootstrap issuance with its authenticated session adapter.
 */
export function createOfflineAuthority(principals) {
  need(Array.isArray(principals) && principals.length > 0 && principals.length <= 128, 'E1_PRINCIPALS');
  const table = new Map(), contexts = new WeakMap();
  for (const input of principals) {
    exact(input, ['principal_id', 'subject_id', 'role', 'projects']);
    need(identifier(input.principal_id) && identifier(input.subject_id) && roles.includes(input.role) && Array.isArray(input.projects) && input.projects.length > 0 && input.projects.every(identifier) && new Set(input.projects).size === input.projects.length && !table.has(input.principal_id), 'E1_PRINCIPAL');
    table.set(input.principal_id, {...immutable(input), active: true, generation: 1});
  }
  for (const principal of table.values()) for (const other of table.values()) if (principal.subject_id === other.subject_id) need((principal.role === 'QA') === (other.role === 'QA'), 'E1_QA_SUBJECT_CONFLICT');
  const lookup = (principalId, projectId) => { const principal = table.get(principalId); need(principal?.active && principal.projects.includes(projectId), 'E1_ACTOR_SCOPE'); return immutable({principal_id: principal.principal_id, subject_id: principal.subject_id, role: principal.role, projects: principal.projects, generation: principal.generation}); };
  const verify = context => { const record = contexts.get(context); need(record, 'E1_AUTH_CONTEXT'); const principal = lookup(record.principal_id, record.project_id); need(principal.generation === record.generation, 'E1_AUTH_REVOKED'); return immutable({...principal, project_id: record.project_id}); };
  const authority = Object.freeze({
    mode: 'OFFLINE_BOOTSTRAP_ONLY',
    issueContext(principal_id, project_id) { const principal = lookup(principal_id, project_id); const context = Object.freeze({principal_id, project_id, trust_source: 'OFFLINE_BOOTSTRAP_ONLY'}); contexts.set(context, {principal_id, project_id, generation: principal.generation}); return context; },
    revokePrincipal(principal_id) { const principal = table.get(principal_id); need(principal?.active, 'E1_ACTOR_UNKNOWN'); principal.active = false; principal.generation++; }
  });
  authorities.set(authority, {verify, lookup}); return authority;
}
export function authorityPorts(authority) { const ports = authorities.get(authority); need(ports, 'E1_AUTHORITY_REQUIRED'); return ports; }
