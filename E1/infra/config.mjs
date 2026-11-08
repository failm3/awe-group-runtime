import fs from 'node:fs';
import path from 'node:path';
import {canonicalize, digest} from '../../contracts/canonical.mjs';
import {deepFreeze, deny, exactKeys} from './errors.mjs';
import {assertStorageRoot, assertScopedPath, containsPath} from './paths.mjs';

export const INFRA_SCHEMA = 'awe-e1.infra.v1';
export const COMPOSITION = 'AWE_E1';
export const RELEASE = 'AWE_E1/1';
export const SOURCE_COMMIT = '3579aeeda379caf78dafe5351704956f1ecc0ea5';
export const E0_RUNTIME_COMMIT = 'c53d1fb3606218a4f3961f37f57ebc41ac6681ef';
export const PRINCIPAL_ROLES = Object.freeze(['owner', 'issuer', 'coordinator', 'worker', 'qa', 'security']);
export const LIVE_BLOCKERS = Object.freeze(['E1_POSTGRESQL_NOT_AUTHORIZED', 'E1_MIGRATION_NOT_RUN', 'E1_PG_RESTORE_NOT_RUN', 'OS_IDENTITIES_NOT_PROVISIONED', 'REAL_VAULT_NOT_BOUND', 'MODEL_NOT_CALLED', 'AUTHORITY_UPTIME_NOT_MEASURED']);
const token = /^[A-Za-z0-9][A-Za-z0-9_.-]{1,95}$/;
const historical = /(?:^|[_.:/-])(?:e0|master01|g102c|92ef)(?:$|[_.:/-])/i;

export function validateProjectId(value) {
  if (typeof value !== 'string' || !token.test(value) || historical.test(value)) deny('C1_PROJECT_DENIED');
  return value;
}

export function normalizeOrigin(value) {
  if (typeof value !== 'string' || value.length > 256 || /[%\\\s]/.test(value) || historical.test(value)) deny('C1_ORIGIN_DENIED');
  let url;
  try { url = new URL(value); } catch { deny('C1_ORIGIN_DENIED'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/' ||
      url.port || !(url.hostname === 'awe-e1.invalid' || url.hostname.endsWith('.awe-e1.invalid')) ||
      (value !== url.origin && value !== url.origin + '/')) deny('C1_ORIGIN_DENIED');
  return url.origin;
}

export function validateInfraConfig(input) {
  try { canonicalize(input); } catch { deny('C1_CONFIG_NOT_JSON'); }
  exactKeys(input, ['schema', 'composition', 'release', 'mode', 'namespace', 'project_id', 'origin', 'source_commit', 'paths', 'database', 'principals', 'model', 'supervisor']);
  if (input.schema !== INFRA_SCHEMA || input.composition !== COMPOSITION || input.release !== RELEASE || input.mode !== 'OFFLINE_PREFLIGHT') deny('C1_OFFLINE_COMPOSITION_REQUIRED');
  if (!/^awe_e1_[a-z0-9_]{1,40}$/.test(input.namespace) || historical.test(input.namespace)) deny('C1_NAMESPACE_DENIED');
  const project_id = validateProjectId(input.project_id);
  const origin = normalizeOrigin(input.origin);
  if (input.source_commit !== SOURCE_COMMIT) deny('C1_SOURCE_PIN_MISMATCH');
  exactKeys(input.paths, ['root', 'state', 'objects', 'backup', 'pgdata']);
  const root = assertStorageRoot(input.paths.root, input.namespace);
  const paths = {root};
  for (const name of ['state', 'objects', 'backup', 'pgdata']) paths[name] = assertScopedPath(root, input.paths[name]);
  const children = Object.entries(paths).filter(([name]) => name !== 'root');
  for (let i = 0; i < children.length; i++) for (let j = i + 1; j < children.length; j++) {
    if (containsPath(children[i][1], children[j][1]) || containsPath(children[j][1], children[i][1])) deny('C1_STORAGE_OVERLAP');
  }
  exactKeys(input.database, ['name', 'schema', 'host', 'port', 'enabled']);
  if (!/^awe_e1_[a-z0-9_]{1,40}$/.test(input.database.name) || input.database.schema !== 'awe_e1_infra' ||
      input.database.host !== '127.0.0.1' || !Number.isSafeInteger(input.database.port) ||
      input.database.port < 49152 || input.database.port > 65535 || input.database.enabled !== false || historical.test(input.database.name)) deny('C1_DATABASE_DENIED');
  exactKeys(input.principals, PRINCIPAL_ROLES);
  const identities = new Set(), accounts = new Set();
  for (const role of PRINCIPAL_ROLES) {
    const principal = input.principals[role];
    exactKeys(principal, ['principal_id', 'os_account_ref']);
    if (typeof principal.principal_id !== 'string' || !/^id_e1_[a-z0-9_]{1,48}$/.test(principal.principal_id) ||
        typeof principal.os_account_ref !== 'string' || !/^os-account:\/\/awe-e1\/[a-z0-9_-]{1,48}$/.test(principal.os_account_ref) ||
        identities.has(principal.principal_id) || accounts.has(principal.os_account_ref)) deny('C1_PRINCIPAL_SEPARATION_REQUIRED');
    identities.add(principal.principal_id); accounts.add(principal.os_account_ref);
  }
  exactKeys(input.model, ['enabled', 'endpoint', 'model_id', 'digest', 'status']);
  if (input.model.enabled !== false || input.model.endpoint !== null || input.model.model_id !== null || input.model.digest !== null || input.model.status !== 'BLOCKED') deny('C1_MODEL_NOT_AUTHORIZED');
  exactKeys(input.supervisor, ['max_restarts', 'stop_timeout_ms']);
  if (!Number.isSafeInteger(input.supervisor.max_restarts) || input.supervisor.max_restarts < 0 || input.supervisor.max_restarts > 3 ||
      !Number.isSafeInteger(input.supervisor.stop_timeout_ms) || input.supervisor.stop_timeout_ms < 100 || input.supervisor.stop_timeout_ms > 5000) deny('C1_SUPERVISOR_LIMIT_INVALID');
  return deepFreeze({...structuredClone(input), project_id, origin, paths});
}

export function loadInfraConfig(filename) {
  let value;
  try {
    const stat = fs.lstatSync(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 32768) deny('C1_CONFIG_FILE_DENIED');
    value = JSON.parse(fs.readFileSync(filename, 'utf8'));
  } catch (error) { if (error?.code?.startsWith('C1_')) throw error; deny('C1_CONFIG_FILE_DENIED'); }
  return validateInfraConfig(value);
}

export const configScope = config => {
  const valid = validateInfraConfig(config);
  return digest({composition: valid.composition, namespace: valid.namespace, project_id: valid.project_id, origin: valid.origin, paths: valid.paths, principals: valid.principals});
};

export function preflight(input) {
  const config = validateInfraConfig(input);
  return deepFreeze({schema: 'awe-e1.preflight.v1', composition: COMPOSITION, release: RELEASE, status: 'TESTED_OFFLINE',
    isolation: 'PASS', namespace: config.namespace, project_id: config.project_id, scope_digest: configScope(config),
    ready: false, live_ready: false, fixture_ready: true, blockers: [...LIVE_BLOCKERS],
    performed: {database_connections: 0, clusters_created: 0, services_started: 0, model_calls: 0, external_effects: 0},
    checks: ['JSON_ALLOWLIST', 'E0_DENY', 'STORAGE_CONTAINMENT', 'LINK_ALIAS_DENY', 'DISTINCT_DECLARED_PRINCIPALS', 'LIVE_PORTS_DISABLED'],
    limitations: ['OFFLINE_PREFLIGHT_ONLY', 'DECLARATIONS_ARE_NOT_OS_AUTHENTICATION', 'TRUSTED_LOCAL_FILESYSTEM_REQUIRED']});
}

export function withLocalRoot(template, root) {
  const config = structuredClone(template);
  config.paths = {root, state: path.join(root, 'state'), objects: path.join(root, 'objects'), backup: path.join(root, 'backup'), pgdata: path.join(root, 'pgdata')};
  return validateInfraConfig(config);
}
