import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {withLocalRoot, createScopedVault, LOCAL_ROOT} from '../../../infra/index.mjs';

export const template = JSON.parse(fs.readFileSync(new URL('../../../infra/templates/awe-e1.offline.json', import.meta.url), 'utf8'));
export function scratch(t, mutate = () => {}) {
  const namespace = 'awe_e1_c1_' + randomBytes(8).toString('hex');
  const root = path.join(LOCAL_ROOT, namespace);
  fs.mkdirSync(root, {recursive: true});
  const raw = structuredClone(template); raw.namespace = namespace; mutate(raw);
  const config = withLocalRoot(raw, root);
  t.after(() => {
    const absolute = path.resolve(root), relative = path.relative(path.resolve(LOCAL_ROOT), absolute);
    if (relative.startsWith('..') || path.isAbsolute(relative) || !path.basename(absolute).startsWith('awe_e1_c1_')) throw new Error('C1_TEST_CLEANUP_SCOPE');
    fs.rmSync(absolute, {recursive: true, force: true});
  });
  return {root, config};
}
export const context = (config, role) => ({principal_id: config.principals[role].principal_id, project_id: config.project_id, origin: config.origin});
export function vaultFixture(config, options = {}) {
  const now = options.now ?? (() => 1000);
  const grants = ['worker', 'qa'].map(role => ({grant_id: 'grant_e1_' + role, principal_id: config.principals[role].principal_id,
    project_id: config.project_id, origin: config.origin, purpose: role === 'qa' ? 'qa-signing' : 'worker-data', expires_at: 2000}));
  const vault = createScopedVault({config, grants, now, available: options.available ?? true});
  return {vault, grants, issuer: context(config, 'issuer'), owner: context(config, 'owner'), worker: context(config, 'worker'), qa: context(config, 'qa')};
}
