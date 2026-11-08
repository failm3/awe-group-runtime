import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath} from 'node:url';
import {deny} from './errors.mjs';

export const WORKSPACE_ROOT = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
export const LOCAL_ROOT = path.join(WORKSPACE_ROOT, 'E1', '.local');
export const HISTORICAL_E0_ROOT = 'C:/Users/1/.codex/worktrees/92ef/AWE-GROUP-INT04';
const forbidden = /(?:^|[\\/_.-])(?:e0|92ef|master01|g102c)(?:$|[\\/_.-])/i;

// Reject aliases rather than guessing their target. No filesystem operation is
// made against the E0 tree, even to resolve it. Existing links are always denied.
export function canonicalLocalPath(value) {
  if (typeof value !== 'string' || !value || value.length > 1024 || /[\x00-\x1f%~]/.test(value)) deny('C1_UNSAFE_PATH');
  if (/^(?:file:|\\\\|\/\/|\\\?\?|\\\?\\)/i.test(value)) deny('C1_UNSAFE_PATH');
  if (forbidden.test(value)) deny('C1_E0_PATH_DENIED');
  const windows = /^[a-z]:[\\/]/i.test(value);
  if (windows && process.platform !== 'win32') deny('C1_FOREIGN_PATH_STYLE');
  if (!windows && !path.isAbsolute(value)) deny('C1_ABSOLUTE_PATH_REQUIRED');
  const components = value.replace(/\\/g, '/').split('/');
  for (let i = windows ? 1 : 0; i < components.length; i++) {
    const component = components[i];
    if (component === '.' || component === '..' || /[. ]$/.test(component) || /[:<>"|?*]/.test(component) ||
        /^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(component)) deny('C1_UNSAFE_PATH');
  }
  if (!windows && value.includes('\\')) deny('C1_UNSAFE_PATH');
  return path.resolve(value);
}

const comparable = value => process.platform === 'win32' ? value.toLowerCase() : value;
export function containsPath(root, candidate, allowEqual = true) {
  const relative = path.relative(comparable(root), comparable(candidate));
  return (allowEqual && relative === '') || (relative !== '' && relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}

export function assertNoLinks(value) {
  const absolute = canonicalLocalPath(value);
  const parsed = path.parse(absolute);
  let current = parsed.root;
  for (const part of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    let stat;
    try { stat = fs.lstatSync(current); }
    catch (error) { if (error.code === 'ENOENT') continue; deny('C1_PATH_INSPECTION_FAILED'); }
    if (stat.isSymbolicLink() || (stat.isFile() && stat.nlink !== 1)) deny('C1_LINK_PATH_DENIED');
    // realpath catches junction/reparse aliases visible to Node as directories.
    let real;
    try { real = fs.realpathSync.native(current); } catch { deny('C1_PATH_INSPECTION_FAILED'); }
    if (comparable(path.resolve(real)) !== comparable(current)) deny('C1_PATH_ALIAS_DENIED');
  }
  return absolute;
}

export function assertStorageRoot(value, namespace) {
  const root = canonicalLocalPath(value);
  const local = canonicalLocalPath(LOCAL_ROOT);
  const temp = canonicalLocalPath(os.tmpdir());
  const withinLocal = containsPath(local, root, false);
  const withinTemp = containsPath(temp, root, false) && path.basename(root).startsWith('awe-e1-');
  if (!withinLocal && !withinTemp) deny('C1_STORAGE_ROOT_DENIED');
  if (withinLocal && path.basename(root) !== namespace) deny('C1_NAMESPACE_PATH_MISMATCH');
  assertNoLinks(root);
  return root;
}

export function assertScopedPath(root, value, {allowRoot = false} = {}) {
  const candidate = canonicalLocalPath(value);
  if (!containsPath(root, candidate, allowRoot)) deny('C1_PATH_OUTSIDE_NAMESPACE');
  return assertNoLinks(candidate);
}
