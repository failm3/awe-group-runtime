import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {fileURLToPath} from 'node:url';

// Independently authored data fixture; it is never an execution receipt.
export function independentConfig() {
  const namespace = 'awe_e1_qa';
  const root = path.join(os.tmpdir(), 'awe-e1-qa-config-' + randomUUID());
  const principals = Object.fromEntries(['owner', 'issuer', 'coordinator', 'worker', 'qa', 'security'].map(role => [role, {
    principal_id: 'id_e1_' + role, os_account_ref: 'os-account://awe-e1/' + role,
  }]));
  return {
    schema: 'awe-e1.infra.v1', composition: 'AWE_E1', release: 'AWE_E1/1', mode: 'OFFLINE_PREFLIGHT',
    namespace, project_id: 'project_qa', origin: 'https://qa.awe-e1.invalid',
    source_commit: '3579aeeda379caf78dafe5351704956f1ecc0ea5',
    paths: {root, ...Object.fromEntries(['state', 'objects', 'backup', 'pgdata'].map(name => [name, path.join(root, name)]))},
    database: {name: namespace, schema: 'awe_e1_infra', host: '127.0.0.1', port: 55591, enabled: false},
    principals, model: {enabled: false, endpoint: null, model_id: null, digest: null, status: 'BLOCKED'},
    supervisor: {max_restarts: 1, stop_timeout_ms: 500},
  };
}

// The integrator explicitly authorized only these unique QA runtime outputs.
// Windows restricted TEMP rejects atomic rename; workspace storage preserves it.
export function runtimeConfig() {
  const config = independentConfig();
  config.namespace = 'awe_e1_qa_' + randomUUID().replaceAll('-', '');
  const root = path.resolve(fileURLToPath(new URL('../.local/', import.meta.url)), config.namespace);
  config.paths = {root, ...Object.fromEntries(['state', 'objects', 'backup', 'pgdata'].map(name => [name, path.join(root, name)]))};
  config.database.name = config.namespace;
  return config;
}

// Only uniquely named QA scratch under the real TEMP directory is removable.
// The single deliberately created alias is unlinked first. Every other entry
// is inspected without following symlinks before a recursive remove.
export function removeScratch(root) {
  const absolute = path.resolve(root);
  const relative = path.relative(path.resolve(os.tmpdir()), absolute);
  const localRoot = path.resolve(fileURLToPath(new URL('../.local/', import.meta.url)));
  const localRelative = path.relative(localRoot, absolute);
  const withinTemp = relative && !path.isAbsolute(relative) && !relative.startsWith('..' + path.sep) && path.basename(absolute).startsWith('awe-e1-qa-');
  const withinLocal = /^[a-z0-9_]+$/i.test(localRelative) && /^awe_e1_qa_[a-f0-9]{32}$/.test(localRelative);
  assert.ok(withinTemp || withinLocal);
  const stat = fs.lstatSync(absolute);
  assert.ok(stat.isDirectory() && !stat.isSymbolicLink());
  assert.equal(fs.realpathSync.native(absolute).toLowerCase(), absolute.toLowerCase());
  const alias = path.join(absolute, 'alias');
  if (fs.existsSync(alias)) {
    assert.ok(fs.lstatSync(alias).isSymbolicLink());
    fs.unlinkSync(alias);
  }
  const inspect = dir => {
    for (const entry of fs.readdirSync(dir, {withFileTypes: true})) {
      assert.ok(!entry.isSymbolicLink());
      const full = path.join(dir, entry.name);
      const child = fs.lstatSync(full);
      assert.ok(!child.isSymbolicLink());
      if (child.isDirectory()) {
        assert.equal(fs.realpathSync.native(full).toLowerCase(), full.toLowerCase());
        inspect(full);
      }
    }
  };
  inspect(absolute);
  fs.rmSync(absolute, {recursive: true, force: false});
}

export function c1Denied(fn, code) {
  assert.throws(fn, error => error?.code?.startsWith('C1_') && (!code || error.code === code));
}
