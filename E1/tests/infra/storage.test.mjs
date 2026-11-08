import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createFixtureObjectStore, withLocalRoot} from '../../infra/index.mjs';
import {scratch} from './fixtures/helpers.mjs';

test('content-addressed fixture objects verify readback and restore a missing copy', t => {
  const {config} = scratch(t), store = createFixtureObjectStore(config);
  const ref = store.put(Buffer.from('synthetic object C1', 'utf8'));
  assert.deepEqual(store.put(Buffer.from('synthetic object C1', 'utf8')), ref);
  assert.equal(store.read(ref).toString('utf8'), 'synthetic object C1');
  assert.equal(store.backup(ref).database_backup, 'NOT_RUN');
  const original = path.join(config.paths.objects, ref.digest.slice(7) + '.blob');
  fs.unlinkSync(original);
  assert.equal(store.restore(ref).database_restore, 'BLOCKED');
  assert.equal(store.read(ref).toString('utf8'), 'synthetic object C1');
  assert.equal(fs.existsSync(config.paths.pgdata), false);
});

test('corruption or foreign object references yield HOLD and cannot become accepted', t => {
  const {config} = scratch(t), store = createFixtureObjectStore(config);
  const ref = store.put(Buffer.from('synthetic integrity object'));
  store.backup(ref);
  const original = path.join(config.paths.objects, ref.digest.slice(7) + '.blob');
  fs.writeFileSync(original, 'X'.repeat(ref.bytes));
  assert.throws(() => store.read(ref), error => error.code === 'C1_OBJECT_INTEGRITY_FAILED' && error.state === 'HOLD');
  assert.throws(() => store.restore(ref), /C1_OBJECT_INTEGRITY_FAILED/);
  assert.throws(() => store.read({...ref, scope_digest: 'sha256:' + '0'.repeat(64)}), /C1_OBJECT_REF_INVALID/);
  assert.throws(() => store.read({...ref, digest: '../../PRIVATE_SENTINEL'}), /C1_OBJECT_REF_INVALID/);
  const other = structuredClone(config); other.project_id = 'prj_e1_product';
  const foreign = createFixtureObjectStore(withLocalRoot(other, config.paths.root));
  assert.throws(() => foreign.put(Buffer.from('foreign')), /C1_NAMESPACE_ALREADY_OWNED/);
});

test('unmarked nonempty namespace is never silently adopted or modified', t => {
  const {config, root} = scratch(t), store = createFixtureObjectStore(config);
  const sentinel = path.join(root, 'sentinel.txt'); fs.writeFileSync(sentinel, 'synthetic untouched');
  assert.throws(() => store.put(Buffer.from('attempt')), /C1_UNMARKED_NAMESPACE_NOT_EMPTY/);
  assert.deepEqual(fs.readdirSync(root), ['sentinel.txt']); assert.equal(fs.readFileSync(sentinel, 'utf8'), 'synthetic untouched');
});

test('storage exhaustion produces a sanitized HOLD without publishing an object', t => {
  const {config} = scratch(t), store = createFixtureObjectStore(config);
  store.put(Buffer.from('initialize fixture'));
  const original = fs.writeFileSync;
  fs.writeFileSync = () => { const error = new Error('PRIVATE_STORAGE_SENTINEL'); error.code = 'ENOSPC'; throw error; };
  try { assert.throws(() => store.put(Buffer.from('cannot persist')), error => error.state === 'HOLD' && error.code === 'C1_STORAGE_FULL' && !error.message.includes('PRIVATE_')); }
  finally { fs.writeFileSync = original; }
});
