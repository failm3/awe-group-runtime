import fs from 'node:fs';
import path from 'node:path';
import {randomUUID, createHash} from 'node:crypto';
import {canonicalize, digest} from '../../contracts/canonical.mjs';
import {assertScopedPath, assertNoLinks} from './paths.mjs';
import {validateInfraConfig, configScope} from './config.mjs';
import {deepFreeze, hold, InfraError} from './errors.mjs';

export const byteDigest = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex');

function safeOperation(operation) {
  try { return operation(); }
  catch (error) {
    if (error instanceof InfraError) throw error;
    hold(error?.code === 'ENOSPC' ? 'C1_STORAGE_FULL' : 'C1_STORAGE_UNAVAILABLE');
  }
}

export function ensureFixtureStorage(input) {
  const config = validateInfraConfig(input);
  return safeOperation(() => {
    const marker = path.join(config.paths.root, 'namespace.json');
    const expected = {schema: 'awe-e1.namespace.v1', composition: 'AWE_E1', scope_digest: configScope(config)};
    assertScopedPath(config.paths.root, marker);
    if (fs.existsSync(marker)) {
      if (canonicalize(readJson(config, marker)) !== canonicalize(expected)) hold('C1_NAMESPACE_ALREADY_OWNED');
    } else {
      if (fs.existsSync(config.paths.root) && fs.readdirSync(config.paths.root).length !== 0) hold('C1_UNMARKED_NAMESPACE_NOT_EMPTY');
      fs.mkdirSync(config.paths.root, {recursive: true, mode: 0o700});
      assertNoLinks(config.paths.root);
      writeJson(config, marker, expected, {exclusive: true});
    }
    for (const name of ['state', 'objects', 'backup']) {
      assertNoLinks(config.paths[name]);
      fs.mkdirSync(config.paths[name], {recursive: true, mode: 0o700});
      assertNoLinks(config.paths[name]);
    }
    // pgdata is a declaration only. This code never creates or opens it.
    return config;
  });
}

export function readJson(config, filename) {
  return safeOperation(() => {
    assertScopedPath(config.paths.root, filename);
    const stat = fs.lstatSync(filename);
    if (!stat.isFile() || stat.size > 65536) hold('C1_STORAGE_RECORD_INVALID');
    const value = JSON.parse(fs.readFileSync(filename, 'utf8'));
    canonicalize(value);
    return value;
  });
}

export function writeJson(config, filename, value, {exclusive = false} = {}) {
  return safeOperation(() => {
    const bytes = canonicalize(value) + '\n';
    assertScopedPath(config.paths.root, filename);
    if (exclusive) {
      const fd = fs.openSync(filename, 'wx', 0o600);
      try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      return;
    }
    const temp = filename + '.' + randomUUID() + '.tmp';
    assertScopedPath(config.paths.root, temp);
    const fd = fs.openSync(temp, 'wx', 0o600);
    try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    try {
      assertScopedPath(config.paths.root, filename);
      fs.renameSync(temp, filename);
      // A best effort directory fsync is sufficient for this FILESYSTEM fixture;
      // Windows does not expose a portable fsync-directory guarantee in Node.
      if (process.platform !== 'win32') {
        const directory = fs.openSync(path.dirname(filename), 'r');
        try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
      }
    } finally { if (fs.existsSync(temp)) fs.unlinkSync(temp); }
  });
}

export function createFixtureObjectStore(input) {
  const config = validateInfraConfig(input), scope = configScope(config);
  function objectPath(ref, directory) {
    if (!ref || ref.schema !== 'awe-e1.fixture-object.v1' || ref.scope_digest !== scope || !/^sha256:[0-9a-f]{64}$/.test(ref.digest ?? '') ||
        !Number.isSafeInteger(ref.bytes) || ref.bytes < 0 || ref.bytes > 1048576 || Object.keys(ref).sort().join(',') !== 'bytes,digest,schema,scope_digest') hold('C1_OBJECT_REF_INVALID');
    return assertScopedPath(config.paths.root, path.join(directory, ref.digest.slice(7) + '.blob'));
  }
  function readAt(ref, directory) {
    return safeOperation(() => {
      const filename = objectPath(ref, directory), stat = fs.lstatSync(filename);
      if (!stat.isFile() || stat.size !== ref.bytes) hold('C1_OBJECT_INTEGRITY_FAILED');
      const bytes = fs.readFileSync(filename);
      if (byteDigest(bytes) !== ref.digest) hold('C1_OBJECT_INTEGRITY_FAILED');
      return bytes;
    });
  }
  function writeAt(ref, directory, bytes) {
    return safeOperation(() => {
      const filename = objectPath(ref, directory);
      if (fs.existsSync(filename)) { readAt(ref, directory); return; }
      const fd = fs.openSync(filename, 'wx', 0o600);
      try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      readAt(ref, directory);
    });
  }
  return Object.freeze({
    kind: 'FILESYSTEM_FIXTURE', live_ready: false,
    put(bytes) {
      if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) hold('C1_OBJECT_BYTES_REQUIRED');
      if (bytes.byteLength > 1048576) hold('C1_OBJECT_TOO_LARGE');
      ensureFixtureStorage(config);
      const copy = Buffer.from(bytes);
      const ref = deepFreeze({schema: 'awe-e1.fixture-object.v1', scope_digest: scope, digest: byteDigest(copy), bytes: copy.byteLength});
      writeAt(ref, config.paths.objects, copy);
      return ref;
    },
    read(ref) { validateInfraConfig(config); return readAt(ref, config.paths.objects); },
    backup(ref) {
      ensureFixtureStorage(config);
      writeAt(ref, config.paths.backup, readAt(ref, config.paths.objects));
      return deepFreeze({status: 'TESTED_OFFLINE', kind: 'FILESYSTEM_OBJECT_COPY', object_digest: ref.digest, database_backup: 'NOT_RUN', live_ready: false});
    },
    restore(ref) {
      ensureFixtureStorage(config);
      writeAt(ref, config.paths.objects, readAt(ref, config.paths.backup));
      return deepFreeze({status: 'TESTED_OFFLINE', kind: 'FILESYSTEM_OBJECT_RESTORE', object_digest: ref.digest, database_restore: 'BLOCKED', live_ready: false});
    }
  });
}

export function checkpointEnvelope(scope, body) {
  return {schema: 'awe-e1.fixture-checkpoint.v1', scope_digest: scope, body, checksum: digest({scope_digest: scope, body})};
}

export function verifyCheckpoint(scope, record) {
  if (!record || record.schema !== 'awe-e1.fixture-checkpoint.v1' || record.scope_digest !== scope || !record.body ||
      Object.keys(record).sort().join(',') !== 'body,checksum,schema,scope_digest' || record.checksum !== digest({scope_digest: scope, body: record.body})) hold('C1_CHECKPOINT_INTEGRITY_FAILED');
  return structuredClone(record.body);
}
