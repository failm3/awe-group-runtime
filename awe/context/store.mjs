import {copy, digest, bytesHash, canonicalize, requireThat, integer} from './common.mjs';

// Host-owned, instance-local store. Staging is never visible through the active pointer.
export function createContextStore({max_entries = 16, max_bytes = 524288, fault = () => {}} = {}) {
  requireThat(integer(max_entries) && max_entries >= 2 && integer(max_bytes) && max_bytes > 0, 'STORE_LIMIT_INVALID');
  const entries = new Map(), active = new Map(); let serial = 0;
  const size = () => [...entries.values()].reduce((n, e) => n + e.bytes, 0);
  function read(ref) {
    const entry = entries.get(ref); requireThat(entry && digest(entry.value) === ref, 'MANIFEST_INVALID');
    return copy(entry.value);
  }
  return Object.freeze({
    current(key) { const ref = active.get(key) ?? null; return ref ? {ref, value: read(ref)} : null; },
    read,
    commit(key, expected_ref, value) {
      requireThat((active.get(key) ?? null) === expected_ref, 'CONTEXT_CONFLICT');
      const record = copy(value), ref = digest(record), bytes = Buffer.byteLength(canonicalize(record));
      requireThat(bytes <= max_bytes, 'STORE_CAPACITY');
      fault('before_stage');
      const protectedRefs = new Set([...active.values(), expected_ref]);
      const victims = [...entries].filter(([id]) => !protectedRefs.has(id) && id !== ref).sort((a, b) => a[1].serial - b[1].serial);
      let projectedBytes = size() + (entries.has(ref) ? 0 : bytes), projectedEntries = entries.size + (entries.has(ref) ? 0 : 1);
      const evict = [];
      while ((projectedBytes > max_bytes || projectedEntries > max_entries) && victims.length) {
        const [id, entry] = victims.shift(); projectedBytes -= entry.bytes; projectedEntries--; evict.push(id);
      }
      requireThat(projectedBytes <= max_bytes && projectedEntries <= max_entries, 'STORE_CAPACITY');
      // A simulated crash discards the staged object; both old and new committed values remain whole.
      fault('after_stage'); fault('before_activate');
      requireThat((active.get(key) ?? null) === expected_ref, 'CONTEXT_CONFLICT');
      for (const id of evict) entries.delete(id);
      entries.set(ref, {value: record, bytes, serial: ++serial}); active.set(key, ref);
      fault('after_activate');
      return ref;
    },
    inspect() { return {entries: entries.size, bytes: size(), active: active.size, max_entries, max_bytes}; }
  });
}

export function createArtifactStore({max_entries = 8, max_bytes = 262144, max_object_bytes = 65536} = {}) {
  requireThat([max_entries, max_bytes, max_object_bytes].every(n => integer(n) && n > 0), 'STORE_LIMIT_INVALID');
  const entries = new Map(); let serial = 0;
  const size = () => [...entries.values()].reduce((n, e) => n + e.data.length, 0);
  return Object.freeze({
    put(binding, input) {
      const data = Buffer.from(input), hash = bytesHash(data), key = digest({binding, hash});
      requireThat(data.length <= max_object_bytes && data.length <= max_bytes, 'ARTIFACT_TOO_LARGE');
      while (!entries.has(key) && (entries.size >= max_entries || size() + data.length > max_bytes)) {
        const oldest = [...entries].sort((a, b) => a[1].serial - b[1].serial)[0];
        requireThat(oldest, 'STORE_CAPACITY'); entries.delete(oldest[0]);
      }
      entries.set(key, {binding: digest(binding), data, serial: ++serial});
      return {artifact_ref: key, hash, bytes: data.length};
    },
    get(binding, ref) {
      const entry = entries.get(ref);
      requireThat(entry && entry.binding === digest(binding) && digest({binding, hash: bytesHash(entry.data)}) === ref, 'ARTIFACT_UNAVAILABLE');
      return Buffer.from(entry.data);
    },
    inspect() { return {entries: entries.size, bytes: size(), max_entries, max_bytes, max_object_bytes}; }
  });
}

export function boundToolOutput(artifactStore, binding, input, {inline_bytes = 256, format = 'TEXT'} = {}) {
  requireThat(integer(inline_bytes) && inline_bytes <= 4096 && ['TEXT', 'BINARY', 'BROKEN_STREAM'].includes(format), 'OUTPUT_INVALID');
  const length = typeof input === 'string' ? Buffer.byteLength(input) : input?.byteLength;
  requireThat(integer(length) && length <= artifactStore.inspect().max_object_bytes, 'ARTIFACT_TOO_LARGE');
  const data = typeof input === 'string' ? Buffer.from(input) : Buffer.from(input);
  if (format === 'TEXT' && typeof input === 'string' && data.length <= inline_bytes)
    return {inline: input, hash: bytesHash(data), bytes: data.length, truncated: false, format, error: null};
  const ref = artifactStore.put(binding, data);
  return {...ref, preview_base64: data.subarray(0, inline_bytes).toString('base64'), truncated: true, format,
    error: format === 'BROKEN_STREAM' ? 'STREAM_INCOMPLETE' : null};
}
