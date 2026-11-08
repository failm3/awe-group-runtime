import {need, fail} from '../memory/boundary.mjs';

// Deliberately narrow portable namespace. Never resolve a worker path on the host OS.
export function safePath(path) {
  need(typeof path === 'string' && path.length > 0 && path.length <= 200, 'UNSAFE_PATH');
  const parts = path.split('/'); need(parts.length <= 12, 'UNSAFE_PATH');
  for (const part of parts) need(/^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}$/u.test(part)
    && !/[. ]$/u.test(part) && !/^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/iu.test(part), 'UNSAFE_PATH');
  return path;
}
export function safePathSet(paths) {
  need(Array.isArray(paths) && paths.length > 0 && paths.length <= 64, 'UNSAFE_PATH');
  const seen = new Set();
  for (const path of paths) { const p = safePath(path).toLowerCase(); need(!seen.has(p), 'UNSAFE_PATH'); seen.add(p); }
  for (const p of seen) {
    const parts = p.split('/'); parts.pop();
    while (parts.length) { need(!seen.has(parts.join('/')), 'UNSAFE_PATH'); parts.pop(); }
  }
  return paths;
}
export function decodeBase64(text, maxBytes = 32768) {
  need(typeof text === 'string' && text.length <= Math.ceil(maxBytes / 3) * 4
    && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(text));
  const bytes = Buffer.from(text, 'base64'); need(bytes.length <= maxBytes && bytes.toString('base64') === text);
  return bytes;
}
export function objectKey(projectId, contentHash) { return projectId + '/objects/' + contentHash.slice(7); }
export function regularBytes(port, key) {
  try {
    const entry = port.read(key);
    need(entry && typeof entry.then !== 'function' && entry.kind === 'file' && entry.reparse === false
      && entry.link_count === 1 && entry.canonical_key === key && Buffer.isBuffer(entry.bytes), 'INTEGRITY_FAILURE');
    return Buffer.from(entry.bytes);
  } catch { fail('INTEGRITY_FAILURE'); }
}
export function immutableWrite(port, key, bytes) {
  try {
    const ack = port.putIfAbsent(key, Buffer.from(bytes));
    need(ack === 'CREATED' || ack === 'EXISTS', 'STORAGE_FAILURE');
    need(regularBytes(port, key).equals(bytes), 'INTEGRITY_FAILURE');
  } catch (error) { if (error.message === 'INTEGRITY_FAILURE') throw error; fail('STORAGE_FAILURE'); }
}
