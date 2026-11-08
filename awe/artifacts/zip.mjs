import {need, fail} from '../memory/boundary.mjs';
import {safePathSet} from './paths.mjs';

export function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) { crc ^= byte; for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0); }
  return (crc ^ 0xffffffff) >>> 0;
}
// E0 accepts only bounded, single-disk, stored ZIPs with plain regular files, no extras/comments.
// No extraction, host paths, decompressor, symlink following, ZIP64 or executable adapter.
export function readStoredZip(bytes) {
  try {
    need(Buffer.isBuffer(bytes) && bytes.length >= 22 && bytes.length <= 49152, 'UNSAFE_ARCHIVE');
    const end = bytes.length - 22; need(bytes.readUInt32LE(end) === 0x06054b50, 'UNSAFE_ARCHIVE');
    need(bytes.readUInt16LE(end + 4) === 0 && bytes.readUInt16LE(end + 6) === 0
      && bytes.readUInt16LE(end + 20) === 0, 'UNSAFE_ARCHIVE');
    const count = bytes.readUInt16LE(end + 10), size = bytes.readUInt32LE(end + 12), start = bytes.readUInt32LE(end + 16);
    need(count > 0 && count <= 64 && count === bytes.readUInt16LE(end + 8) && start + size === end, 'UNSAFE_ARCHIVE');
    let cursor = start, expectedOffset = 0, total = 0; const files = [];
    for (let index = 0; index < count; index++) {
      need(cursor + 46 <= end && bytes.readUInt32LE(cursor) === 0x02014b50, 'UNSAFE_ARCHIVE');
      const required = bytes.readUInt16LE(cursor + 6), flags = bytes.readUInt16LE(cursor + 8), method = bytes.readUInt16LE(cursor + 10);
      need(required <= 20 && (flags === 0 || flags === 0x800) && method === 0, 'UNSUPPORTED_ARCHIVE');
      const crc = bytes.readUInt32LE(cursor + 16), packed = bytes.readUInt32LE(cursor + 20), length = bytes.readUInt32LE(cursor + 24);
      const nameSize = bytes.readUInt16LE(cursor + 28), extra = bytes.readUInt16LE(cursor + 30), comment = bytes.readUInt16LE(cursor + 32);
      const attr = bytes.readUInt32LE(cursor + 38), mode = (attr >>> 16) & 0xf000, offset = bytes.readUInt32LE(cursor + 42);
      need(bytes.readUInt16LE(cursor + 34) === 0 && (mode === 0 || mode === 0x8000)
        && (attr & 0x410) === 0 && extra === 0 && comment === 0, 'UNSAFE_ARCHIVE');
      need(packed === length && length <= 32768 && offset === expectedOffset && cursor + 46 + nameSize <= end, 'UNSAFE_ARCHIVE');
      const nameBytes = bytes.subarray(cursor + 46, cursor + 46 + nameSize), path = nameBytes.toString('utf8');
      need(Buffer.from(path).equals(nameBytes), 'UNSAFE_ARCHIVE');
      need(offset + 30 <= start && bytes.readUInt32LE(offset) === 0x04034b50, 'UNSAFE_ARCHIVE');
      need(bytes.readUInt16LE(offset + 4) === required && bytes.readUInt16LE(offset + 6) === flags
        && bytes.readUInt16LE(offset + 8) === method && bytes.readUInt32LE(offset + 14) === crc
        && bytes.readUInt32LE(offset + 18) === packed && bytes.readUInt32LE(offset + 22) === length
        && bytes.readUInt16LE(offset + 26) === nameSize && bytes.readUInt16LE(offset + 28) === 0, 'UNSAFE_ARCHIVE');
      const dataOffset = offset + 30 + nameSize;
      need(bytes.subarray(offset + 30, dataOffset).equals(nameBytes) && dataOffset + length <= start, 'UNSAFE_ARCHIVE');
      const data = Buffer.from(bytes.subarray(dataOffset, dataOffset + length)); need(crc32(data) === crc, 'UNSAFE_ARCHIVE');
      total += length; need(total <= 49152, 'UNSAFE_ARCHIVE');
      files.push({path, bytes: data, media_type: 'application/octet-stream'});
      expectedOffset = dataOffset + length; cursor += 46 + nameSize;
    }
    need(cursor === end && expectedOffset === start, 'UNSAFE_ARCHIVE'); safePathSet(files.map(f => f.path));
    return files;
  } catch (error) {
    if (['UNSAFE_PATH', 'UNSUPPORTED_ARCHIVE'].includes(error.message)) throw error;
    fail('UNSAFE_ARCHIVE');
  }
}
