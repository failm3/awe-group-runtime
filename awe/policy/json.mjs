import {canonicalize} from '../../contracts/canonical.mjs';

// The worker boundary accepts bytes-as-text, never executable JS objects.
// Decode names before checking duplicates ("actor" and "\u0061ctor" collide).
export function parseIntent(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > 65536)
    throw new TypeError('BOUNDED_JSON_TEXT_REQUIRED');
  let i = 0;
  const whitespace = () => { while (/[\x20\t\r\n]/.test(text[i] ?? '') && i < text.length) i++; };
  const string = () => {
    const start = i++;
    while (i < text.length) {
      if (text[i] === '\\') { i += 2; continue; }
      if (text[i++] === '"') return JSON.parse(text.slice(start, i));
    }
    throw new SyntaxError('UNTERMINATED_STRING');
  };
  const visit = depth => {
    if (depth > 32) throw new TypeError('DEPTH_LIMIT');
    whitespace();
    if (text[i] === '"') { string(); return; }
    if (text[i] === '{' || text[i] === '[') {
      const object = text[i++] === '{', close = object ? '}' : ']', keys = new Set();
      whitespace();
      if (text[i] === close) { i++; return; }
      while (i < text.length) {
        if (object) {
          whitespace();
          if (text[i] !== '"') throw new SyntaxError('KEY_REQUIRED');
          const key = string();
          if (keys.has(key)) throw new SyntaxError('DUPLICATE_KEY');
          keys.add(key); whitespace();
          if (text[i++] !== ':') throw new SyntaxError('COLON_REQUIRED');
        }
        visit(depth + 1); whitespace();
        if (text[i] === close) { i++; return; }
        if (text[i++] !== ',') throw new SyntaxError('COMMA_REQUIRED');
      }
      throw new SyntaxError('UNTERMINATED_CONTAINER');
    }
    const match = /^(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(i));
    if (!match) throw new SyntaxError('VALUE_REQUIRED');
    i += match[0].length;
  };
  visit(0); whitespace();
  if (i !== text.length) throw new SyntaxError('TRAILING_INPUT');
  const value = JSON.parse(text);
  canonicalize(value);
  return value;
}

export const copy = value => JSON.parse(canonicalize(value));
export function freeze(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
export function requireKeys(value, keys) {
  if (!value || Array.isArray(value) || typeof value !== 'object' ||
      Object.keys(value).length !== keys.length ||
      Object.keys(value).some(key => !keys.includes(key))) throw new Error('INVALID_FIELDS');
}
