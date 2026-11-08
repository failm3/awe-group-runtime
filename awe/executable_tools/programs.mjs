import {ensure,exact,identifier,freeze} from './protocol.mjs';
export const TEMPLATE='text.stats.v1';
export function specShape(s){exact(s,['tool_id','language','template']);ensure(/^tool_[a-z0-9_-]{1,64}$(?![\s\S])/.test(s.tool_id)&&['JS','PYTHON'].includes(s.language)&&[TEMPLATE,'text.word_count.v1'].includes(s.template),'TOOLS_TEMPLATE');return freeze({...s});}
// Closed, dependency-free source templates. No user code, imports, paths or commands are interpolated.
export function sourceFor(language,template=TEMPLATE){
 ensure(['JS','PYTHON'].includes(language)&&[TEMPLATE,'text.word_count.v1'].includes(template),'TOOLS_TEMPLATE');
 const words=template==='text.word_count.v1';
 return language==='JS'?`import {createHash} from 'node:crypto';
let b='';for await(const c of process.stdin){b+=c;if(Buffer.byteLength(b)>16384)process.exit(2);}
const p=JSON.parse(b);if(Object.keys(p).join()!=='text'||typeof p.text!=='string'||Buffer.byteLength(p.text)>4096)process.exit(2);
const s=p.text;console.log(JSON.stringify(${words?"{words:s.split(/[ \\t\\r\\n]+/).filter(Boolean).length,utf8_bytes:Buffer.byteLength(s),sha256:'sha256:'+createHash('sha256').update(s).digest('hex')}":"{utf8_bytes:Buffer.byteLength(s),code_points:[...s].length,lines:s.split('\\n').length,sha256:'sha256:'+createHash('sha256').update(s).digest('hex')}"}));
`:`import sys, json, hashlib
b=sys.stdin.buffer.read(16385)
if len(b)>16384: sys.exit(2)
p=json.loads(b)
if list(p)!=['text'] or not isinstance(p['text'],str) or len(p['text'].encode('utf-8'))>4096: sys.exit(2)
s=p['text']
${words?"import re\nprint(json.dumps(dict(words=len([x for x in re.split(r'[ \\t\\r\\n]+',s) if x]),utf8_bytes=len(s.encode('utf-8')),sha256='sha256:'+hashlib.sha256(s.encode('utf-8')).hexdigest())))":"print(json.dumps(dict(utf8_bytes=len(s.encode('utf-8')),code_points=len(s),lines=len(s.split('\\n')),sha256='sha256:'+hashlib.sha256(s.encode('utf-8')).hexdigest())))"}
`;
}
