import {createHash} from 'node:crypto';
let b='';for await(const c of process.stdin){b+=c;if(Buffer.byteLength(b)>16384)process.exit(2);}
const p=JSON.parse(b);if(Object.keys(p).join()!=='text'||typeof p.text!=='string'||Buffer.byteLength(p.text)>4096)process.exit(2);
const s=p.text;console.log(JSON.stringify({words:s.split(/[ \t\r\n]+/).filter(Boolean).length,utf8_bytes:Buffer.byteLength(s),sha256:'sha256:'+createHash('sha256').update(s).digest('hex')}));
