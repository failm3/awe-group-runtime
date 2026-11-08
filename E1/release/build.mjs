import {readdirSync,readFileSync,lstatSync} from 'node:fs';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {digest} from '../../contracts/canonical.mjs';

const root=fileURLToPath(new URL('../../',import.meta.url));
const sha=bytes=>'sha256:'+createHash('sha256').update(bytes).digest('hex');
const included=name=>/\.(?:mjs|cjs|json|sql)$/.test(name);
export function buildManifest(){
 const entries=[];
 function walk(directory){for(const item of readdirSync(join(root,directory),{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name,'en'))){
  if(item.name.startsWith('.')||['evidence','qa','tests'].includes(item.name))continue;
  const name=directory+'/'+item.name;
  if(lstatSync(join(root,name)).isSymbolicLink())throw new Error('E1_BUILD_LINK_DENIED');
  if(item.isDirectory())walk(name);
  else if(included(item.name)&&!['build-manifest.json'].includes(item.name)){const bytes=readFileSync(join(root,name));entries.push({path:name,bytes:bytes.length,digest:sha(bytes)});}
 }}
 walk('E1');
 for(const name of ['contracts/canonical.mjs','awe/project_factory/factory.mjs','awe/state/errors.mjs']){
  const bytes=readFileSync(join(root,name));entries.push({path:name,bytes:bytes.length,digest:sha(bytes)});
 }
 entries.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
 const payload={schema:'awe-e1.build-manifest.v1',release:'AWE_E1/1',profile:'AWE_E1',base_source:'3579aeeda379caf78dafe5351704956f1ecc0ea5',executed_e0_source:'c53d1fb3606218a4f3961f37f57ebc41ac6681ef',files:entries};
 const freeze=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;};
 return freeze({...payload,build_digest:digest(payload)});
}
