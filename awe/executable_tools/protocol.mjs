import {createHash} from 'node:crypto';
import {bounded,digest,canonical,copy,ensure,hash} from '../tool_registry/common.mjs';
import {parseIntent,freeze,requireKeys} from '../policy/json.mjs';
export {bounded,digest,canonical,copy,ensure,hash,freeze};
export const CONTRACT='tools02/1';
export const bytesDigest=b=>'sha256:'+createHash('sha256').update(b).digest('hex');
export const exact=(o,keys)=>{try{requireKeys(o,keys);}catch{throw Error('TOOLS_FIELDS');}};
export const parse=text=>{try{return bounded(parseIntent(text),16384);}catch{throw Error('TOOLS_JSON');}};
export const text=(v,max=4096)=>ensure(typeof v==='string'&&Buffer.byteLength(v)<=max&&!/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(v),'TOOLS_TEXT');
export const identifier=v=>typeof v==='string'&&/^[a-z][a-z0-9_-]{0,71}$(?![\s\S])/.test(v);
export function fileName(v){ensure(typeof v==='string'&&/^[a-zA-Z0-9_-][a-zA-Z0-9_.-]{0,100}$(?![\s\S])/.test(v)&&!v.includes('..')&&!/[. ]$/.test(v)&&!/^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(v),'TOOLS_PATH');return v;}
export function scopeShape(v){exact(v,['project_id','task_id','operation_id']);ensure(Object.values(v).every(identifier),'TOOLS_SCOPE');}
export function inputShape(kind,p){
 if(kind==='fs.read'){exact(p,['path']);fileName(p.path);}
 else if(kind==='fs.write'){exact(p,['path','text']);fileName(p.path);text(p.text);}
 else if(kind==='fs.list'||kind==='cli.node_version'||kind==='cli.git_version'){exact(p,[]);}
 else if(kind==='browser.snapshot'){exact(p,['fixture_id','credential']);ensure(p.fixture_id==='welcome'&&p.credential==='TEST_BROWSER_ONLY','TOOLS_FIXTURE_ONLY');}
 else if(kind==='api.get'){exact(p,['fixture_id','credential']);ensure(p.fixture_id==='inventory'&&p.credential==='TEST_API_ONLY','TOOLS_FIXTURE_ONLY');}
 else {exact(p,['text']);text(p.text);}
 return freeze(copy(p));
}
export function requestShape(q){
 exact(q,['contract','run_id','actor_id','scope','pin','input','input_hash']);
 ensure(q.contract===CONTRACT&&identifier(q.run_id)&&identifier(q.actor_id),'TOOLS_CONTRACT');scopeShape(q.scope);
 exact(q.pin,['id','digest']);ensure(/^tool_[a-z0-9_-]{1,64}$(?![\s\S])/.test(q.pin.id)&&hash(q.pin.digest),'TOOLS_PIN');
 ensure(hash(q.input_hash)&&digest(q.input)===q.input_hash,'TOOLS_INPUT_DIGEST');return freeze(q);
}
export function denial(error){return freeze({contract:CONTRACT,decision:'DENY',code:/^TOOLS_[A-Z_]+$/.test(error.message)?error.message:'TOOLS_HOST_FAILURE',physical_decision:'DENY',retry_allowed:false});}
