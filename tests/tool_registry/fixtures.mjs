import {generateKeyPairSync,sign} from 'node:crypto';
import {digest,canonical,copy} from '../../awe/tool_registry/common.mjs';
export const NOW=Date.parse('2026-11-05T12:00:00Z');
export const principal={tenant_id:'tenant_a',actor_id:'alice'};
export const epochs={auth:1,policy:1,tool:1,project:1};
export const {privateKey,publicKey}=generateKeyPairSync('ed25519');
export const schema=digest({type:'object',properties:{},additionalProperties:false});
export function tool(capability='browser.screenshot',n=1){
 const payload={tenant_id:'tenant_a',actor_id:'alice',project_id:'project_a',tool_id:'tool_'+String(n).padStart(40,'0'),version:'1.0.0',revision:1,input_schema_digest:schema,capabilities:[capability],epochs:copy(epochs),issued_at:'2026-11-05T11:00:00Z',valid_until:'2026-11-05T13:00:00Z'};
 return {tool_id:payload.tool_id,title:'Synthetic '+capability,version:'1.0.0',revision:1,capabilities:[capability],verified:'TESTED',available:'AVAILABLE',platform:['linux'],cost:{amount_micros:'0',currency:'RUB',basis:'SYNTHETIC'},risk:'SYNTHETIC_ONLY',hazards:[],disabled:false,compromised:false,valid_until:payload.valid_until,input_schema_digest:schema,manifest_digest:digest(payload),signed_manifest:{key_id:'test',payload,signature:sign(null,Buffer.from(canonical(payload)),privateKey).toString('base64')}};
}
export const request=(need='Сделать скриншот браузера')=>({project_id:'project_a',need});
export const bind=t=>({project_id:'project_a',tool_id:t.tool_id,capability:t.capabilities[0],version:t.version,revision:t.revision,manifest_digest:t.manifest_digest,input_schema_digest:t.input_schema_digest,epochs:copy(epochs),task_id:'task1',operation_id:'op1',idempotency_key:'key1',artifact_digest:digest('artifact'),plan_digest:digest('plan'),max_cost_micros:'0',currency:'RUB'});
export function memoryRepository(rows){return {search:async(r,p)=>{if(r.project_id!=='project_a'||p.tenant_id!=='tenant_a'||p.actor_id!=='alice')throw Error('ACL');return copy(rows);},get:async(p,t,a)=>{if(p!=='project_a'||a.actor_id!=='alice'||a.tenant_id!=='tenant_a')throw Error('ACL');return copy(rows.find(x=>x.tool_id===t)??null);}};}
export const raw=(overrides={})=>({id:'row1',source:'fixture',source_row:1,url:'https://example.org/tool',description:'Playwright browser screenshot',title:'Fixture',category:'fixture',resource_type:'repository',...overrides});
