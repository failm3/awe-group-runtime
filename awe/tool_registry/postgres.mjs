import {bounded,ensure,id} from './common.mjs';
import {normalizeRequest} from './discovery.mjs';
export function createPostgresRegistry({readerPool,ingestPool=null}){
 ensure(readerPool&&typeof readerPool.connect==='function','TR_PG_POOL');
 const tx=async(pool,fn)=>{ensure(pool,'TR_INGEST_PORT_REQUIRED');const c=await pool.connect();let bad=false;try{await c.query('BEGIN');const result=await fn(c);await c.query('COMMIT');return result;}catch(e){bad=true;try{await c.query('ROLLBACK');}catch{}throw e;}finally{c.release(bad);}};
 const scoped=async(c,p,actor)=>{ensure(id(p)&&id(actor?.tenant_id)&&id(actor?.actor_id),'TR_SCOPE');const r=await c.query('SELECT awe_tr01.check_scope($1,$2,$3) AS ok',[p,actor.tenant_id,actor.actor_id]);ensure(r.rows[0]?.ok===true,'TR_SCOPE_DENIED');};
 return Object.freeze({
  search:async(request,actor)=>{const r=normalizeRequest(request);return tx(readerPool,async c=>{await scoped(c,r.project_id,actor);
   const filtered=await c.query('SELECT result FROM awe_tr01.discover($1,$2,$3,$4,$5,$6,$7,$8) AS result',[r.project_id,r.capabilities,r.mode,r.platform??null,r.max_cost_micros??null,r.currency??null,r.limit,r.text_filter??null]);
   return filtered.rows.map(x=>x.result);});},
  get:async(project,tool,actor)=>tx(readerPool,async c=>{await scoped(c,project,actor);ensure(id(tool),'TR_TOOL');const out=await c.query('SELECT awe_tr01.tool_view(t.tool_id) AS result FROM awe_tr01.tools t JOIN awe_tr01.project_tools p USING(tool_id) WHERE p.project_id=$1 AND t.tool_id=$2',[project,tool]);return out.rows[0]?.result??null;}),
  ingest:async(batch)=>{bounded(batch,32*1024*1024);ensure(Array.isArray(batch.records)&&batch.records.length<=5000,'TR_BATCH');return tx(ingestPool,async c=>{const r=await c.query('SELECT awe_tr01.ingest($1::jsonb) AS result',[JSON.stringify(batch)]);return r.rows[0].result;});}
 });
}
