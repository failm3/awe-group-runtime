import {createHash} from 'node:crypto';
import {MemoryStorage} from './memory-storage.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex'),clone=structuredClone,stores=new WeakSet();
const need=(v,c)=>{if(!v)throw Error(c);};
export const isPostgresStateStorage=s=>stores.has(s);
const envelope=data=>JSON.stringify({snapshot_version:1,checksum:sha(JSON.stringify(data)),data});
// D03 storage port over the EXISTING D09 project row. No new authority store,
// ledger, filesystem restore or default connection. Database validation pending.
export async function openPostgresStateStorage({pool,project_id,requiredHead}){
 need(pool?.connect&&/^prj_[a-z0-9][a-z0-9_-]{0,63}$/.test(project_id),'D03_REVIEWED_POOL_REQUIRED');
 need(Number.isSafeInteger(requiredHead?.commit)&&requiredHead.commit>=0&&/^[a-f0-9]{64}$/.test(requiredHead.hash),'D03_EXTERNAL_RECOVERY_ANCHOR_REQUIRED');
 let data,head,hold=false,tail=Promise.resolve();
 async function invoke(fn,command){
  let client,began=false,committing=false,broken=false;
  try{client=await pool.connect();await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');began=true;
   await client.query('SET LOCAL synchronous_commit = on');await client.query("SET LOCAL statement_timeout = '10s'");
   const response=await client.query(`SELECT awe_d09.${fn}($1::jsonb) AS result`,[JSON.stringify({...command,project_id})]);
   const r=response.rows?.[0]?.result;need(r?.physical_decision==='DENY'&&Number.isSafeInteger(r.commit)&&typeof r.body_text==='string'&&sha(r.body_text)===r.hash,'D03_DATABASE_CONTRACT');
   if(fn==='d03_commit_master01')need(r.commit===head.commit+1&&r.hash===command.hash&&r.body_text===command.body_text,'D03_COMMIT_RECEIPT_BINDING');
   committing=true;await client.query('COMMIT');began=false;return clone(r);
  }catch(e){broken=true;let rollbackFailed=false;if(began)try{await client.query('ROLLBACK');}catch{rollbackFailed=true;}if(committing||rollbackFailed){hold=true;const x=Error('D03_COMMIT_OUTCOME_UNKNOWN');x.outcomeUnknown=true;throw x;}throw e;
  }finally{try{const close=await client?.release(broken);if(close?.released===false)throw Error('D03_CLIENT_CLOSE_UNPROVEN');}catch(e){hold=true;if(!broken)throw e;}}
 }
 const initial=await invoke('d03_read_master01',{});
 need(initial.commit>=requiredHead.commit&&(initial.commit!==requiredHead.commit||initial.hash===requiredHead.hash),'D03_ROLLBACK_OR_ANCHOR_MISMATCH');
 // A higher database commit is evidence of a recovery gap, not authorization
 // to lift an external anchor. Only an independently reconciled exact head opens.
 need(initial.commit===requiredHead.commit,'D03_UNRECONCILED_HEAD_GAP');
 const parsed=JSON.parse(initial.body_text);need(parsed.data.commit===initial.commit&&Object.keys(parsed.data.projects).every(p=>p===project_id),'D03_SCOPE_OR_REVISION');
 // Reuse existing D03 restore validation and its restore_pending semantics.
 data=new MemoryStorage({snapshot:initial.body_text}).read(x=>x);head={commit:initial.commit,hash:initial.hash};
 const port=Object.freeze({
  read(query){need(!hold,'D03_STORAGE_HOLD');return clone(query(clone(data)));},
  snapshot(){need(!hold,'D03_STORAGE_HOLD');return envelope(clone(data));},
  status:()=>({status:hold?'HOLD':'BOUND',profile:'MASTER01_POSTGRES_D03',head:clone(head),physical_decision:'DENY'}),
  transaction(reducer){const next=tail.then(async()=>{
   need(!hold,'D03_STORAGE_HOLD');const draft=clone(data),value=reducer(draft);need(!value?.then,'ASYNC_TRANSACTION_FORBIDDEN');const detached=clone(value);
   draft.commit=head.commit+1;need(Number.isSafeInteger(draft.commit),'D03_COMMIT_OVERFLOW');
   const body_text=envelope(draft),hash=sha(body_text);
   try{const r=await invoke('d03_commit_master01',{expected_commit:head.commit,expected_hash:head.hash,body_text,hash});data=clone(draft);head={commit:r.commit,hash:r.hash};return detached;}
   catch(e){hold=true;throw e;}
  });tail=next.catch(()=>{});return next;}
 });stores.add(port);return port;
}
