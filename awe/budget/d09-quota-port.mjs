import {digest} from '../../contracts/canonical.mjs';
const ports=new WeakSet(),copy=structuredClone,need=(ok,c)=>{if(!ok)throw Error(c);};
const kinds=['PROJECT','ORIGIN','DAY','MONTH','ACCOUNT'];
// Trusted D09 read port, not a reservation/admission/ledger. No caller can set
// a guard reference. The fixed SQL receipt is usable only after COMMIT ACK.
export function createD09QuotaEvidencePort({pool,currentBinding,currentHead,clock=Date.now}){
 need(pool?.connect&&typeof currentBinding==='function'&&typeof currentHead==='function','QUOTA_HOST_PORTS_REQUIRED');
 let cached=null,hold=false,last=0;
 const now=()=>{const n=clock();need(Number.isSafeInteger(n)&&n>=last,'QUOTA_CLOCK_ROLLBACK');last=n;return n;};
 function validate(r,binding,head){
  const b=r?.body;need(b?.schema==='master01.d09.quota-evidence.v1'&&b.planning_only===true&&b.admission===false&&b.physical_decision==='DENY','QUOTA_RECEIPT_KIND');
  need(digest(b.binding)===digest(binding)&&digest(b.head)===digest(head)&&r.evidence_ref===digest(b),'QUOTA_RECEIPT_BINDING');
  need(Number.isSafeInteger(b.issued_at)&&Number.isSafeInteger(b.expires_at)&&b.issued_at<=now()&&b.expires_at>now()&&b.expires_at-b.issued_at<=2000,'QUOTA_RECEIPT_EXPIRED');
  need(Array.isArray(b.budgets)&&b.budgets.length>=5&&digest(b.budgets)===b.budget_hash,'QUOTA_BUDGET_HASH');
  need(kinds.every(k=>b.budgets.some(x=>x.kind===k))&&b.budgets.every(x=>kinds.includes(x.kind)&&x.currency==='RUB'&&x.cap_micros==='0'&&x.balance_micros==='0'&&x.reserved_micros==='0'&&x.spent_micros==='0'&&Number.isSafeInteger(x.attempts_used)&&Number.isSafeInteger(x.attempt_limit)&&x.attempts_used>=0&&x.attempts_used<x.attempt_limit&&x.valid_until>=b.expires_at),'QUOTA_CAP_DENIED');
  need(b.task_attempt_ceiling===1&&b.cost_micros==='0','QUOTA_TASK_CAP');return copy(r);
 }
 const port=Object.freeze({
  async refresh(){
   need(!hold,'QUOTA_HOLD');cached=null;const binding=copy(currentBinding()),head=copy(currentHead());let c,began=false,committing=false,broken=false;
   try{c=await pool.connect();await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');began=true;await c.query('SET LOCAL synchronous_commit = on');await c.query("SET LOCAL statement_timeout = '10s'");
    const out=await c.query('SELECT awe_d09.quota_local_master01($1::jsonb) AS result',[JSON.stringify({binding,expected_head:head})]);need(out.rows?.length===1,'QUOTA_DATABASE_CONTRACT');const r=validate(out.rows[0].result,binding,head);
    committing=true;await c.query('COMMIT');began=false;
    need(digest(currentBinding())===digest(binding)&&digest(currentHead())===digest(head),'QUOTA_SOURCE_CHANGED');validate(r,binding,head);cached=r;return {status:'QUOTA_OBSERVED',evidence_ref:r.evidence_ref,committed:true,planning_only:true,physical_decision:'DENY'};
   }catch(e){broken=true;if(began)try{await c.query('ROLLBACK');}catch{hold=true;}if(committing){hold=true;const x=Error('QUOTA_COMMIT_OUTCOME_UNKNOWN');x.outcomeUnknown=true;throw x;}throw e;}
   finally{try{const closed=await c?.release(broken);need(closed?.released!==false,'QUOTA_CLIENT_CLEANUP_UNPROVEN');}catch(e){hold=true;cached=null;if(!broken)throw e;}}
  },
  evidence(binding){if(hold||!cached)return {};try{validate(cached,binding,currentHead());need(digest(binding)===digest(currentBinding()),'QUOTA_TASK_STALE');return {quota:cached.evidence_ref};}catch{cached=null;return {};}},
  invalidate(){cached=null;},status:()=>({status:hold?'HOLD':cached?'BOUND':'UNBOUND',admission:false,physical_decision:'DENY'})
 });ports.add(port);return port;
}
export const isD09QuotaEvidencePort=p=>ports.has(p);
