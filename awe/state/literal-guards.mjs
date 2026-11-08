import {digest} from '../../contracts/canonical.mjs';
// Read committed D03/D08/D07 records in the current transaction. Generic
// harness guard hashes are never sufficient for this dialect.
export function literalCompletionGuards(db,p,t,binding){
 const r=db.d08?.[p.id+'/'+t.id],x=r?.sec_evaluation,c=p.catalogue;
 if(!r||r.qa!=='QA_PASS'||r.acceptance!=='OWNER_ACCEPTED'||x?.qa!=='QA_PASS'||x.accepted!==true||!x.proof||r.proof_hash!==digest(x.proof)||t.cancel_requested||t.restore_pending||t.acceptance_stale)return {};
 const pin=x.d03_pin,operations=Object.values(p.operations).filter(o=>o.scope.task_id===t.id);
 if(!operations.length||!pin||digest(pin.scope)!==digest(binding.scope)||digest(pin.spec)!==digest(t.spec)||digest(pin.epochs)!==digest(p.epochs)||pin.fence!==t.fence||digest(pin.lease)!==digest(t.lease)||pin.operations_hash!==digest(operations)||operations.some(o=>o.status!=='CONFIRMED'||o.retained_reservation||!o.d09_local_ack_hash))return {};
 const ref=r.reference,k=p.id+'/'+ref?.artifact?.artifact_id,a=c?.artifacts?.[k];
 if(a?.status!=='PERSISTED'||a.record.version!==ref.version||a.record.reference.content_hash!==ref.artifact.content_hash||a.record.manifest.provenance.source_hash!==ref.provenance_hash||c.tombstones.artifacts.includes(k)||c.heads.artifacts[k]?.version!==ref.version||!a.record.manifest.files.some(f=>f.path===ref.path&&f.content_hash===ref.file_hash&&f.bytes===ref.bytes)||a.readbacks?.length!==2)return {};
 return Object.fromEntries(['local_qa','examiner_qa','auditor_qa','integration_qa','persisted','independent_readback'].map(kind=>[kind,digest({kind,binding,proof_hash:r.proof_hash,reference:ref,readbacks:a.readbacks})]));
}
