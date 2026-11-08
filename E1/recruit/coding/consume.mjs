import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {digest,need} from '../../contracts/index.mjs';
import {createPsqlSession,createCoordinator} from '../../coordinator/index.mjs';
import {MODEL_POLICY} from '../../broker/schemas.mjs';
import {validateListing,rankListings} from '../pipeline.mjs';
import {runScoreSandbox} from './sandbox.mjs';

/** Trusted host verifies the model-produced file against the actual native QA
 * result. The descriptor/QA DB handle never crosses into the script worker. */
export async function verifyScoreArtifact({resource,filename}){
 const file=fs.lstatSync(filename);need(file.isFile()&&!file.isSymbolicLink()&&file.size<=65536,'SCORE_ARTIFACT_FILE');
 const a=JSON.parse(fs.readFileSync(filename,'utf8'));
 need(a.schema==='awe.recruit.model-authored-score/1'&&a.status==='INDEPENDENT_QA_VERIFIED'&&a.producer==='AWE_E1_RUNTIME_LOCAL_MODEL'&&a.filename==='score_helper.py'&&a.language==='python'&&a.source_digest==='sha256:'+createHash('sha256').update(a.code).digest('hex'),'SCORE_ARTIFACT_PROVENANCE');
 const db=await createPsqlSession(resource,{role:'qa'});
 try{
  const view=createCoordinator({db,project_id:a.project_id}),state=await view.snapshot(),task=state.tasks.find(t=>t.mission_id===a.mission_id&&t.task_id==='score_author'&&t.is_current),attempts=state.attempts.filter(t=>t.mission_id===a.mission_id&&t.task_id==='score_author');
  need(task?.state==='ACCEPTED'&&task.plan_digest===a.plan_digest&&task.result_hash===a.result_hash&&digest(task.result)===a.result_hash&&task.result.output.code===a.code&&task.document.capability.capability_id==='e1.recruit.score-author','SCORE_ARTIFACT_NATIVE_QA');
  need(attempts.length===1&&attempts[0].state==='CONFIRMED'&&attempts[0].actual_cost===0&&attempts[0].reserved===0&&attempts[0].route_id===MODEL_POLICY.route_id&&attempts[0].usage?.digest===MODEL_POLICY.digest&&attempts[0].usage?.model===MODEL_POLICY.model&&attempts[0].usage?.wire_attempts===1&&attempts[0].usage?.input_tokens>0&&attempts[0].usage?.output_tokens>0,'SCORE_ARTIFACT_NATIVE_MODEL');
  return {schema:'awe.recruit.verified-score-input/1',code:a.code,source_digest:a.source_digest,artifact_digest:digest(a),author_mission_id:a.mission_id,author_project_id:a.project_id,author_result_hash:a.result_hash,author_plan_digest:a.plan_digest,independent_qa_digest:digest(a.independent_qa),isolated_git:a.isolated_git};
 }finally{await db.close();}
}

export async function rankWithVerifiedCode(sources,scoreInput){
 need(scoreInput?.schema==='awe.recruit.verified-score-input/1'&&scoreInput.source_digest==='sha256:'+createHash('sha256').update(scoreInput.code).digest('hex'),'SCORE_CONSUMPTION_BINDING');
 const records=sources.flatMap(source=>source.records.filter(validateListing).map(record=>({reference:`${source.source_id}:${record.listing_id}:r${record.revision}`,skills:record.skills})));
 const receipt=await runScoreSandbox({code:scoreInput.code,inputs:records.map(r=>r.skills)}),scoreByEvidence=Object.fromEntries(records.map((r,i)=>[r.reference,receipt.scores[i]]));
 const ranking=rankListings(sources,{scoreByEvidence});
 return {...ranking,code_execution:{schema:'awe.recruit.consumed-score/1',source_digest:receipt.source_digest,artifact_digest:scoreInput.artifact_digest,author_mission_id:scoreInput.author_mission_id,author_project_id:scoreInput.author_project_id,author_result_hash:scoreInput.author_result_hash,independent_qa_digest:scoreInput.independent_qa_digest,input_digest:digest(records),output_digest:digest(receipt.scores),inputs:records,scores:receipt.scores,sandbox:receipt,used_for_ranking:true,developer_fallback:false}};
}
