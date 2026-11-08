import {digest,canonicalize} from '../../contracts/canonical.mjs';
import {fileName,text,exact,freeze,copy,bytesDigest} from '../executable_tools/protocol.mjs';
export const LITERAL_DIALECT='MASTER01_LITERAL_TEXT_V1';
// A bounded compiler, with no LLM and no interpretation of embedded instructions.
// The original goal and exact requested bytes are pinned BEFORE storeSpec.
export function compileLiteralGoal(input){
 exact(input,['goal','filename','text']);text(input.goal,8192);text(input.text,4096);fileName(input.filename);
 if(!input.goal.trim()||!input.filename.endsWith('.txt')||input.filename.length>64||input.text.includes('\0')||input.goal.includes('\0')||Buffer.byteLength(canonicalize({path:input.filename,text:input.text}))>8192)throw Error('LITERAL_GOAL_INVALID');
 const original_user_goal_hash=bytesDigest(Buffer.from(input.goal));
 const spec={dialect:LITERAL_DIALECT,original_user_goal_hash,input:{path:input.filename,text:input.text},
  requirements:['req_exact_text','req_exact_bytes'],
  criterion_requirement_mapping:[{criterion_id:'Q01',requirement_id:'req_exact_text',check:{kind:'exact-text',text:input.text}},{criterion_id:'Q02',requirement_id:'req_exact_bytes',check:{kind:'bytes-sha256',expected:bytesDigest(Buffer.from(input.text))}}],
  effect_class:'IDEMPOTENT_WRITE',write_semantics:'CREATE_EXCLUSIVE',capability:'fs.write',external_network:0,physical_decision:'DENY'};
 const plan={version:'master01.plan/1',spec_hash:digest(spec),nodes:[{id:'create_text',capability:'fs.write',depends_on:[],payload_hash:digest(spec.input),write_semantics:'CREATE_EXCLUSIVE'}],
  lifecycle_owner:'D03',attempt_budget_owner:'D09',artifact_owner:'D07',memory_owner:'D03/DATA02',qa_owner:'D08',acceptance_owner:'OWNER',physical_decision:'DENY'};
 return freeze({original_user_goal:input.goal,spec:copy(spec),spec_hash:digest(spec),plan,plan_hash:digest(plan)});
}
