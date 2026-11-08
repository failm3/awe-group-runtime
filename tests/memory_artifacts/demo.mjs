import assert from 'node:assert/strict';
import {fixture, must, text} from './fixtures.mjs';
import {digest} from '../../awe/memory/boundary.mjs';

const f = fixture();
const search = project => must(f.memory.search(f.session('act_reader', project), text({query: 'lesson', limit: 20})));
const note = f.stageMemory('mem_lesson', 'lesson synthetic approved knowledge', {shareable: true});
const before = search('prj_alpha'); f.stageMemory('mem_canary', 'lesson CANARY_BETA_7', {projectId: 'prj_beta'});
assert.deepEqual(search('prj_alpha'), before);
must(f.memory.promote(f.session('act_owner'), text(f.promotion(note))));
const rb = f.readback(), stateHash = digest(f.world), receipt = must(rb.complete()); assert.equal(digest(f.world), stateHash);
console.log(JSON.stringify({scope: 'SYNTHETIC_E0_ONLY', cross_project_canary_leaks: 0, project_search: before,
  promoted_references: search('prj_beta').hits.filter(h => h.origin === 'PROMOTED'), artifact_readback: receipt,
  canonical_state_unchanged: true, actual_external_effects: 0, independent_acceptance: false}, null, 2));
