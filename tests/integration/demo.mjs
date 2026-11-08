import {createHash} from 'node:crypto';
import {fixture, completeCanary} from './fixtures.mjs';
const f = await fixture(), review = await f.review(), result = await completeCanary(f);
console.log(JSON.stringify({mode: 'E0_CANARY_ONLY', production_ready: false,
  preflight_before_owner_action: f.preflight, review, task: {state: result.task.state, revision: result.task.revision},
  operation: f.operation(), owner_action_uses: f.h.service.getOwnerActions(f.h.state, 'prj_alpha')[0].uses,
  checkpoint: result.checkpoint.checkpoint_ref, d02: f.inspect(),
  physical_effect_decision: f.bridge.worker.requestPhysicalEffect(),
  state_snapshot_sha256: createHash('sha256').update(f.h.storage.snapshot()).digest('hex')}, null, 2));
