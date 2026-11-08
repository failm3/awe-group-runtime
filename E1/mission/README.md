# Mission ingress · contract preflight

`createMissionIngress({clock, authority, capabilities, domainManifests, projectId})` is one synchronous, process-local ingress. `projectId` optionally limits the instance to one project. The production composition should always supply it. A plan reaching `PUBLISHED_PREFLIGHT_ONLY` still has `execution_authorized=false`, `effects=0` and `accepted=false`.

`createOfflineAuthority(principals)` builds a bootstrap-only credential issuer. A principal is `{principal_id,subject_id,role,projects}`; roles are OWNER, HEAD, COORDINATOR, EXECUTOR, QA and AUDITOR. `authority.issueContext(principal_id,project_id)` mints an immutable, opaque context tracked in a private WeakMap. `authority.revokePrincipal(id)` invalidates issued contexts. JSON objects, cloned contexts and credentials from another authority are rejected.

The authority is trusted **offline setup**, not live authentication. Keep its issuance/revocation methods outside user/model requests. A2/SEC must bind context issuance to authenticated sessions and owner-controlled grant persistence. Constructor callers holding the authority are trusted bootstrap code.

```js
import {createMissionFixture} from '../examples/fixtures.mjs';
const f = createMissionFixture('A');
const {ingress, contexts, spec, grant, plan} = f;
const created = ingress.mission.create({spec, grant}, contexts.owner);
const proposed = ingress.plan.propose({plan}, contexts.head);
const validated = ingress.plan.validate({
  mission_id: spec.mission_id,
  plan_digest: proposed.plan.digest
}, contexts.coordinator);
const published = ingress.plan.publish({
  mission_id: spec.mission_id,
  plan_digest: proposed.plan.digest,
  validation_digest: validated.validation.digest
}, contexts.coordinator);
```

Exact request shapes:

| Method | Request | Required role |
|---|---|---|
| `mission.create` | `{spec,grant}` | OWNER matching owner/issuer |
| `mission.revise` | `{spec,grant,expected_spec_digest,expected_grant_digest,reason}` | Same OWNER, existing permission |
| `mission.revoke` | `{mission_id,expected_spec_digest,expected_grant_digest,reason}` | Same OWNER, stop permission |
| `plan.propose` | `{plan}` | Granted HEAD matching `proposed_by` |
| `plan.validate` | `{mission_id,plan_digest}` | Granted COORDINATOR |
| `plan.publish` | `{mission_id,plan_digest,validation_digest}` | Granted COORDINATOR |

`mission.revise` accepts only the next version and a nonempty reason; it preserves old sealed spec/grant records and invalidates publication. There are at most 16 mission revisions (`MAX_MISSION_REVISIONS`). Grant updates cannot widen prior scope or budget. Owner stop remains available after grant expiry and appends a revoked grant version.

`plan.propose` fixes an immutable snapshot. Only the current proposal may validate/publish. It must reference the previous proposal digest, keep the plan ID and increment revision. A mission permits the initial proposal plus at most its granted `max_replans` (0–8), across spec revisions. Rejected validation consumes the proposal slot, not a new repair budget. Reasons and old proposals remain immutable.

Validation fixes a certificate bound to plan/spec/grant/registry digests. Publication rechecks the complete policy, grant validity and current revision; a stale certificate is not a bypass. Repeated validation/publication is idempotent and does not append audit events. These certificates are not worker leases or D09 reservations.

`snapshot(context)` returns the actor's project-scoped mission views; `history(mission_id,context)` returns a deeply frozen event-digest chain. Mutations stage a new record and build the response before replacing stored state. Invalid requests cannot partially mutate a mission. Snapshot/history may contain multiple independently bounded contracts and exceed 64 KiB.

This state disappears when the process exits. No coordinator, queue, money ledger, durable journal, reserve/settle, production authentication, signature verification, effect adapter, actual QA/owner acceptance, crash recovery or cross-process locking is implemented here. D03/D09 A2 must own durable admission and recheck scope/revision/grant atomically before attempts. A3 owns reviewed capabilities, execution selection, real model/worker ports and schema-checked outputs.
