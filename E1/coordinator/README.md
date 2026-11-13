# AWE E1 durable coordinator

Dependency-free Node 24 ESM and native PostgreSQL 18. This is the single E1 D03 task lifecycle and D09 accounting/outbox transaction domain. Historical A1 preflight and C1 offline profiles remain unchanged.

## Resource and admission

The host supplies `.private/e1-resource.json` after its resource handoff. `createPsqlSession(descriptor,{role})` pins the actual E1 resource, PostgreSQL port 5433, Ubuntu, database, socket, PGDATA, executable and Unix/PG role pair before spawning any child. WSL uses absolute `/usr/sbin/runuser` for the root-provisioned nologin accounts. Backend identity and the resource marker are checked on connection. There is no shell, password argument, automatic reconnect or SQL emulation. `transaction(callback)` retains one real PostgreSQL backend for BEGIN/commands/COMMIT or ROLLBACK.

`applyCoordinatorMigrations(adminSession)` checks actual database/admin role/port/PGDATA/socket and the root-provisioned `awe_e1_resource.identity` before sending any migration SQL, then applies only this directory's migration chain. The additive 0002 also checks the resource before any DDL. Only the integrator provisions, starts, stops, backs up or restores a cluster. The coordinator role has function execution only; table/sequence privileges and public function execution are revoked. Worker has no runtime schema privileges; QA has an independent role and cannot perform coordinator writes.

```js
const admission = createAdmissionBridge({
  authenticate,       // trusted session -> {principal_id, project_id, role}
  resolvePublication,// trusted lookup -> bundle below
  verifyGrant,        // current authenticated owner grant check, required
  policy,            // host-owned bounded runtime policy, never LLM output
});
const coordinator = createCoordinator({db, admission, project_id});
await coordinator.admit({mission_id}, trustedContext);
```

The publication bundle is `{spec,grant,plan,publication,validation,capabilities,domainManifest}`. A1 sealed `spec/grant/plan/validation` are accepted as well as raw validated values. `publication` must be the normal A1 `PUBLISHED_PREFLIGHT_ONLY` result. The bridge revalidates current time, grant, DAG, capability manifests, input/output schemas, publication and validation digests. JSON alone does not mint execution authority; missing trusted ports fail closed. A1's bootstrap credential issuer remains offline only.

Policy is `{budget_cap_micros,quota_cap,max_parallel,resource_limits,capabilities?}`. Capability policy may set `{resource_keys,model_routes,max_claims,priority}`. Project money/quota/parallel caps are immutable after admission. Resource limits are persisted. Only the pinned free local Ollama route is supported for model attempts in this stage. A caller may use a project-scoped coordinator view; views share the same database and ledger.

## Claim, accounting and completion

`claim({worker_id,capabilities,lease_ms,mission_id?,task_id?})` atomically checks the current grant, plan, accepted dependencies, capability health, deadline, slots and budget. It inserts the lease, monotonic fence, task reserve and canonical effect intent in one PostgreSQL transaction. The ready queue uses `FOR UPDATE SKIP LOCKED`. Execution occurs after commit. Heartbeats never extend execution beyond the task's fixed timeout/deadline.

Task budget is reserved once at claim. Model reserves allocate within that task reserve; they do not duplicate the project charge. The mandatory accounting methods are:

```js
const scope = {mission_id,task_id,worker_id,fence,
  logical_request_id,attempt_id,route_id,capability_id,capability_version};
await coordinator.reserve({...scope,reserve_micros,quota_units:1,request_hash});
await coordinator.markSending(scope); // one-shot RESERVED -> SENDING
await coordinator.settle({...scope,actual_cost_micros,usage,provider_ref});
// On possible send / response loss:
await coordinator.unknown({...scope,reason});
// Only on a proved no-wire failure while still RESERVED:
await coordinator.failBeforeSend({...scope,reason});
```

`reserve` returns `RESERVED`, `markSending` returns `SENDING`, and settlement returns `CONFIRMED`. Costs are nonnegative integer micros, within the original reservation. Zero-cost requests still allocate durable quota and an attempt record. One active model attempt per task and bounded attempt history prevent caller-generated logical IDs from bypassing limits. Repeating markSending is denied. `SENDING` and `OUTCOME_UNKNOWN` never obtain a fresh dispatch right.

`failBeforeSend` releases safe task reserves, slots, lease and quota exactly once; the FAILED attempt remains in history. Expired/cancelled/revoked grants do not acquire new work. UNKNOWN retains money/quota/resource holds until positive reconciliation; it cannot be released through the prewire path. Settlement/readback is allowed against the original immutable attempt scope after expiry or revoke because it creates no outgoing action.

`complete({...claim,result,result_hash})` freezes a result as WAIT_QA. `result` includes `{output_schema_digest,output}`; code validates `output` against the registered schema persisted at admission, checks the digest and the current lease/fence. A leaf cannot supply its own schema or mark itself accepted. `qaEvaluate({mission_id,task_id,plan_digest,result_hash,evaluator_id,verdict,checks})` requires the independent QA database role, exact current result/plan binding and all required checks for PASS. Dependencies become ready only after ACCEPTED.

## Effects, recovery and revisions

Canonical intents have PostgreSQL `UNIQUE(owner_id,business_key)` across missions and projects. Intent state is RESERVED/SENDING/CONFIRMED/FAILED/OUTCOME_UNKNOWN. `markEffectSending` validates current grant/fence before a trusted adapter leaves the authority. `confirmEffect` accepts positive provider receipt/readback; UNKNOWN never calls a submit path. A negative eventual-consistency search is not proof authorizing retry.

Recovery reclaims expired pure read/compute leases with a greater fence, within the original retry bound. A late completion cannot commit. Expired SENDING work becomes UNKNOWN/HOLD and retains the resource hold. Cancellation and revocation release only proved unsent work. Events, deduplicated inbox records and CAS monitor cursors live in the same PostgreSQL domain.

A new plan is admitted only with the same spec/grant digests, next bounded revision, matching parent digest and stable plan ID. Active leases/reserves, WAIT_QA and unresolved outcomes require drain. Old task rows/results are archived and previous plans remain immutable; spent, quota, budgets and fence sequence never reset. `tasks[].is_current` and `tasks[].plan_digest` distinguish the current plan; `task_history` retains prior results. Late old-plan QA is denied. A changed owner grant/spec requires a separate authorized mission, rather than silently refreshing limits.

## Resource-only local quiescence

An actual model timeout may have consumed compute even when no response or usage reached the broker. `failBeforeSend` is not available for SENDING/UNKNOWN. An aborted client connection alone does not prove the provider is idle.

The narrowly scoped direct host method `quiesceLocalModel({mission_id,task_id,logical_request_id,attempt_id,worker_id,fence,proof,proof_digest})` releases only the original held execution lease/slots after a host operator independently verifies completed cancellation, two distinct idle observations at least one second apart, and runner absence. It applies only to the exact E1 resource, pinned local Ollama route/model/digest, a zero-reserved llm task with NONE effect/no effect intents, matching original UNKNOWN attempt and task/mission HOLD. All related model/task/project/mission reserves must be zero. Any other pending attempt/linkage mismatch is denied.

The proof has exact fields defined in `quiescence.mjs`; `attestor_id` is fixed `e1_local_operator`, proof fence is a canonical decimal string, and `proof_digest` is the A1 canonical digest. Typed evidence refs are `{schema,ref,digest,observed_at,status}`: completed cancellation, two IDLE observations, and ABSENT runner proof. Resource ID, route, model ID/digest and statement are pinned. Freshness is at most five minutes, with at most ten seconds clock skew into the future. The host must verify referenced bytes and actual provider observations before calling; SQL validates the structured attestation and scope, not the provider itself.

An immutable proof row/event is appended and the task fence advances once. **The attempt remains OUTCOME_UNKNOWN, task/mission remain HOLD, original attempt fence/request hash/usage/claims and all money/quota remain unchanged.** A repeated identical proof returns the same fence without another mutation; changed proof is rejected. No requeue, grant renewal, quota refund, settlement, FAILED transition or automatic retry occurs. The same logical request remains blocked. This may free concurrency for a separately authorized bounded experiment using the remaining original quota.

This operation is absent from every worker/BROKER/QA/owner RPC method map. Its SQL function is executable only by coordinator/admin roles. Synthetic proof fixtures test the boundary and must never be used as evidence for an actual provider invocation.

## Authority and leaves

`createAuthorityServer({coordinator,qaCoordinator?,dispatchEffect?})` binds loopback HTTP. Host-only `issueCredential` creates random scoped bearer credentials; there is no credential minting, DB query or admission-bypass HTTP endpoint. Workers can claim/heartbeat/complete and use bounded accounting; QA uses the separate QA port. The fixed `leaf-worker.mjs` receives only the authority URL, credential and bounds over IPC. No DB descriptor or credentials are passed to it.

This staging code does not establish hostile Windows process isolation, human identity verification, a production credential vault, unattended external effects, OS-process authority reboot, 24-hour availability or disaster recovery. The integrator owns the actual host identity/resource boundary and later acceptance.

## Verification

```powershell
$env:AWE_E1_NATIVE_TEST='1'
node --test E1/tests/coordinator/resource.test.mjs E1/tests/coordinator/native.test.mjs
```

Native tests require the integrator's already running isolated E1 cluster and approved WSL execution. They never provision or restart it. The initial `native-final.tap` records the baseline 14/14 passing run. The expanded final command adds `quiescence.test.mjs` and explicit `quiescence-native.test.mjs`; `final-with-quiescence.tap` records **20/20 PASS, zero skipped**. `native-evidence.json` and `quiescence-evidence.json` contain persisted readback, worker PIDs, overlapping intervals, fences, ledger totals and clearly labeled fake-provider/synthetic-attestation results. The external/fake-provider scenarios do not call paid APIs, mail, cloud or deployment services. Test `.local` provider scratch should not be published as runtime source.
