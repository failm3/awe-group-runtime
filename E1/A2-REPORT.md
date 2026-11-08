# A2 durable coordinator report — 2026-11-08

Status: **IMPLEMENTED / VERIFIED_LIVE_LOCAL_POSTGRESQL**, final expanded authored checks **20/20 PASS, zero skipped**. The initial baseline was 14/14; the additive quiescence change is documented below. Independent QA and integrated A3 real-model composition are the integrator's separate evidence. External effects in this A2 test run use a **clearly labeled fake provider only**. Production acceptance, 24-hour durability and human AuthN are not claimed.

## Ownership and bases

All changes are in `E1/coordinator/**`, `E1/tests/coordinator/**` and this report. No Git/index/branch/remote action, original worktree edit, cluster lifecycle operation, paid API, cloud call, message or deployment was performed by A2.

The integrator-provided clean export identifies source `c6c2db24c4648d96fd93c8fe7da63ba98dd9af19` and accepted A1 source `b689248952a3282fdda0b9f020f4cc014f610926`. A2 did not inspect or mutate Git, as instructed by `E1/TEAM-A2A3.md`. Historical E0 is a reference only; this implementation never connects to its database.

Runtime: Node `v24.21.0`; root-provisioned PostgreSQL 18 E1 resource `awe_e1_a2a3_20261108`, database `awe_e1_test`, Unix peer socket `/var/lib/awe-e1-test/awe_e1_a2a3_20261108/socket`, port **5433**. Descriptor and handshake pin database/role/port/server major/resource marker. Existing 5432 and historical 55582 are rejected before child spawn. Cluster provisioning, restart and backup evidence belong to the integrator/C1, not this report.

## Delivered behavior

- One native PostgreSQL transaction domain for mission/grant/plan/task/dependency state, leases/fences, resource slots, task/model reservations, canonical effect outbox, events, inbox dedupe and cursors. No second coordinator or ledger.
- Normal A1 published-plan admission through required trusted authenticate/resolve-publication/verify-current-owner-grant ports. A1 historical/offline contracts and serializers are unchanged. Revalidation covers DAG, provenance, manifests, schemas, grant, bounds and current time.
- Atomic claim/slot/task-budget-reserve/intent, SKIP LOCKED ready selection, bounded priorities/parallelism/resource pools, fixed task timeout, monotonic fences, heartbeat and lease recovery.
- Model `reserve / markSending / settle / unknown / failBeforeSend`: exact immutable attempt scope, local route/capability binding, quotas including cost=0, actual cost within reserve, no implicit retry of SENDING/UNKNOWN. Proved prewire failure releases quota/reserve/lease exactly once; attempt history remains.
- Same owner/business-key unique intent across missions, durable SENDING before provider access, UNKNOWN/HOLD with retained holds and reconciliation-only confirmation. No blind re-submit on timeout or restart.
- Cancel/revoke/expiry/current capability checks before dispatch; expiry/revoke do not erase accounting. Positive settlement/readback may finalize the original immutable attempt without granting a new dispatch.
- Bounded same-grant plan revision after drain; immutable plan/task result history; cumulative spend/quota/caps and fence sequence preserved. Changed grant/spec digests cannot refresh the mission. Old completion and old-plan QA are denied.
- Actual separate Node leaf processes over a loopback authority, without DB descriptor/credentials in worker IPC. Independent QA role is required for ACCEPTED; producer completion creates WAIT_QA and dependencies wait.

Public entry: `E1/coordinator/index.mjs`. Detailed contracts and limitations: `E1/coordinator/README.md`. Mandatory accounting scope and status names were agreed with A3; settle returns `CONFIRMED`, failBeforeSend returns `FAILED`.

## Commands and results

Working directory for every A2 command:

`<new clean runtime checkout>`

The root explicitly handed off this new resource before any native SQL. WSL execution required tool `require_escalated` because sandboxed WSL returned `Wsl/E_ACCESSDENIED`; automatic approval accepted the bounded E1 commands. No alternate port/cluster was used.

Initial native migration/smoke used Node ESM stdin importing `createPsqlSession` and `applyCoordinatorMigrations` with `.private/e1-resource.json`, admin role, then normal coordinator admit/claim/snapshot. Subsequent native tests reapplied the current additive migration, verified repeats, then ran behavioral tests. The final exact command was:

```powershell
$env:AWE_E1_NATIVE_TEST='1'
node --test E1/tests/coordinator/resource.test.mjs E1/tests/coordinator/native.test.mjs 2>&1 | Tee-Object -FilePath E1/tests/coordinator/native-final.tap
exit $LASTEXITCODE
```

Result: exit **0**, **14 tests / 14 pass / 0 fail / 0 skipped**, about 12.2 seconds. Earlier runs found one harness assertion using `assert.rejects` for an intentional synchronous project-scope denial; the harness was corrected to `assert.throws`. No weakening of the scope check occurred.

| Real experiment | Persisted/readback result |
|---|---|
| Two forked read workers | Different PIDs, overlapping execution intervals; both WAIT_QA before dependency can run; accepted only through QA role |
| Hard kill during read | SIGKILL, lease expiry, second process/fresh greater fence; old result denied |
| Shared money/slot race | Two independent native sessions; one winner; reservations/leases match readback; cancel releases safe held money |
| Independent budget, resource-slot, model-quota races | Each limit tested separately, one winner; quota=1 cannot be exceeded by concurrent attempts |
| Model settlement and restart | Reserve9, actual4, spent4/reserved0/quota1; event cursor and attempt confirmed state persist across DB-session/coordinator-instance restart |
| Before fake-provider effect crash | Durable SENDING becomes UNKNOWN/HOLD; provider submit/effect count0; second mission cannot claim canonical key |
| After fake-provider effect / lost ACK | Persisted provider count1, intent count1; no second submit; only positive fake readback confirms it |
| Drained revision | Active lease/reserve and WAIT_QA rejected; rev2 succeeds after QA; two plans/one archived result; spend4/quota1 preserved; old fence/QA rejected |
| Changed/revoked scope | Normal A1 owner spec/grant revision rejected by durable boundary; re-admission after durable revoke denied |
| Zero-cost UNKNOWN | Attempt and quota1 remain durable, GPU slot HELD after restart, no automatic new dispatch |
| Proven prewire failure after expiry | Wire count0; FAILED history preserved; quota0/reserve0/leases0; repeated release does not subtract twice |
| Persistent psql transaction | Same backend PID across operations; deliberately thrown callback rolls back an inbox/event write, absent on independent readback |
| Schema/auth/ACL negatives | Forged output shape rejected despite matching schema label; worker impersonation, foreign project, worker SQL RPC, worker native table/function access and coordinator-as-QA all denied |
| Resource spoof negatives | E0/5432, wrong distro/DB/PGDATA/socket/role/executable/extra fields rejected before process spawn |

`native-evidence.json` contains exact run IDs, worker PIDs/times, fences, amounts, cursor and fake-provider counts. Scratch provider JSON is under `E1/tests/coordinator/.local/`; it is synthetic and excluded from source publication. Native persisted rows are intentionally left in the authorized E1 test database; no drop/reset/cleanup of shared data occurred.

## Final hashes

SHA-256 of the applied final migration `0001-durable-runtime.sql`:

`d0708161fc480b1489a89a93e1e3d7c508fbf6aeecefb642df380a69e3c78472`

Evidence SHA-256:

- `E1/tests/coordinator/native-evidence.json` (latest expanded rerun): `64d15aae16db2387645408cf97704c5ec3330497ce765fc6cd0717161427ede8`
- `E1/tests/coordinator/native-final.tap`: `8af7069bda3527299d83127c38766834f31e1742c0394500d4343be0ed79e2fa`

Baseline implementation SHA-256 before the later additive quiescence change (changed-file pins are superseded below):

| File under E1/coordinator | SHA-256 |
|---|---|
| admission.mjs | d4f807d5c631669f8d929c40a9d564ce1e6c572c20c220ddb98f7184900a95c2 |
| authority-server.mjs | 583d5e1d7f8bacd8862cb9df4e1dde1e326c3f7a3d49fa16d0c581a3e9a87e73 |
| coordinator.mjs | 9ca074d20c2b7eaff3f45de9bd28d83d1313cde0cbf91bbebcb8a2ca90717653 |
| errors.mjs | f2911bffd56bd47a737f2d424d6982c0a43fc8825ea9666aacbc1fa91e50e668 |
| index.mjs | 2d342e04f64944ee4553bfd62b10452e5f90ac24546b58db68f8faa74e90fb40 |
| leaf-worker.mjs | af5f2ebd4b8bfc4eedaf0273c75b5fab92932d38686f5f8b648ecb89bb2dbebd |
| migrate.mjs | e722fa43ac377ac5b510fbcd2ab4c88223710bb7ceb059c32878b97d2b74bc18 |
| psql-session.mjs | 5cef8b04894eb76c6e792bfdbbf46511e020dd5d36b3f25c2ce0ef9fd9338998 |
| resource.mjs | 99641f84b411685ed517d1fe092f15975f17134914daf46974748c8a186b5063 |

## Limits and remaining acceptance

- Real PostgreSQL and real leaf concurrency/crash tests are verified. Model usage/cost in A2's ledger tests uses a labeled fake model; actual local Ollama evidence belongs to A3/integration. No paid model or real external effect was performed.
- The restart experiment replaces the coordinator object and native DB session within the authority/test OS process. Literal authority service kill/reboot, 24-hour operation, C2 backup/restore of active outbox and multi-node recovery remain NOT_RUN here.
- The host authority is trusted staging code. Its credential issuer is not proof of human identity, and forked Windows workers share the host account. Hostile OS worker isolation and production vault/service identities remain NOT_PROVEN by this module.
- UNKNOWN deliberately retains its hold after positive reconciliation; resuming/replanning that held mission requires an explicit recovery policy rather than an automatic reset. A new owner grant/spec is not silently applied to an existing mission.
- A2 does not sign its own independent acceptance, publish source, merge or declare production readiness. The integrator owns clean history/publication and the independent QA verdict.

## Additive integration fix: local execution quiescence

The integrator reported a real local-model timeout with no durable response. A2 inspected code without changing that live mission, then received an explicit mandate for this bounded fix. Frozen migration 0001 remains byte-identical with SHA-256 `d0708161fc480b1489a89a93e1e3d7c508fbf6aeecefb642df380a69e3c78472`.

New migration `0002-local-model-quiescence.sql` adds a separate direct-host SQL function and immutable attestation table. The operation validates exact resource/route/model pins, fixed operator ID, canonical proof digest, typed completed cancellation/repeated idle/runner-absence refs, observation ordering/freshness, original task/attempt/lease linkage, llm executor/NONE effect, no effect intents and all related reserves zero. The host is responsible for independently verifying real artifact bytes and provider observations; the SQL function does not claim to have observed Ollama itself.

Only the original execution lease/slots are removed and task fence advances. Original model attempt, usage, logical identity, claim count, all money and consumed quota remain unchanged; task/mission remain HOLD and attempt remains OUTCOME_UNKNOWN. The same logical retry remains prohibited. Identical proof is idempotent; changed proof is rejected. No RPC principal can invoke it, including worker, BROKER and QA. Independent QA database role has no SQL execution permission. Existing `release_task` is not used, preventing refunds or hidden requeue.

Resource safety is checked before any DDL: 0002 begins with exact actual admin/database/port/PGDATA/socket/root-identity guard. The migration runner also performs that identity read before any frozen 0001 SQL, including bootstrap sessions created with marker verification disabled. A separate offline recording-port test rejects six foreign identity mutations after one SELECT and before any DDL.

The final exact command was:

```powershell
$env:AWE_E1_NATIVE_TEST='1'
node --test --test-concurrency=1 E1/tests/coordinator/resource.test.mjs E1/tests/coordinator/native.test.mjs E1/tests/coordinator/quiescence.test.mjs E1/tests/coordinator/quiescence-native.test.mjs 2>&1 | Tee-Object -FilePath E1/tests/coordinator/final-with-quiescence.tap
exit $LASTEXITCODE
```

Result: **exit0 / 20 tests / 20 pass / 0 fail / 0 skipped**, about 14.9 seconds. The new native test file is explicit and has no opt-in skip; it is run only in the authorized native lane. Tests use unique `a2_quiesce_project_*` missions and synthetic attestations, perform zero actual model calls and write nothing to the root's failed live mission. Negatives cover stale/future proof, false scope, nonlocal route, effectful task, nonzero money reserve, linkage mismatch and worker/BROKER/QA RPC/native ACL. Positive readback proves full attempt/project/mission equality, task equality except fence, unchanged UNKNOWN/HOLD/quota1/usage-null, single proof/event and one fence advance across repeated calls.

Final additive hashes:

| File | SHA-256 |
|---|---|
| coordinator/migrations/0002-local-model-quiescence.sql | 379791e981bd5d0b40b28a60add314458c2b3837722aeb3e61fb74a36e1d5ee1 |
| coordinator/quiescence.mjs | 1df99ac57e04cbdbcdc150d3b1379b1eece187475f6805e6e527aed0a99d17a7 |
| coordinator/coordinator.mjs | 94c54a28379fb4efa72004d58370a3b3c1424d613d552fa0391115a1c137dbef |
| coordinator/psql-session.mjs | 87bf88bb3e790414a809ed2809329860205457c84fddfab235a2f94078569a26 |
| coordinator/migrate.mjs | 94c9cdc00b384c8dfc8c1c123a07310c0f483d1b2d08ae645bfb0f121caafde9 |
| coordinator/index.mjs | 39967aa6a7b5baa78fec6ccc4ca6592bdf81577cf5f9d98d0867e5ddcd0e28f4 |
| tests/coordinator/quiescence-evidence.json | a29634c10d60f85970a6ff9e0b39be500e3ac3d3d16ed8c2d83ae7e2d8cc65cf |
| tests/coordinator/final-with-quiescence.tap | ce0740c58095e4473ffec8e20a3a067eeabf62fd0ccf6171f24d88b85d8da142 |

The integrator owns real provider cancellation/idle evidence, independent QA and any later invocation of the host method against the failed live mission. This report does not resolve or refund that UNKNOWN attempt.
