# Independent QA2 — A2/A3 final report

**VERIFIED for bounded local G2/G3; full E1 remains PARTIAL.** All 45 independent tests pass with no failures/skips. A real pinned local Head produced a typed plan, which was published as revision 2 and executed through the shared native coordinator, script/model brokers and separate QA process/DB role. Independent cold readback rechecked four frozen results, two plan revisions, real backend usage, settlement and cursor. The helper's seeded sorting bug was not changed or executed. Owner/D08 acceptance and G4/G5/G6 are not issued.

QA authored only `E1/qa2/**` and verified unique `E1/.local/awe_e1_qa2_*` scratch. Implementation was read-only. QA performed no Git mutation/publication, schema DDL, cluster/model lifecycle, E0 connection, paid/cloud request or actual model generation. Parent authorized synthetic `prj_qa2_*` native tests and read-only inspection of the two actual maintenance missions.

## Final verification

Exact command:

`node --test --test-concurrency=1 --test-reporter=tap E1/qa2/model-seams.test.mjs E1/qa2/maintenance-oracle.test.mjs E1/qa2/native-seams.test.mjs E1/qa2/native-processes.test.mjs E1/qa2/host-seams.test.mjs E1/qa2/quiescence-seams.test.mjs`

Result: **45/45 PASS, 0 fail, 0 skip**, exit 0, Node `v24.21.0`, 2026-11-08T01:18:25.172Z–01:18:46.249Z. The 42 source/test pins were stable before/after the run. `all-final.tap` SHA-256: `cb559582050f00209ae6f9bd816da9f6a70af95f6156d9d46c92062fa3155c64`. `all-final.command.json` contains the exact command, timestamps, exit and all hashes. There are 20 native PG/process/host/quiescence tests and 25 offline contract/model/oracle tests; offline model responses are explicitly `OFFLINE_TEST_DOUBLE`, never live evidence.

The first native launch hit sandbox `Wsl/E_ACCESSDENIED`; automatic escalation review authorized the same E1-only tests. QA corrected over-wide retry and impossible-second-active-attempt fixture assumptions after the public coordinator correctly rejected them. A partial test run retained open fixture sessions until its timeout; the corrected final run passes. Earlier failures and raw scans stay local and are superseded by the final command record.

## Actual local intelligence and cold readback

`node E1/qa2/verify-local-contour.mjs` — exit 0. Actual mission `mission_code_compact_mw7543y4`: COMPLETE, two plan revisions, four independently rechecked frozen results. The verifier opened a fresh QA peer session, reconstructed the clean fixture from persisted time/suffix/concise policy and unchanged registry time, matched exact spec/grant digests, read the actual model outputs from PostgreSQL and replayed the independent semantic oracle.

| Real operation | Backend input/output tokens | Measured latency | Native accounting |
| --- | --- | --- | --- |
| Head typed plan | 623 / 162 | 18,240 ms | CONFIRMED, one generation |
| Semantic code review | 144 / 235 | 13,800 ms | CONFIRMED, one generation |

Model `qwen3:4b-instruct`, pinned digest `0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0`. Each persisted attempt has one ordered RESERVE→SENDING→SETTLE sequence; usage matches integrator evidence, PostgreSQL and the separate cold-process readback. Actual review identifies default lexical sorting and proposes an ascending numerical comparator while preserving the copy; it does not claim an implemented correction or passing helper tests. Cursor persists; API ledger reserve/spend are 0, quota is 3. Infrastructure cost was not measured.

`actual-contour-review.json` SHA-256: `9353a7b1cc6b55f9fb529bb105c38e53af0e5236f8e8c4d3b2960b128fd04075`. QA made zero new model calls or state changes during this verification.

The earlier real Head mission `mission_code_live_mw745gdt` timed out after 120 seconds. It remains HOLD with one OUTCOME_UNKNOWN attempt, no usage/final ACK, one charged unit and exactly one SENDING event. Its parse artifact and separate parse QA passed, but no Head result or revised plan was invented. `actual-timeout-review.json` SHA-256: `4be16b01bdbc4288a16884e7c0e2d0eb2f3c6152fb0e593cd4aa382f8709be26`.

After a separately reviewed host operation, only its physical execution lease/slot was quiesced. Independent QA verified the historical operator observation commitments, exact proof event, unchanged old request hash/attempt fence 98/usage/quota, preserved HOLD/UNKNOWN, one claim, no second send and new task fence 158. `actual-quiescence-review.json` SHA-256: `6d70cb411ec0fd03845c7be49c84129c487223e31b2a6492e5fd0a1f2ae07690`. The old charged unit remains included in quota 3; the compact experiment has a distinct narrowed spec/grant and distinct global request IDs. Quiescence is not settlement, acceptance or authorization to retry/resume the old request.

## Independent native and failure coverage

- Two real Node leaf processes overlapped persisted execution intervals. A dependent claim waited until upstream results were independently checked and accepted by the separate QA role. Leaves received scoped RPC credentials/task limits, not DB descriptors/passwords.
- An owned Windows child was force-killed with `child.kill('SIGKILL')`; a new worker took over after expiry, advanced its fence and rejected the stale result. This is Windows process termination, not a Linux `kill -9` result.
- Native concurrent backends admitted one shared money reservation and one model-quota reservation; counters stayed nonnegative, cancellation released safe reservations. Worker SQL access, QA write access, RPC impersonation/project/capability/owner misuse and revoked credentials were denied.
- Two missions competed for one canonical business key. PostgreSQL held one intent; a clearly labelled local fake provider was independently read back with 0 or 1 effects before/after a simulated lost ACK. No second submit occurred; reconciliation confirmed only the existing fake receipt. No real external exactly-once guarantee is claimed.
- Unknown outcomes stayed HOLD across new authority connections. Cancel/revoke stopped new dispatch and late completion. Inbox dedupe/conflict, cursor CAS and fresh-session cursor persisted.
- Wrong-type output was rejected before persistence. A schema-valid seeded numerical error was frozen in PG, independently recomputed and rejected, with persisted FAILED and a matching QA_FAIL result digest. No acceptance key/signature was issued.
- Proven pre-wire expiry/route revocation released quota/reserve/lease exactly once with zero generation. Ambiguous reservation/SENDING acknowledgements stayed UNKNOWN. A final `done_reason:length` ACK with genuine-shaped metrics settled once CONFIRMED, retained usage/quota and returned REPAIR even for valid-looking JSON; unknown completion reasons remained UNKNOWN.
- Operator-only quiescence retained all accounting/outcome/claims and removed only a held execution lease while fencing its worker. Repeated proof was idempotent; malformed/stale/future/pin/fence/cancel/idle evidence, positive reserves/effects and worker/BROKER/QA RPC access were denied. The public one-active-attempt guard prevented another pending model call on that lease.
- Stored function bodies for `command`, `assert_active`, `assert_fence`, `release_task`, `quiesce_local_model`, `quiescence_canonical` and `quiescence_ref` matched the exact frozen 0001/0002 migration source. QA did not apply DDL. Host tests reject rehashed invalid output/schema substitution, require authenticated published owner scope, count RUNNING work correctly and keep model request IDs unique across missions.

## Independent semantic oracle

`maintenance-oracle.mjs` exports `evaluateMaintenanceArtifact({fixture, phase, output, artifact_digest, plan?, draft?, task?})`. It returns PASS/FAIL, the five frozen rubric checks, evidence digest and oracle source digest. SHA-256: `05573cd3d05bcd2161f80129c6191d045f6b4d880e4a863fe031eb0808321cf3`.

Parse checks exact canonical source/cases only. Head checks two executor kinds, semantic-after-parse dependencies, criteria, protected scope/grant metadata and input preservation. Review checks the lexical-sort defect and a safe unimplemented ascending comparison proposal. Seeded missing dependencies, false-success/reversed analysis, changed source/digest, producer/QA subject collision and wrong phase capability are rejected. Separate native QA role, stored result/artifact/schema commitments and frozen plan digest are required at persistence. No generated code is evaluated by this oracle.

## Publication safety

Original 449 files (3,111,056 bytes) were independently compared with source Git blobs at `c6c2db24c4648d96fd93c8fe7da63ba98dd9af19`: all source/export/manifest hashes agreed. Read-only source operations used `git --no-optional-locks`. Initial inventory had no copied `.git`, symlink, special file, binary, PGDATA or receipt/evidence/delivery/checkpoint tree. Secret/PII-shaped matches were manually classified as denial canaries, negative URLs, code variables/policy strings or SVG coordinates; no real secret/contact/private-key body was found.

Historical host metadata in two runtime locks and `tests/security/fixtures/initial-baseline-check.json` was omitted. New disabled lock templates contain null binary paths/hashes and fail before spawn. Eight added source assets match original blobs. The sole declared transformation in `INTEGRATION-01/adapters/int04-host.mjs` was exactly two textual changes deferring optional MASTER01 import into its explicit branch. A1 contracts and historical DENY profiles remained intact; original source was untouched.

Read-only initial-index review approved exactly 465 staged files and exact bytes: 454 source, 2 disabled templates, 5 root files, provenance, offline runner and 2 sanitized release summaries. No private/reference/scratch/raw-QA/new-A2/A3 path was staged. Initial `export-index-review.json` SHA-256: `2267000a85d0ce6880c2161c35f6ad4127eb306b7a5c938d8210a217beebcc35`. This is the baseline verdict. The separate `PUBLICATION-REVIEW.json` records the exact final A2/A3 index verdict; publication applies only to its reviewed path/hash set.

Recommended QA source/final-log/sanitized-summary paths are in `PUBLICATION-PATHS.txt`. Exclude `.private/**`, `.reference/**`, all `.local/**`, native big readbacks, old raw export scans and early/partial failure TAPs. Source helpers retain historical development-path literals and were not executed. Automated scanning/manual classification reduce disclosure risk without proving arbitrary semantic PII absence.

## Limits

These results establish a bounded synthetic maintenance planning/analysis path on the scoped local E1 resource. The seed helper remains unchanged, helper function tests are NOT_RUN, and no autonomous coding/GitHub action occurred. Hostile same-host isolation and global cross-project GPU admission are not proved by process-local/model and project-scoped controls. Tests lasted seconds, not a 24-hour recovery/production campaign. G4/G5/G6, paid/cloud routes, real external effects and owner/D08 acceptance remain outside this result.
