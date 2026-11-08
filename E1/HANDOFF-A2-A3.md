# E1 A2/A3 handoff · 2026-11-08

The first bounded local AWE planning/analysis loop is verified with native PostgreSQL, actual local model responses, independent artifact QA and readback from a fresh OS process. E1 Pilot and owner acceptance remain **NOT_ACCEPTED / NOT_ISSUED**. The seeded helper was not fixed and no autonomous GitHub task was executed.

The owner authorized a new clean private runtime history and one isolated WSL PostgreSQL E1 test cluster. Main is the reviewed allowlist baseline `351719536815efcec25a56bc43c21525864f61a4`; development is `codex/e1-a2-a3-20261108`, through a PR with no merge. The original source HEAD is `c6c2db24c4648d96fd93c8fe7da63ba98dd9af19`, accepted offline A1 source `b689248952a3282fdda0b9f020f4cc014f610926`, E0 runtime `c53d1fb3606218a4f3961f37f57ebc41ac6681ef`, recorded E0 evidence `3579aeeda379caf78dafe5351704956f1ecc0ea5`. No original Git objects/history were imported. See [export provenance](../release/EXPORT-PROVENANCE.json).

Three separate Codex subagent contexts actually worked in parallel: `coordinator_a2` owned coordinator/migrations/tests; `broker_a3` owned registry/model adapter/tests and then the separate prepared Coding Executor scope; `qa_a2_a3` independently tested and reviewed under QA-only files. The root integrator owned host composition, resource operations, safe export, integration evidence, Git and publication. Agents did not edit the same files or Git index concurrently. These developer agents are not AWE runtime workers.

## Delivered and executed

| Component | Actual evidence |
|---|---|
| A1 compatibility | Existing universal mission/grant/plan/schema contracts and A/B fixtures retained; 373 clean-export baseline tests are included in the final offline command. |
| C1 resource | Separate PostgreSQL 18.6 in WSL Ubuntu, port 5433, separate Unix/peer roles and PGDATA. Clean/repeated migration, E1-only restart and synthetic backup/restore passed. A placeholder migration digest was corrected and re-exported/restored with the real SHA. [Evidence](evidence2/C1-PINNED-RESTORE.json) |
| A2 | One durable coordinator/ledger domain: claim/lease/fence, dependencies waiting for QA, transactional reservations/attempts/intents, shared project quotas/slots, cancel/revoke, inbox/cursor, cold readback and drained plan revisions. Real concurrent Windows workers and hard-kill takeover were tested. External effect fault cases use an explicitly fake provider. |
| A3 | Three bounded capabilities, script-first selection, pinned local Ollama model, mandatory A2 accounting, structured Head proposal and separate QA. Actual Head and review responses were independently read back from PG. [Actual QA](qa2/actual-contour-review.json) |
| Coding Executor | Grant-bound engine, isolated Git branch, red→green fixed tests and a separate decimal holdout rejecting a superficially passing seeded patch. Model, sandbox, accounting and publisher ports in these fixtures are explicit doubles. Live execution remains WAIT. [Report](CODING-EXECUTOR-REPORT.md) |

Final commands `node E1/verification/staging.mjs --offline` and `--native` passed **442/442 offline + 38/38 native**, zero fail/skip/cancel; source hashes were stable. [Offline record](evidence2/OFFLINE-TESTS.json) and [native record](evidence2/NATIVE-TESTS.json) include commands, counts, timestamps and output/source hashes. Independent QA repeated its **45/45** subset separately; these overlap the integrator suite and must not be added as unique tests. [QA command](qa2/all-final.command.json), [TAP](qa2/all-final.tap), [summary](qa2/SUMMARY.json).

## Actual model contour and failure handling

Mission `mission_code_compact_mw7543y4` used the ordinary A1 publish/admit path. A real Head response created revision 2 with two tasks; a fixed parser and actual semantic review executed them through A2 and separate QA processes. The generated plan was not prewritten by the integrator. Two current tasks and two archived bootstrap tasks have independently checked frozen result/artifact/schema commitments and QA PASS events.

| Actual model task | Input/output tokens | Latency | D09 |
|---|---|---|---|
| Head | 623 / 162 | 18,240 ms | CONFIRMED, one wire |
| Review | 144 / 235 | 13,800 ms | CONFIRMED, one wire |

Model `qwen3:4b-instruct`, digest `0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0`, Ollama 0.40.12; context 4096, output bound 512, timeout 120 seconds. Broker source pin `sha256:9e34868ec2bcdbbb7ec3627d5518942a2ec544b78e84fb2561741eee66082b9e`. Original registry health TTL was reused without extension. [Contour](evidence2/LOCAL-CONTOUR.json), [new-process readback](evidence2/COLD-READBACK.json). Authority PID 41440 exited; PID 6924 read COMPLETE, cursor 624 and persisted exact usage. Independent QA PID 32208 then reread and re-evaluated the frozen outputs without another model call.

The first separate mission `mission_code_live_mw745gdt` hit a real cold-inference timeout. Its single attempt remains OUTCOME_UNKNOWN, usage NULL, mission/task HOLD and quota unit 1 charged. No second send occurred. After completed provider cancellation and repeated idle/runner-absence observations, an audited direct-host operation freed only the physical execution slot and advanced the task fence; no quota, outcome or money was reset. [Failure](evidence2/FIRST-CANARY-HOLD.json), [operator observations](evidence2/ACTUAL-LOCAL-QUIESCENCE.json), [independent readback](qa2/actual-quiescence-review.json). Current project quota 3 equals the retained unknown unit plus two confirmed new requests; spent/reserved API micros are 0. Infrastructure, energy and orchestration costs are not measured.

## Errors corrected

- The exported AUTO compatibility host eagerly imported excluded closed historical PG bindings; the export now defers that optional profile import. Original source was not edited.
- A pre-wire validation failure after reservation leaked a reservation. A2 now releases it exactly once only on proven zero-send; ambiguous acknowledgements remain UNKNOWN.
- Persisted output needed actual schema/value validation, plus stored result/artifact/schema commitments at independent/cold readback. Negative substitutions and wrong types are rejected.
- Request IDs were reused across missions; host IDs now bind mission and task by canonical digest.
- Genuine complete `length` acknowledgements were misclassified UNKNOWN. They now settle real usage once and return REPAIR without accepting truncated output.
- Native bootstrap migrations now check the actual resource identity before any DDL. The integration runner explicitly enables the native suite and rejects skips.
- Health counts use the native RUNNING state; failed QA-session initialization closes its earlier coordinator session.

## Preservation, limits and next work

[Original preservation](evidence2/ORIGINAL-PRESERVATION.json) confirms the original source HEAD, no tracked changes, and E0/92ef's exact initial normalized status hash (97 untracked entries, unchanged). [Final isolation](evidence2/FINAL-ISOLATION.json) verifies nine preexisting PG processes unchanged, all four E1 Unix principals denied E0 data reads, E1 TCP/peer impersonation/other-database denials and zero E0 connections. PGDATA, dumps, full receipts, raw private logs and closed historical metadata stay outside publication.

These checks establish bounded local G1/G2/G3 behaviors, not full A2/A3 production acceptance. Worker force termination ran on Windows, not literal Linux kill -9. Project-scoped pools/process-local inference exclusion do not prove global cross-project GPU admission or hostile same-host isolation. Human AuthN, real vault, 24-hour soak, disaster recovery, broader cross-model/browser benchmark and G4/G5/G6 remain unverified. There were no paid/cloud calls, real applications, site publication, automatic merge or production release.

The next implementation streams can proceed in parallel with separate ownership: verified OS sandbox/fixed runner and patch-capability binding; global host resource admission/recovery/soak preparation; independent adversarial Coding Executor QA. A first actual self-development test additionally needs the owner's concrete GitHub issue, exact allowed paths/base SHA and bounded task grant. It must prepare a draft PR for independent review, without protected-core mutation, automatic merge or release. No new design project is proposed.
