# AWE E1 local integration

Current stage: **SANDBOX-RECRUIT-01 bounded synthetic mission PASS**, including one real AWE model-authored score function, actual bwrap execution and independent native/cold QA. Cloud owner authorization is **ISSUED**, technical state **PREPARED_PROVIDER_BLOCKED**; zero paid generations. [Outcome](SANDBOX-RECRUIT-REPORT.md) · [Resume](RESUME-SANDBOX-RECRUIT.md). Earlier Issue3 NOT_ISSUED entries describe the prior stage. E1 Pilot remains unaccepted.

Issue 3 adds a separate, **paid-disabled** Router.Cheap adapter and native shared cloud accounting. [Current cloud outcome and blockers](cloud/INTEGRATION-OUTCOME.md) · [Astra test-lead handoff](astra3/LEAD-HANDOFF.md). A model listing and the nominal USD 10 key limit do not establish live cloud completion.

This branch integrates the accepted offline A1 contracts with a native PostgreSQL coordinator (A2), a pinned local Ollama broker (A3), independent QA and a prepared Coding Executor. It is bounded local staging; E1 Pilot has not been accepted. See [A2](A2-REPORT.md), [A3](A3-REPORT.md), [independent QA](qa2/REPORT.md), [Coding Executor](CODING-EXECUTOR-REPORT.md) and [handoff](HANDOFF-A2-A3.md).

The repository is a new allowlist export with no E0 Git ancestry. [Export provenance](../release/EXPORT-PROVENANCE.json) records original source SHAs, exclusions, disabled runtime locks and one declared compatibility import transformation. Original worktrees and history remain local and untouched. Private metadata, receipts, PGDATA and original author metadata are excluded. Development branch: `codex/e1-a2-a3-20261108`. No merge or release is authorized.

Use Node 24.21.0/npm 11.19.0; no dependency install is needed:

```powershell
npm test
npm run test:e1:offline
```

`npm test` checks the clean-export compatibility baseline. `test:e1:offline` adds resource/proof boundaries, broker negative cases, stored artifact commitments, temporary Git Coding Executor tests and independent model/oracle regressions. All model responses in these tests are explicitly doubles. The final runner rejects any skip; some checks require actual filesystem junction/hardlink permission.

The separately authorized E1 resource must exist before native tests. Host-owned `.private/e1-resource.json` pins database, PGDATA, socket, port 5433 and peer roles. See the [native runbook](infra/native/README.md).

```powershell
node E1/host/migrate.mjs --authorized-e1-only .private/e1-resource.json
npm run test:e1:native
```

Native tests use actual PostgreSQL transactions and separate Windows processes. They check concurrent claims, dependencies gated by QA, force termination/takeover/fences, budget/quota races, ACL/project denials and persistent cursors/inbox. Fake-provider effects are explicitly labelled. These tests send no real external effect or model inference. Windows force termination does not establish Linux kill -9. One D03/D09 domain owns claims, accounting and canonical intents.

`createNativeE1Host` composes authenticated published A1 plans with native admission and scoped worker/QA ports. `createE1Composition` retains the A1 preflight-only entrypoint for two domain fixtures. No successful native result is substituted with a mock.

The manual local-model canary requires an explicit host command:

```powershell
node E1/host/maintenance-canary.mjs --authorized-local-canary .private/canary-run.json
```

The private configuration binds a unique suffix, frozen registryTime and fixed local limits. Reuse a still-valid registry binding within one project; changing a timestamp is not permission to lift health TTL or overwrite capability versions. An owner-supplied synthetic bootstrap accounts the Head request. Its model-generated typed revision, script dispatch, model review and separate QA process use normal contracts. The canary never executes generated code, fixes the seeded helper, uses a GitHub task or accepts itself. Actual results are in evidence2, separate from offline tests.

The first actual Head timed out during cold inference. Its HOLD/OUTCOME_UNKNOWN and charged quota remain recorded; approximate server counters are not usage. The manual quiesce-local operation needs completed local cancellation, repeated idle and runner-absence evidence. It releases only execution slots, preserving UNKNOWN, mission/task HOLD and accounting, with a new fence and no worker/BROKER/QA RPC. It cannot retry or resume that logical request. A complete length ACK instead settles genuine usage and returns REPAIR without accepting a truncated plan.

The prepared Coding Executor binds patch proposals, isolated Git worktrees, tests, independent QA and draft intents to an owner grant. Temporary Git red/green and a seeded decimal holdout are real local tests; their model/accounting/sandbox/publisher ports are explicit doubles. Live execution waits for a concrete authorized GitHub issue, accounted patch capability and verified OS sandbox. No autonomous GitHub PR or code fix is proven.

Trusted local bootstrap and loopback credentials do not prove production human AuthN or hostile-process isolation. Global cross-project GPU admission, 24-hour soak, disaster recovery, G4/G5/G6, production release and owner acceptance remain outside these results. Paid/cloud calls, real applications, site publication, auto merge and protected-core autonomous changes are not authorized.
