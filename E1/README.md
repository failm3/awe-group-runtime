# AWE E1: A1 contracts and C1 preparation

This is the `AWE_E1/1` contract and infrastructure preparation slice. It is not an autonomous worker runtime. A1 is `TESTED_OFFLINE` after the named suites pass. C1 live database, identities, vault, model and authority availability remain `BLOCKED` or `UNKNOWN`. The composition exposes no dispatch or acceptance port.

Development branch: `codex/awe-e1-a1-c1-20261108`, separate worktree `51d0`. The original E0 worktree `92ef` is read-only. Evidence base is `3579aeeda379caf78dafe5351704956f1ecc0ea5`; executed E0 runtime source is `c53d1fb3606218a4f3961f37f57ebc41ac6681ef`. See [source provenance](release/source-provenance.json) and [baseline verification](evidence/baseline-verification.json).

Run with Node 24.21.0, npm 11.19.0, without installing dependencies:

```powershell
npm --prefix E1 test
npm --prefix E1 run examples
npm --prefix E1 run preflight
node E1/cli.mjs schema MissionSpec
```

The two fictional examples call the same `createE1Composition` and `prepareMission` path. They have different projects and domain manifests, identical core build digest, independent branches and dependent joins. The result is `PUBLISHED_PREFLIGHT_ONLY`, `accepted=false`, `execution_authorized=false`, zero effects. No task is executed. Their fixed synthetic clock is printed explicitly.

The administrator CLI also accepts supplied mission data, using the current clock:

```powershell
node E1/cli.mjs prepare mission.json trusted-bootstrap.json infra-config.json
```

`mission.json` contains exactly `spec`, `grant`, `plan`. `trusted-bootstrap.json` contains exactly `principals`, `capabilities`, `domainManifests`, and `actors` (`owner`, `head`, `coordinator`). Bootstrap is a trusted local configuration, not a remote authentication channel. The CLI creates opaque offline contexts; serializing an actor does not authorize it. Config pins the project and declared owner/coordinator/QA identities. A2/SEC must supply real authenticated principals and durable rechecks before any execution. Keep supplied private input files outside Git.

Contract schemas and canonical hashes are owned by [A1](contracts/index.mjs); [mission ingress](mission/ingress.mjs) owns bounded proposals, validation and append-only local history. It reuses the existing canonicalization and DAG validator. It creates no alternate scheduler or budget ledger. Mission revisions invalidate publication; revocation stops further planning; publishing rechecks grant, capabilities, domain manifest, schema bindings and current time. Only D03/D09 in A2 may persist, claim and reserve execution.

C1 offers strict disabled-resource configuration, path/origin checks, declared identities, scoped handle fixtures, a fixed local fixture process, content-addressed object copy/restore, sanitized health and guarded SQL preparation. See [infrastructure runbook](infra/RUNBOOK.md). The process proves fixture lifecycle/checkpoint behavior only. PostgreSQL migrations and backup restore have not run. JavaScript interception is a regression guard, not an OS sandbox.

Historical E0 profiles and tests remain intact. `AUTO01_MOCK_ONLY` and `LOOPBACK_MOCK` are unchanged. Test evidence is in [TEST-RESULTS.json](evidence/TEST-RESULTS.json), with raw TAP and hashes. [Independent QA](qa/REPORT.md) is a separate Codex developer context, not a D08 signature or owner acceptance.

Runtime publication is stopped under the owner's prepublication condition. The preserved ancestor history contains E0 private metadata/receipts. No runtime history is pushed or rewritten. Sanitized outcome documentation can be synchronized to Academy. The owner must decide how to handle closed historical evidence before a runtime repository and PR can be populated.

Next parallel work: A2 durable D03/D09 claim/reserve/recovery contracts and A3 registry/model adapter preparation can use these interfaces. Their live integration requires a separately authorized E1 PostgreSQL and measured model endpoint. B1 source/fact preparation can proceed independently; applications and publication still require explicit live scope.
