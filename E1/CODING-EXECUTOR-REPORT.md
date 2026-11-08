# CodingExecutor preparation

Status: **IMPLEMENTED contract/port composition; TESTED_OFFLINE with actual disposable Git; LIVE coding task WAIT**. AWE self-development is **NOT_VERIFIED**. No actual GitHub issue was selected or read, and no real repository branch, PR, merge, deployment or production release was created by this work.

## Concrete interface

`E1/executors/coding/index.mjs` exports `createCodingExecutor`, `validateCodingTaskGrant`, `validatePatchProposal`, `PATCH_PROPOSAL_SCHEMA`, its canonical digest and frozen-artifact helpers. It does not change the broker, A1 schemas, A2 migration chain or existing composition root.

```js
const executor = createCodingExecutor({
  authority, githubReader, modelPort, gitPort, testRunner, qaPort, publisher,
  clock, hostProtectedRoots
});
const result = await executor.run({grant_ref, context, attempt_scope});
```

The authority resolves an opaque grant reference under an authenticated owner context and is rechecked before every step. Raw grant JSON is data validation, not authentication. A grant fixes repository owner/name, issue number, base commit SHA, codex branch prefix, exact file paths (no globs), model capability/version/route/output-schema digest, fixed test capability/version/command digest/timeout, zero paid-API budget, validity deadline, one model attempt, maximum steps, file count and patch bytes. Required permissions cannot be widened by the model. The current preparation allows only the already-authorized local Qwen route; no cloud fallback.

Ports must identify a live scoped host profile. The public live factory rejects labelled offline ports. The explicitly named test factory is available only from `executor.mjs`, requires `OFFLINE_TEST_DOUBLE`, and emits that profile with `accepted=false`, `self_development_verified=false` and zero external mutations.

## Enforcement and flow

1. Resolve and validate the owner grant and mandatory ports. Missing actual grant, scoped publisher or safe OS runner yields WAIT before issue/model/worktree calls.
2. Read exactly the granted issue through a trusted read port. Verify repository, issue number and issue-content digest. Inspect the pinned Git base and exact allowlist through a trusted Git port.
3. Call a mandatory accounted patch-model port once. It must bind the A2 attempt scope and return native `CONFIRMED`, actual usage/cost, one attempt, and the pinned model ID/digest. The engine creates no ledger and holds no database credential. The future host adapter must use the SAME A2 D09 port; it is not implemented as a side account.
4. Accept only a structured full-file patch proposal: base SHA, summary and changed paths with before-byte digests and replacement UTF-8 text (`ABSENT` for a new file). The schema passes unchanged A1 `inspectBoundSchema`; protected owner/grant/test/shell/acceptance fields are absent. Paths reject traversal, absolute paths, backslashes, ADS/URL encodings, Windows aliases/trailing dots, case duplicates, symlinks and unknown ancestry. Protected runtime/core, authority, broker, credentials, Git metadata and workflow paths cannot be granted by this interface. Host protection can narrow further.
5. Verify byte limits/digests, create an isolated codex branch/worktree via the trusted Git port, apply only the validated patch, then independently read back exact changed paths and bytes. A committed, clean isolated head different from the base is mandatory; an uncommitted working tree cannot become a PR intent.
6. Run only fixed granted test IDs/command digests through a network-DENY OS sandbox port. The model cannot supply argv or shell. Test deadlines must fit the remaining grant; deadlines are also passed to the host ports. Failed tests stop before QA/publisher.
7. Freeze patch/tests/source/model-receipt/rubric digests into an artifact. Require a different QA principal, the exact frozen artifact/rubric and a PASS verdict. The model and producer cannot set accepted=true.
8. Prepare a scoped draft-PR intent with repository/issue/base/head/branch/artifact/QA/grant pins. The publisher port has only `prepareDraftIntent`; automatic merge and production release are false. Preparation must report zero external mutations. Actual dispatch is a future explicitly granted host/D09 publication gate.

## Verification

`node --test E1/tests/executors/coding.test.mjs`: **14/14 PASS** after a narrow sandbox escalation for disposable Git fixture writes. The sandbox initially denied writing temporary `.git/config`; no current repository Git operation was attempted. Every fixture is created under a verified `awe-e1-coding-unit-*` temporary root and removed only after checking that absolute root again.

After fixing the test clock and replacing the canned QA outcome with a real decimal holdout, the affected positive/holdout tests were rerun with `--test-name-pattern='temporary Git|independent QA holdout'`: **2/2 PASS**.

The local Git positive case has a real failing numerical-sort regression on the base, a real isolated worktree/branch and committed fixed code, a passing regression after the patch, unchanged base working copy and no remotes. A native Git symlink tree entry is rejected before model/worktree creation. A seeded truncating comparator passes the producer's integer regressions but fails a separate decimal-order QA holdout; the independent role also recomputes the frozen artifact digest and prevents the draft intent. Other negatives cover path/base/byte/digest/core/permissions/paid-route changes, unaccounted model output, missing publisher, owner revocation before mutation, failing tests and profile confusion.

Model/accounting/QA/publisher in this command are explicitly offline doubles. The test runner executes only controlled synthetic fixture code; its OS-sandbox attestation is a unit double. This proves fixed orchestration and fail-before/pass-after for that fixture, **not** Windows/WSL isolation, a live model patch, native D09 coding accounting, real GitHub read/write, independent production QA or unattended self-development.

## Exact live blockers and next gate

- Owner has not selected an actual repository/issue/base SHA and exact safe path allowlist or issued the authenticated coding task grant.
- `e1.coding.patch` is a prepared output-schema contract, not a registered/approved live A3 capability. Its clean-code input classification/redaction adapter, versioned code pin, health/canary and A2 claimed-task binding remain NOT_BOUND. The broker source remains frozen for the separate Head canary.
- An actual least-privilege OS sandbox runner, isolated Git credential-free host port and fixed approved test capability bindings remain NOT_BOUND. The unit fixture is not a security sandbox.
- A real scoped issue reader, independent QA identity/key/rubric and idempotent D09-backed draft-PR intent publisher remain NOT_BOUND. The leaf receives none of their credentials.
- First real coding acceptance needs native A2 accounting plus actual model output, pinned safe repository task, observed tests and frozen-artifact QA, then a separately authorized scoped draft publication. No automatic merge or production release is available.

Until those ports and owner policy exist, the production interface returns WAIT/BLOCK; the test path cannot establish live acceptance.
