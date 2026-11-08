# E1 cloud accounting extension

Status: native E1 PostgreSQL candidate; real Router.cheap funding/send DISABLED.
This extends the preserved E1 baseline at `09f1a864e6fa26afa62ffac3249c6532a6116175`.
It does not accept production readiness or owner funding on the basis of local tests.

## Authority and accounting

`createAdmissionBridge` remains local-only by default. An explicitly versioned
`awe.e1.cloud-task-policy/1` may add exact `router.cheap.chat.*` routes. The policy
pins the current authenticated mission grant, funding grant, key identity, and
the complete immutable model/source/price snapshot. Re-admitting the same plan
cannot change its policy. Existing attempt history and quota are preserved.

`cloud_command` wraps the frozen `command` in one PostgreSQL transaction. The
coordinator and QA cannot execute the frozen implementation directly. A model
reservation therefore consumes the existing D03/D09 project/mission accounting
and the shared cloud funding row atomically. The shared group is fixed as
`router.cheap.shared/1`; all admitted projects sharing a host key consume the
same row. A unique provider account evidence binding prevents a second key alias
from minting another budget. This boundary is available to Issue 3 and future
Lab/Career M0 projects only when their project IDs appear in the same host grant.

Funding is a host-only operation exposed through an opaque
`createCloudBudgetAuthority`, not a worker RPC. It requires authenticated host,
verified bounded owner funding, a digest-bound provider hard **actual-charge**
cap, per-request hard-cap support, and unexpired evidence. The SQL function is
coordinator-only; workers and QA lack its privilege. Exact installation is
idempotent. No top-up, budget reset, history deletion, or replacement grant exists.
No funding row is installed by migration. A missing key returns DISABLED with
budget/per-attempt/attempts limits `0/0/0`.

`provider_limit_evidence.max_request_actual_charge_micros` denotes the maximum
**supported configurable request cap**, so it must cover the grant's per-attempt
cap. It is not evidence that a larger static enforced cap protects a smaller
reservation. Each reserve records a lower `request_charge_cap_micros` equal to
its reservation; this is currently internal accounting metadata. The broker does
not transmit or prove provider enforcement of that lower request cap. The paid
host transport is disabled, and verified actual provider request-cap binding
remains a blocking live contract.

Source/cache/output prices and source multipliers use exact rational arithmetic.
The reservation is the maximum conservative charge across all pinned sources,
with cache priced at the more expensive of cached/uncached input rates. Integer
NUMERIC multiplication, `div` and `mod` apply the final upward rounding once;
there is no floating-point or ppm approximation. Rational components support
36 decimal digits, while final accounting amounts stay within JavaScript's safe
integer range. Each reserve requires its provider request charge cap to equal
the reserved amount. Per-attempt, shared money and lifetime attempts limits are
checked while holding the shared funding row lock.

Settlement preserves the immutable route/quote, provider request ID, priced
usage, actual source multiplier/evidence and provider charged USD micros. Charge,
usage and source evidence must agree with the frozen quote. A charge above the
reservation or another charge/source mismatch becomes durable UNKNOWN/HOLD;
the observed charge is recorded, original money/quota remains reserved, and the
shared key is held. No negative balance or invented zero-cost settlement occurs.
Lost ACK/recovery preserves UNKNOWN and forbids blind retry or refund. Proven
no-send releases reserved money; the global lifetime attempt count remains used.

`cloudBudget()` exposes financial readback derived from the same existing
`cloud_attempt` rows, with no second ledger or changed debit/refund behavior:

| Field | Meaning |
| --- | --- |
| `spent` | Compatible numeric field for confirmed booked charges only |
| `booked_confirmed_micros` | Exact decimal string for the same booked amount |
| `observed_held_charge_micros` | Exact decimal string sum of observed charges on held UNKNOWN attempts |
| `observed_overrun_micros` | Exact decimal string sum of each held observed charge above its original reservation |
| `unknown_charge_attempts` | Count of SENDING/UNKNOWN attempts without an acknowledged charged-cost observation |
| `accounting_semantics` | Versioned field definitions, exact micro-USD encoding, and explicit `UNKNOWN_NOT_ZERO` interpretation |

The synthetic overcharge case reports booked `"0"`, observed held `"41"`,
overrun `"1"`, reserve `40`, unknown-charge count `0`, and key HOLD. It does not
report actual cost zero. A lost-ACK UNKNOWN without a charged-cost observation
reports unknown-charge count `1`; a zero sum of **observed** charges does not
resolve its actual cost, which remains UNKNOWN. The snapshot retains the
individual attempt's observed charge and evidence.

## Validation

The root applied only additive guarded `0003-cloud-accounting.sql` to the
pre-existing E1 resource on port 5433. There was no cluster creation/start/stop,
E0 access, key access, or Router.cheap request in this stream.

Author native command, executed by root with its authorized WSL transport:

```powershell
$env:AWE_E1_CLOUD_NATIVE_TEST='1'
$env:AWE_E1_CLOUD_EVIDENCE='E1/coordinator/evidence/cloud-ledger-native.json'
node --test --test-reporter=tap E1/tests/cloud-ledger/native.test.mjs
```

Final result against migration hash `ed2f7e3f7aff2598e29f08caf60a262370836b598b588a1b20b192ab57994676`:
**9 passed, 0 failed, 0 skipped**, including the parent test and the new financial
readback assertions. `evidence/cloud-ledger-native.tap` was copied from root's
successful `.private/cloud-tests/author-native-final.tap`. The raw JSON receipt
is retained locally for inspection and excluded from publication; the compact
independent review is `E1/qa3/NATIVE-REVIEW.json`. Every author-suite
funded native key is `synthetic_cloud_*`, every test project is `prj_cloud_*`, and
every charged value is explicitly labeled
`EXPLICIT_SYNTHETIC_FAKE_PROVIDER_CHARGED_COST`. Provider requests: **0**.

The native suite proves disabled zero limits, exact fractional/cache settlement,
atomic cross-project contention across independent PostgreSQL backends, cold
lost-ACK UNKNOWN retention, lifetime attempts bounds after proven no-send,
over-reservation charge HOLD, negative RPC/native ACL checks and default local
Ollama accounting regression. It does not prove provider behavior or actual
provider hard-cap semantics.

Offline local/policy/resource checks:

```powershell
node --require ./E1/qa3/offline-guard.cjs --test E1/tests/cloud-ledger/policy.test.mjs E1/tests/coordinator/resource.test.mjs E1/tests/coordinator/quiescence.test.mjs
```

Result: **8 passed, 0 failed, 0 skipped**. Independent QA and the complete old
native regression were also executed by root/QA against the final code:
**independent native QA 9/9**, including the combined fake-broker/native seam,
financial readback oracles, races and negative privilege cases; **legacy native
38/38**, with source stability confirmed. There were no failed or skipped tests
in either native run. Root's local logs are
`.private/cloud-tests/qa-native-financial-final.log` and
`.private/cloud-tests/legacy-native-final.log`; the published independent compact
evidence is `E1/qa3/NATIVE-REVIEW.json`, with the tested source available in Git.

Frozen source hashes (SHA-256):

| Source | SHA-256 |
| --- | --- |
| `migrations/0001-durable-runtime.sql` | `d0708161fc480b1489a89a93e1e3d7c508fbf6aeecefb642df380a69e3c78472` |
| `migrations/0002-local-model-quiescence.sql` | `379791e981bd5d0b40b28a60add314458c2b3837722aeb3e61fb74a36e1d5ee1` |
| `migrations/0003-cloud-accounting.sql` | `ed2f7e3f7aff2598e29f08caf60a262370836b598b588a1b20b192ab57994676` |

`git diff --exit-code` confirms 0001/0002 remain unchanged. No A1 or Ollama source
was edited by this stream.

## Disable and version rollback

`operations/disable-cloud.sql` is a **prepared, unexecuted** guarded E1-admin
procedure. Drain host funding-provision operations first. It holds existing
funded keys and removes coordinator funding-install privileges. It does not
delete attempts, forgive money/quota, reset counters/cursors, or remove tables.
Local Ollama operations and cloud settlement/UNKNOWN reconciliation continue
through `cloud_command`; new cloud reservations/sends fail closed.

This is a cloud-disable operation, not a destructive down migration. A code
rollback must retain the forward `psql-session`/coordinator shim that calls
`cloud_command`. Restoring raw old `09f1a864` database access while 0003 is
installed is BLOCKED: its direct `command` call is intentionally denied. Do not
restore that ACL, rename/rewrite frozen functions, or reapply the historical
migration alone to bypass the shared ledger. Forward reapplication of the normal
migration chain can restore provisioning privileges, so it is a separately
authorized operational change after disable.

## Remaining contract gap

There is no authenticated owner funding contract or verified provider enforcement
of an actual-after-source-coefficient hard charge cap for the real installation.
Nominal subscription/base-price limits do not satisfy that contract. Proposed
USD 30 / USD 3 / 15 settings are not installed authority. Real cloud generation
remains disabled with zero installed limits until both contracts are verified.
