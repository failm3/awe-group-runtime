# Cloud financial authorization v4

Owner financial consent is **ISSUED** under the consolidated live
[Issue 3](https://github.com/failm3/awe-group-runtime/issues/3) and
[Issue 4](https://github.com/failm3/awe-group-runtime/issues/4) directives updated
2026-11-08 03:57:57Z / 03:58:00Z. The current technical status is
**PREPARED_PROVIDER_BLOCKED**, not missing owner consent and not completed paid
integration. All source changes here are Codex engineering work; they are not
AWE-generated mission artifacts. Actual SANDBOX-RECRUIT-01 runtime evidence is
reported separately by the mission supervisor.

## Approved bounded policy

- USD 10 actual cumulative charges across all authorized projects/agents/routes.
- Canary: two distinct fixed routes, at most USD 0.25 each and USD 0.50 pooled.
- Independently accepted canary permits at most USD 9.50 for followup, USD 1 per
  request and 20 further attempts; same key, same cumulative 22-attempt accounting.
- One wire attempt; no fallback or blind retry; UNKNOWN or charge overrun holds
  the whole authorization. USD 21 of the owner's reported balance stays
  unallocated. No refill, account/key settings change or provider fund transfer.

The reported balance is not a new independently measured account balance. These
limits authorize work; they do not prove Router.cheap enforces actual debits.

## Actual host and native preparation

Root created a new Ed25519 authorization signing key under WSL `nox`, mode 0600.
Its private value stayed in the protected host file; only public SPKI/signatures
were exported. This is separate from the Router.cheap credential, which this
stream never reads. The signing helper verifies owner, mode, regular/single-link
file status and non-writable non-symlink ancestors. It passes a protected FD to
OpenSSL and emits only a bounded public signed receipt.

`prepare-authorization.mjs` resolves the verified authenticated GitHub snapshots
and chat ratification, authenticates an opaque COORDINATOR context through the
actual native host authority server, signs the exact mandate/limits/scope, and
persists it through the coordinator-only native preparation function. Provenance
is explicitly **HOST_ATTESTED_CHAT_AND_GITHUB_DELEGATION**; this is not a claim
of production human login or an independent provider attestation. Native SQL
enforces coordinator ACL and digest/shape/scope rules; Ed25519 verification and
the trusted public-key anchor are enforced by the host Node admission port.
Workers/QA cannot install authorization through RPC or direct table privileges.

Root executed the real host signer and preparation CLI successfully. The initial
authorization digest is
`sha256:ab0759a45e953ad01eafecf14ad455d7d9133b696979a80781c3e635c9060851`.
Its initial scope was exactly `prj_recruit_cycle01_4101`, native owner `e1_owner`,
same logical key `router_cheap_staging`. This initial project has insufficient
remaining quota for two paid canary tasks. The initial receipt must not be
described as authorizing every future project. Public safe receipts are in
`evidence/owner-authorization.json`, `evidence/owner-mandate.json` and
`evidence/authorization-readback.json`.

Additive 0004 guards the existing `cloud_attempt` rows and original funded row.
It stores authorization/phase, not a parallel money ledger. Native attempt
insertion/state transitions enforce the canary and followup caps. Phase exposure
is derived from the same confirmed charges, failed no-send records and retained
funded reservations. Unknown charging holds the authorization. Independent QA
promotion requires two confirmed distinct canary routes and matching native
independent PASS records; it preserves spend, reservations and attempt counts.
Existing unregistered v1/local keys retain their original behavior.

## Prepared-only same-key scope amendment

Additive 0005 permits only an authenticated signed **scope expansion**, on the
same key and owner, while state is PREPARED_PROVIDER_BLOCKED and there is no
funding row or cloud-attempt row for that key. Existing local Ollama attempts do
not count as cloud attempts. The previous authorization digest is a CAS token;
issuer/public anchor, mandate, limits and evidence mode remain fixed, expiry
cannot increase, and previous signed receipts remain in immutable coordinator-
inaccessible history. No project removal, key alias, recharge or counter reset
is allowed. A budget-table lock and current-authorization funding-insert guard
serialize concurrent amendment/provisioning and reject stale funding documents.

Scope amendment does not require new owner consent within the already approved
mandate. Root executed the genuine signed native amendment and cold history/
readback. Revision 2 has digest
`sha256:e88054feccd4ed7a4a7af9ff61b57e5f2f8d50773a82c4142ee5fcfa033b0372`.
Its six authorized project IDs are `prj_cloud_canary_20261108`,
`prj_recruit_cycle01_4101`, `prj_recruit_cycle02_4101`,
`prj_recruit_cycle03_4101`, `prj_recruit_cycle04_4101` and
`prj_recruit_score01_4101`. This is an explicit allowlist, not unrestricted future
project authority. Same key/owner/expiry and all cumulative limits remain
unchanged; state is PREPARED_PROVIDER_BLOCKED, funding is disabled and no counters
were reset. The host CLI is:

```powershell
node E1/cloud4/amend-scope.mjs --projects prj_recruit_cycle01_4101,prj_recruit_cycle02_4101,prj_recruit_cycle03_4101,prj_recruit_cycle04_4101,prj_recruit_score01_4101,prj_cloud_canary_20261108
```

## Objective paid-provider blocker

Fresh public-only API documentation and pricing were obtained by root without
Authorization or credential access. The reference documents key-level usage
figures and request identifiers, but does not establish a coefficient-adjusted
actual-debit hard ceiling or a supported per-request dollar cap. Undocumented
request fields may pass through without enforcement. Request cost is described
in the dashboard journal; a source-and-actual-charge ACK or public charge lookup
contract is not documented. Model aliases and changing prices add verification
requirements. This is a missing guarantee, not proof the provider necessarily
overcharges. [Official API reference](https://router.cheap/reference/api.ru.md),
[public pricing](https://router.cheap/api/pricing),
[security guidance](https://router.cheap/security).

Public source digests: API
`8fc49ae8803a5a763a55600364139e201b7d9d3f1eca281689066bce1102645c`;
pricing `383911469159ab647f0133f587fa329a2e944bc02b2857203614a20fd8ee8bdc`.
Full external documents stay in excluded `.reference/`, not the publication.

Therefore paid send remains **DISABLED**. `createCloud4LiveBinding` returns the
objective provider blocker, with zero wire calls, even when a caller supplies
JSON claiming verification. It is a blocked binding candidate, not a completed
live provider transport. No fabricated source prices, input bound, hard-cap
proof or charged ACK activates it. Real native funding remains disabled; signed
owner authorization is persisted separately. Actual paid generations: **0**.

## Verification and limitations

Root applied additive 0004 to the pre-existing E1 resource on port 5433 after
independent static QA. Its SHA-256 is
`6ba41950ec39790d01565cc55b7c315b783465d300e877e73b87858cfb695034`.
Root also applied 0005 at SHA-256
`e0efa1802a2a0a90ad478b1c5a339e2c34665ef5949622be38af54e192686f39`.
Applied 0001 through 0005, the old psql transport, and Ollama source remain
unchanged after their respective freezes.

- Guarded author/independent pure checks: **11/11 PASS** (7 author + 4 QA).
- Root actual PostgreSQL phase suite: **6/6 PASS**, zero skips, including parent.
  It used explicit synthetic signing keys/provider proofs/charged costs, actual
  native host opaque contexts, two distinct fake-model routes and real native QA
  records. It proved prepared denial, phase substitution denial, two-attempt
  canary limit, independent promotion without reset, and pooled UNKNOWN HOLD.
- The initial genuine host signing/preparation command succeeded with no Router
  key access or provider calls. No paid quality canary is claimed.
- Root actual PostgreSQL scope suite: **4/4 PASS**, zero skips, including parent.
  Two real backends produced one accepted CAS and one stale rejection; prior
  receipt history/cold lineage persisted; stale funding and amendments even to
  a zero-spend funded key were denied; worker/QA privileges remained denied.

Subsequent lock review found an invalid-funded-amendment edge: 0005 could hold
the budget-table lock while waiting for an authorization row held by a reserve,
whose later budget write needed that table lock. Rejection stayed fail closed,
but the unnecessary wait could create a database deadlock. Additive 0006 fixes
only that order by rejecting an existing funded key before taking the
authorization-row lock. It preserves all phase/accounting/scope semantics and
existing ACL. The prepared 0006 SHA-256 is
`d88d8289b8d4b29a1d301e54723570af7e4c9018fc528288ee43098047dae303`.
Root applied it after independent static clearance. The actual native concurrency
oracle **passed 1/1, zero skips**: two backends held real native budget/auth locks,
the funded amendment rejected while the authorization lock remained held, and
the other backend committed a real reserve of 40 synthetic micros/one attempt.
Proven no-send cleanup released the reservation and retained the used attempt.
No provider wire occurred. The rejection completed in 33 ms in this test; this
is a lock-order observation, not a general performance claim.

The three author native suites therefore report **11/11 PASS** (6 phase + 4
scope + 1 lock-order). Independent QA replay of the same frozen financial suite
also passed **11/11, zero skips**, at 04:36:28–04:36:31Z, with source stability
confirmed and zero provider calls/key reads/DDL. These are the same cases, not
22 distinct tests. See `E1/qa4/FINANCE-NATIVE.json` and
`E1/qa4/FINANCE-NATIVE.tap`. Compact, credential-free
evidence is `evidence/FINANCIAL-REVIEW.json`; the current genuine Ed25519 owner
receipt was independently verified locally against the host public pin when
that compact review was created. It records the six-project revision, retained
history, exact signed caps, zero actual funding/paid calls, and clearly labeled
synthetic native test charges. The original v1 missing-funding diagnostic is a
generic legacy field; it does not revoke the newly signed owner consent.

QA found a stale-context/mandate admission defect. The host admission now
revalidates principal identity/role/project and the current mandate, as well as
signature and expiry, before every privileged operation; the independent
revocation tests pass. A supplied object `kind` is not proof of a trusted native
transport, and all binding labels remain blocked until actual live contracts
are established.

`operations/disable-cloud4.sql` and `operations/disable-cloud5.sql` are
**PREPARED_NOT_RUN** guarded admin operations. They preserve authorization
history, funding, attempts, UNKNOWN liabilities and cursor evidence. They revoke
new privileged transitions while retaining settlement/reconciliation/local
operations. Neither deletes data, resets accounting nor regrants the legacy
unwrapped database entry point.
