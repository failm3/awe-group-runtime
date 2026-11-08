# Issue 3 independent QA

Status: **PASS for the tested offline and native synthetic boundaries; NO-GO for paid Router.Cheap execution.** This is a technical candidate, not cloud mission completion or owner acceptance.

QA owns only `E1/qa3/**`. Implementation authors own the cloud adapter, host helper and additive D09 migration. Base: `09f1a864e6fa26afa62ffac3249c6532a6116175`; branch: `codex/e1-router-cheap-issue3-20261108`.

## Evidence and scope

| Check | Result | Practical meaning |
|---|---|---|
| Independent cloud/pricing/funding/host boundary tests | 29/29 PASS, zero skips | Mock transports only; network and subprocess dispatch blocked by preload |
| Public-only clean export | 29/29 PASS, zero skips | No `.private`, Git checkout, host descriptor or host configuration needed for offline tests |
| Host helper synthetic custody/discovery tests | 7/7 PASS | All secret filesystem operations and discovery requests mocked; audit hook rejects real key reads, network and subprocess dispatch |
| Independent native E1 PostgreSQL and broker integration | 9/9 PASS, zero skips | Real D09 transactions with unique synthetic `prj_qa3_*` projects and fake provider charges |
| Native execution owner | Root runner | Existing E1 resource, port 5433; QA test code performs no migrations or cluster lifecycle operations |
| Source preservation | PASS | Eleven original broker/Ollama, infra, host and frozen migration files equal base; no changes under `awe`, `contracts`, `baseline` |
| Actual Router.Cheap generation | NOT_RUN | Zero provider generation calls in QA; host transport remains disabled |
| Original maintenance mission with cloud Head/delegation/QA | NOT_RUN | Adapter and ledger tests do not establish that mission end to end |

`SUMMARY.json` contains compact command results, source stability and output hashes. `SOURCE-PINS.json` binds the reviewed implementation and test sources. `OFFLINE.tap`, `NATIVE.tap`, `HOST-SYNTHETIC.log` and `NATIVE-REVIEW.json` contain the reviewed public evidence. Native evidence contains synthetic scopes and amounts only. These amounts are ledger fixtures, not payments.

The published host log is normalized from CRLF to LF for source publication. Its original captured-output hash and run times remain recorded; a separate published-log hash binds the normalized bytes. This formatting change is not a new test run.

The final host metadata amendment adds two fixed GET negatives. Root's reviewed `E1/evidence3/READONLY-PREFLIGHT-FINAL.json` records HTTP 401 for the unauthenticated catalogue and HTTP 404 for the authenticated nonexistent-model metadata lookup. QA repeated all 7 synthetic helper cases and 29 offline cases against the current helper. The latest native 9/9 rerun covers the final financial-readback migration and updated assertions; it never executes the Python discovery helper. Current source pins bind both independently tested boundaries. These HTTP results establish metadata rejection behavior, not a generation, token usage or charge proof.

## Independent adversarial coverage

The offline suite covers exact rational arithmetic, rounding once after cache subtraction and source coefficient application, cache prices above ordinary input prices, the maximum reserve across eligible sources, fractions beyond JavaScript's safe integer precision, absent prices/factors/evidence, stale or future catalogues, duplicate identities, wrong origins, unknown features and token limits. It also checks the full serialized request, including the output schema, reaches the trusted input-bound verifier.

The broker tests cover privacy labels and credential-like text, protected input additions, response schema injection, redirects and wrong response origins, response content type and size, malformed JSON, missing input/output/cache usage, mismatched model or source, missing or estimated charge evidence and inconsistent billed amounts. Any possible send or uncertain durable marker becomes HOLD/UNKNOWN. A known exact charge settles once before malformed or truncated structured output becomes REPAIR. Lost reserve, SENDING and settlement acknowledgements do not create a second POST. Revalidation runs after reserve and after SENDING; concurrent and repeated logical requests dispatch at most once.

The native suite composes the offline cloud broker with the actual D09 coordinator and additive `0003` transaction wrapper. One fake provider response reserves 150 fixture micros, records input/cache/output counts 3/1/2, settles exactly 4 fixture micros, and records one attempt and quota unit. The output remains `accepted=false` and requires independent mission QA.

Two projects on independent native sessions race against a shared cap of 220 fixture micros: one 150-micro reservation succeeds, one fails, and the rejected transaction leaves no attempt or quota debit. Proven no-send release clears funding exposure but does not reset the lifetime attempt counter. Cold sessions retain UNKNOWN reservations, quota and HOLD; refund and blind retry fail. Revocation, project and fence substitution cannot mark a send. Quote, snapshot, factor-reference and charge-evidence substitutions fail before a valid idempotent settlement. An observed synthetic charge above reserve becomes a durable shared HOLD while exposure remains reserved. Native ACLs deny direct frozen-command bypass and worker/QA funding or table access. The final native oracle also checks that the SQL fraction `9007199254740993/9007199254740992` rounds up to 2 for one token.

The final financial readback distinguishes booked confirmed charges from observed unconfirmed charges. A synthetic observed charge of 151 against reserve 150 reads `booked_confirmed_micros="0"`, `observed_held_charge_micros="151"`, `observed_overrun_micros="1"`, zero attempts lacking an observed charge, and HOLD. Compatibility field `spent=0` therefore means no booked confirmed charge, not zero observed cost. A lost ACK instead retains `actual_charged_micros=null` and one `unknown_charge_attempts`, with explicit `UNKNOWN_NOT_ZERO` semantics. All three amount fields use exact decimal strings; held observations exclude confirmed attempts, and overrun sums only the positive difference per held attempt.

## Findings corrected during review

| Finding | Correction and evidence |
|---|---|
| Provider-controlled field names and freeform billing expressions could enter discovery metadata | Field names filtered; expression reduced to digest and `UNVERIFIED_NO_EVAL`; synthetic injection regression passes |
| Ancestor `lstat` followed by an absolute secret open left a path race and did not pin parent ownership | Directory-descriptor walk, `O_NOFOLLOW`, protected parent ownership/modes; synthetic custody regressions pass |
| Adapter route aliases/slash model IDs and SQL inferred route identity disagreed | Explicit model and route snapshot binding; combined native adapter test passes |
| Raw provider request ID and prefixed provider reference disagreed | Exact raw provider reference binding; combined settlement passes |
| Offline broker charge labels did not match native synthetic funding | Test path explicitly labels fake charges; live authenticated label remains separate |
| SQL settlement did not bind all frozen quote/snapshot/factor metadata | Exact binding and seeded substitution regressions pass |
| SQL price fraction bounds were narrower than the adapter's rational contract | Separate exact NUMERIC fractions; final charged amounts remain bounded; native beyond-safe-integer oracle passes |
| Compatibility `spent=0` could obscure an observed charge on HOLD or an unknown charge | Separate exact booked/observed-held/overrun strings and unknown-charge count; existing UNKNOWN and overcharge native cases verify their explicit semantics |

No correction grants spending authority. The host policy factory still refuses to mint a policy, the trusted host transport refuses paid sends, and its input-bound verifier returns false.

`request_charge_cap_micros` in the synthetic ledger request is a local quote/accounting bound. No actual provider request-charge-cap field or header is transmitted. A maximum supported request cap in a future provider proof does not establish that a particular paid request has that cap applied. Paid activation requires an enforceable provider contract and request binding.

## Paid execution and handoff readiness

| Required evidence or boundary | Current state | Requirement for a bounded Astra-led mission test |
|---|---|---|
| Catalogue/metadata GET | Discovery only | Keep observations separate from generation, consumption and charged-cost proof |
| Nominal key limit of USD 10 | Actual-charge guarantee UNVERIFIED | Verify enforcement after every applicable source/cache/model coefficient and a hard request-charge bound |
| Exact authenticated owner funding grant | NOT_ISSUED | Bind project/mission, key/account, total, per-attempt amount, lifetime attempts and expiry to the owner's exact authorization |
| USD 30 total / USD 3 attempt / 15 attempts proposal | NOT_AUTHORIZATION | A proposal or test fixture cannot fund a real key |
| Provider input-token upper bound for the complete request | UNVERIFIED | Verify an upper bound for the full serialized request and schema under the pinned model |
| Exact source identity, usage/cache counts and actual charged ACK | UNVERIFIED | Pin and verify a provider contract; never substitute a price estimate for a billed receipt |
| Host-bound native accounting | Tested with real coordinator in synthetic integration; future live binding unresolved | Bind the live host capability to its owning native coordinator/accounting port before any policy-minting or paid-send path can be enabled |
| Original mission state and independent QA | Cloud mission NOT_RUN | Revalidate current worktree/source, publication, grant, claim/fence, frozen artefacts and independent QA/owner acceptance |

The public live factory currently accepts an accounting-method object after validating opaque host transport/policy capabilities. It has no active paid policy today, so this is a future activation blocker, not an observed live spending bypass. Enabling a future host policy must also bind native accounting; a fake accounting port cannot become a live authority.

Astra can use these tests and the existing frozen maintenance rubric to lead the next bounded mission exercise. A paid exercise remains gated by the missing evidence above. There is no automatic provider fallback or blind retry. The preserved Ollama profile remains the default local policy; QA did not rerun actual Ollama inference or turn its source preservation into a fresh runtime claim.

## Reproduction and publication

From a public source export with Node 24.21.0:

```text
node E1/qa3/run-offline.mjs E1/qa3/pricing-adversarial.test.mjs E1/qa3/funding-adversarial.test.mjs E1/qa3/broker-adversarial.test.mjs E1/qa3/host-boundary.test.mjs
node E1/qa3/verify-portability.mjs
```

With Python 3 available, `node E1/qa3/run-host-synthetic.mjs` runs synthetic helper tests. `QA3_PYTHON` may select the Python executable; it supplies no host or provider configuration. The native command is `node E1/qa3/run-native.mjs`; it intentionally requires the existing verified E1 descriptor and approved host transport. A public export does not contain that descriptor and cannot silently retarget a database. Never run native tests as a substitute for authorization or install migrations from the QA suite.

Publish only the exact paths in `PUBLICATION-REVIEW.json`. Exclude `.private`, `.reference`, `.portable`, keys, PGDATA, host configuration, raw provider bodies, raw runtime receipts and the local full command records. No credential value was read, copied or displayed by QA. No E0 runtime, provider generation, physical dispatch, account change or cluster lifecycle action was performed by QA.
