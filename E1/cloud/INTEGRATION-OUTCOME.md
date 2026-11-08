# Issue 3 · Router.Cheap · 2026-11-08

**PARTIAL_IMPLEMENTATION / NO_GO_PAID / CANARY_NOT_RUN.** The separate adapter and shared native D09 accounting are implemented and tested. Real authenticated discovery and billing metadata are verified. A paid host binding is deliberately disabled; it is not a completed live cloud integration. The original Career mission and E1 Pilot remain unaccepted.

Source base: `09f1a864e6fa26afa62ffac3249c6532a6116175`; branch `codex/e1-router-cheap-issue3-20261108`. The owner supplied a restricted WSL key file; no credential value entered Git, a model, worker, shell argument/environment, report or agent context. Only the dedicated trusted WSL helper reads it. The helper validates its owner, mode 0600, regular/single-link status and protected non-symlink ancestors using directory descriptors. It uses fixed GET paths, TLS verification, no proxy/redirect forwarding, bounded bodies and whitelisted output. Raw error bodies and exceptions are suppressed. Missing/fake host policy cannot activate spending.

## Actual provider observations

- Authenticated `GET /v1/models`: **75 models**. Candidate IDs include `gpt-6-sol`, `claude-opus-4-8`, `deepseek-v4-pro-0813`, `qwen3.8-27b`.
- Authenticated subscription metadata: **soft/hard/system hard limit USD 10**, expiry field 0. This is the compatibility API's key-level figure, not independently verified enforcement of post-coefficient account deductions. The official API reference also requires checking error envelopes even on HTTP 200.
- Authenticated usage metadata: **0 US cents**, at the captured time. No paid generation was submitted. The owner's reported account balance and separate OpenAI/Codex credits were not treated as equivalent funding.
- Metadata-only negatives: no Authorization → **401**; a fixed nonexistent model GET → **404**. These establish metadata access behavior, not generation/error billing semantics.
- Public pricing snapshot `a42d372ccf0b5dd13ecf71203521f9d2`: available source-relative factors for GPT range **3/4 to 5**, Claude **125/162 to 3125/504**. The payload also has separate `price_ratio` / balance-price fields; these must not be multiplied twice or assumed to equal actual charged USD.
- The public UI computes ordinary nominal input pricing from twice `model_ratio`, with separate completion/cache ratios. The observed rows include Claude `2.5 / 5 / 0.1` and Qwen `0.25 / 6 / 0.2` for model/completion/cache ratios. GPT-6 Sol and DeepSeek use tier expressions. These observations are **not an executable authenticated USD charge quote**. Unknown expressions are hashed and never evaluated. Account-selected sources, final billing conversion and exact charge receipts remain unverified.
- Chat is advertised for the candidate routes; strict per-model JSON schema, complete input-token bound and actual source/charge acknowledgement fields are not proven by the listing. Such unknowns block the executable catalog.

[Final sanitized readback](../evidence3/READONLY-PREFLIGHT-FINAL.json) · [initial readback](../evidence3/READONLY-PREFLIGHT.json) · [catalog status](catalog-status.json). Primary sources: [API reference](https://router.cheap/reference/api.ru.md), [public pricing](https://router.cheap/api/pricing), [API integration](https://router.cheap/openai-compatible-api), [security](https://router.cheap/security). The web text reader could not render the API reference; its actual public Markdown was obtained through HTTPS from the site's own documented page link. No other service named Router was used as evidence for Router.Cheap.

## Implemented and executed

| Area | Result |
|---|---|
| A3 separate adapter | Exact rational source/cache pricing, immutable quotes, bounds, privacy/schema checks, one wire attempt, mandatory reserve/SENDING/settle/UNKNOWN/no-send paths. Existing Ollama source/pin/default preserved. Live activation remains unavailable. |
| Native D09 | Additive guarded 0003, one atomic shared budget per key across projects, total/per-attempt/lifetime attempt limits, exact source/rate snapshots, idempotent settlement, request-ID uniqueness and retained unknown exposure. No parallel money authority. |
| Boundary tests | 29/29 independent offline; 7/7 synthetic host custody; 9/9 independent **actual PostgreSQL** integration. Cloud network replies and charged amounts in these tests are explicitly fake. Independent public-only replay also passed 29/29. |
| Author tests | 13/13 adapter, 8/8 policy/resource and 9/9 native ledger checks were executed. These overlap QA behavior and are not additional unique coverage totals. |
| Regression | 442/442 previous offline and 38/38 previous native checks passed on the upgraded branch, zero skips. No new real Ollama inference is claimed. |
| Real funding | Database readback: **0 authenticated funding rows**, reserved/spent 0; effective real caps 0/0/0. Only separately labelled synthetic keys were installed by tests. |

Native QA composed the actual coordinator with the explicit offline broker, checked concurrent projects/cold sessions, exact cache/factor arithmetic including a fraction beyond JS safe integers, atomic cap rejection, grant/fence/ACL denial, no refund/resend after UNKNOWN, and overcharge→HOLD without negative balances. The original database entry point is deliberately no longer a cloud-accounting bypass. Frozen 0001/0002 SQL and Ollama files are unchanged. See [QA](../qa3/REPORT.md), [native readback](../qa3/NATIVE-REVIEW.json), [funding](../evidence3/REAL-FUNDING-DISABLED.json), [D09 report](../coordinator/CLOUD-ACCOUNTING-REPORT.md).

Financial readback explicitly separates booked confirmed cost, known observed held charges, overrun and unknown-charge count. In the synthetic QA overcharge case these are **0 / 151 / 1 micros**, unknown count 0 and key HOLD; a lost ACK retains actual charge NULL and unknown count 1. Booked zero is never presented as zero actual cost. The aggregates come from the same D09 attempt rows and use exact decimal strings.

Rollback is a cloud-disable operation retaining the D09 shim and evidence. Rolling source back to the old psql entry point alone is unsupported; that would either fail ACL checks or bypass the new global ledger if permissions were naively restored. The guarded disable SQL is prepared and **not executed**. No tables, counters, unknown exposures or receipts are deleted or forgiven.

Fixed during independent integration: route/snapshot/schema mismatches, provider-request ID representation, fake-vs-real charge labels, quote/source evidence substitution checks, exact large-rational handling, and host metadata sanitization/redirect handling. A portable test/host guard keeps real credentials and paid endpoints out of offline verification.

## Paid stop gate and next action

The proposed canary is two fixed synthetic evaluations: GPT-6 Sol and Claude Opus 4.8, at most **USD 0.25 each / USD 0.50 total / two attempts**, with a local-Qwen comparison only when its separate binding is valid. This proposal is **NOT_ISSUED**, not permission or a verified price estimate. [Typed plan](canary-plan.json).

The owner/provider must first confirm enforceable actual-charge limits after all source/balance coefficients and issue an exact bounded spending grant. Technical work then needs verified normalized source prices/features, a charged-ACK lookup/contract, full request input bound and a live host capability bound to its actual native accounting port. Today `send` is disabled, the bound verifier returns false, and the host cannot mint a paid policy. Offline doubles and a successful GET cannot lift this gate. No charge or successful paid canary is invented.

## Astra handoff

`cloud_a3`, `cloud_d09` and `cloud_qa` actually ran in separate Codex contexts with exclusive file scopes. The integrator owned host discovery, key custody, resource operations and Git publication. Then **Astra was actually started as a Codex test lead**, not as a paid AWE cloud worker. She repeated 50 contract tests (a subset of the existing regression), and delivered the original Career M0 oracles and missing-authority matrix. The next zero-Router-cost exercise covers synthetic vacancy discovery/deduplication, source coverage and rejection of unsupported facts. [Astra handoff](../astra3/LEAD-HANDOFF.md).

No real applications, sites, production release, auto merge, new designer project, E0 PostgreSQL connection or E0 worktree mutation occurred. The dedicated key remains in its owner-controlled file. Paid API cost for this task is **zero generations; reported key usage 0 cents**. Provider account-wide balance changes, energy and Codex orchestration cost are not measured here.
