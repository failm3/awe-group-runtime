# Separate Router.Cheap adapter

Status: **OFFLINE CANDIDATE; PAID CANARY BLOCKED.** This change adds a separate cloud adapter. It does not modify the existing Ollama broker, its model pin, or its disabled cloud fallback. No provider generation was performed by the adapter author. No credential or key file was read by the adapter author.

## Entry points and trust

`createCloudModelBroker({accounting, transport, policy, registry, clock?, timeoutMs?})` accepts only the opaque transport and policy capabilities validated by the fixed host modules in `E1/host/router-cheap/`. Raw functions, ordinary JSON policy objects, alternative endpoints and activation flags are rejected. The factory captures the authenticated transport methods and policy token so later mutation of the factory options cannot substitute a test transport. Host issuance and the provider secret remain outside `E1/cloud/`.

`createOfflineCloudModelBrokerForTests({accounting, registry, catalog, policy, clock?, timeoutMs?}, {transport, inputTokenBound, label: 'OFFLINE_TEST_DOUBLE'})` is a separate, explicit test boundary. It cannot mint host capabilities. All results retain `OFFLINE_TEST_DOUBLE`; its settlement charge label is `EXPLICIT_SYNTHETIC_FAKE_PROVIDER_CHARGED_COST`, even when a test response emulates the real acknowledgement shape.

`invoke` accepts the existing A1 mission/grant/capability/input binding and A2 attempt scope, plus `route_id`, `data_label`, `max_input_tokens` and `max_output_tokens`. A registered active LLM capability must explicitly permit the exact versioned cloud route. The fixed registered input/output schemas are reused through A1 validation. Only `SYNTHETIC` / `CLEAN_CODE`, PUBLIC / PROJECT data and OWNER / PROJECT origins are eligible. Credential-like input or personal email content is rejected before accounting or dispatch.

## Quotes and real charge accounting

`validateCloudCatalog` and `cloudQuote` accept only a complete normalized catalogue with the exact HTTPS endpoint `https://router.cheap/v1/chat/completions`, official-domain provenance, observation/expiry timestamps, model/source identities and explicitly confirmed required features. The catalogue validity interval is at most 24 hours. The hard-cap observation must remain at most five minutes old; both catalogue and policy are checked again after reserve and after SENDING.

Each source has separate input, cached input and output prices, expressed as exact rational USD-micros per token, and a positive exact rational source coefficient. Prices, coefficients and evidence are mandatory. A documented zero price is representable; missing prices never become zero. Unknown tier expressions are not evaluated. Provider `price_ratio` and relative source coefficients are not treated as interchangeable, and no USD mapping is inferred from either.

Reservation is the maximum across eligible sources of `ceil((max(input_price, cache_price) * maximum_input_tokens + output_price * maximum_output_tokens) * source_coefficient)`. Actual usage is `ceil(((input_tokens - cached_tokens) * input_price + cached_tokens * cache_price + output_tokens * output_price) * actual_source_coefficient)`. Fractions use BigInt throughout; rounding occurs once after the sum and coefficient. Conversion to a native A2 integer occurs only after a safe-integer bound check. Quotes pin the entire route/source/rate snapshot, all token limits, catalogue provenance, freshness, maximum source coefficient and digests.

An opaque host verifier must validate the token bound for the complete serialized provider request, including the schema and protocol wrapper. A feature flag or worker estimate cannot supply this proof.

The sole accounting sequence is A2 `reserve` -> `markSending` -> one possible wire -> `settle`. The cloud payload carries the snapshot/quote digests, full token bounds, reserve and per-request charge cap. Acknowledgements require an exact model, source, provider request ID, input/cache/output counts, and a provider actual-charge amount/evidence. Charge must equal the exact recomputation for that source and remain within reserve. Missing cached-token counts, unknown billing or a mismatched amount retain UNKNOWN/HOLD; they do not invent a zero cost or release a potentially spent reserve.

Known charged length-limited, malformed or schema-invalid output settles first and returns REPAIR without retry. Lost reserve/SENDING/settlement acknowledgements or a possible wire return HOLD and invoke A2 `unknown`. A proven failure after reserve but before attempting SENDING uses A2 `failBeforeSend` on the same reservation. A failure after SENDING retains reserve even when the adapter itself has not dispatched yet. Durable aggregate budgets, shared provider-key funding, quotas and deduplication remain owned by native A2; no local spending ledger is introduced. An additional module-local logical-request guard prevents simultaneous/repeated dispatch across broker instances in one process, without claiming crash durability.

The adapter makes only one fixed POST capability request with redirects denied and no automatic retry. It bounds response bytes and timeout. Results select only safe usage/charge/identity metrics; provider diagnostics, response headers, raw exceptions and arbitrary billing payloads are not returned or logged. Producer output is an unaccepted schema-validated proposal.

## Current blockers and bounded plan

The host's read-only discovery is not proof of a provider cap on actual charged dollars after source coefficients. There is no exact issued owner spending grant, confirmed input-token bound, complete finite price normalization or confirmed actual-charge receipt contract. Public catalogue/billing observations therefore cannot activate this adapter. This report makes no paid-runtime, native-budget or acceptance claim.

`catalog-status.json` records only the two selected authenticated model IDs and sanitized public-pricing observation from the host's 2026-11-08 discovery. It records required unsupported/unverified features explicitly. It is deliberately not an accepted normalized catalogue. `gpt-6-sol` has an unevaluated `tiered_expr`; the model/source ratios for either model have no established exact USD mapping in this adapter.

The current real WSL host transport implements read-only `preflight()`, keeps credential bytes outside Node, and deliberately disables `send()`. Its input-bound verifier returns false. Host policy issuance throws `CLOUD_PROVIDER_ACTUAL_HARD_CAP_UNVERIFIED`; no valid live policy is minted. These are explicit remaining live implementation/proof gaps, not a claim of completed paid-provider integration.

`canary-plan.json` proposes at most two independent synthetic code-review attempts, one for `gpt-6-sol` and one for `claude-opus-4-8`, with a proposed $0.25 ceiling per attempt and $0.50 in total. These numbers are **NOT AN ISSUED GRANT**. Its prerequisites must all be established before any paid attempt. Unknown outcomes stop the plan with reserve and quota held; the plan never retries automatically.

## Validation

Syntax checks pass for the adapter, pricing, registry and author tests. With the fixed host validator imports present, the guarded author broker suite passes **13/13**, and independent guarded pricing/catalogue/broker QA passes **22/22** (8 pricing/catalogue plus 14 broker cases). Commands:

```text
node --require ./E1/qa3/offline-guard.cjs --test E1/tests/cloud/broker.test.mjs
node --require ./E1/qa3/offline-guard.cjs --test E1/qa3/pricing-adversarial.test.mjs E1/qa3/broker-adversarial.test.mjs
```

An initial pricing-QA invocation omitted its required preload and failed its guard self-test while attempting DNS for `example.invalid`; the corrected guarded invocation passed 8/8. No provider request or generation resulted from that harness mistake. All broker runs used the network/child-process prohibition. Native PostgreSQL/cloud-funding verification is owned by the separate integration stream and is not established by these mock-only tests.
