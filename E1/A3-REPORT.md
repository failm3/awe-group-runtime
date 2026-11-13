# A3 — model and capability broker

Status at 2026-11-08: **IMPLEMENTED / TESTED_OFFLINE / VERIFIED_LIVE for one bounded local canary**. A real Head response created revision 2, its script/review tasks reached technical ACCEPTED, and a fresh OS process read back COMPLETE and persisted usage. The earlier timed-out attempt remains HOLD/UNKNOWN with its quota charged. Overall `accepted=false`; owner acceptance was not requested. E1 Pilot A/B, G4–G6, production capability and model superiority are not established.

## Scope and source

New clean allowlist export only. Original 51d0 checkout, E0, historical schemas, migrations, Git/index/branch/remotes and external providers were not modified by A3. Ownership is limited to `E1/broker/**`, `E1/tests/broker/**` and this report. Runtime Node `v24.21.0`; dependency-free ESM. Source lineage is recorded by integrator in `E1/TEAM-A2A3.md`.

Observed runtime/version pins: A1 release `AWE_E1/1`, contracts `awe.e1.contracts/1`, registry `awe.e1.capabilities/1`, local model policy `awe.e1.local-model-policy/1`, capability versions `1.0.0`, Node `24.21.0`, native PostgreSQL `18.6`, Ollama `0.40.12`. Broker source/build pin is `sha256:9e34868ec2bcdbbb7ec3627d5518942a2ec544b78e84fb2561741eee66082b9e`; model is `qwen3:4b-instruct`, GGUF 4.0B Q4_K_M, digest `0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0`. Registry digest for the measured run is `sha256:69b58e8a1991d6986c42aff02a0bdf3f4fbb7efe719e3c7cd953594f6af0cfa2`. The original health interval, 00:48:01.074Z–01:48:01.074Z, was retained without a TTL extension. These are broker/runtime pins; final repository commit/release provenance is owned by the integrator.

## Implemented

- Registry `awe.e1.capabilities/1` wraps the frozen A1 CapabilityDescriptor. Three installed operations: `e1.code.parse` (script), `e1.code.review` (llm), `e1.head.plan` (llm). Entries bind schemas, actual source-byte/build digest, platform, placement, permissions, data labels, resource/time limits, health TTL, canary status, QA suite, no-retry/UNKNOWN policy and API-cost basis. Discovery does not imply installation. Approval is explicitly `BOUNDED_CANARY`; unknown sample quality cannot authorize ordinary production use.
- Selector filters availability, source pins, platform, grant/capability/permission, data, origins/effects, deadline and budget before choosing. Deterministic parsing chooses the fixed script; semantic work chooses one local LLM. Rejected alternatives have reason codes. No automatic fallback or retry.
- Live factory `createLocalModelBroker` has fixed loopback endpoint/model/digest, no injected transport or alternate cloud route, one in-process concurrent inference, one generation POST per attempt, JSON Schema `format`, `stream:false`, `think:false`, context 4096/8192, output 512–2048 and timeout at most 120 seconds. Redirects and oversized responses fail closed. The existing Ollama daemon is not started/stopped or replaced.
- Mandatory injected A2 port: `reserve → markSending → one model POST → settle`, `failBeforeSend` for a proven no-wire failure after confirmed reservation, or `unknown` on an ambiguous reservation/marker or possible send. Native settlement must return `CONFIRMED`, matching A2's PostgreSQL state. A completed `done_reason:length` acknowledgement with all required identity/metrics/time fields settles genuine usage, then returns `REPAIR / A3_OUTPUT_TRUNCATED` before parsing or proposing any plan, even when its text is valid JSON; it does not release quota or retry. Unknown completion reasons or missing metrics remain UNKNOWN. Zero API cost still reserves one durable quota unit. Capability ID/version and route are sent to A2 for comparison with its admitted/claimed task. Backend usage is never estimated from text. Marker response loss also requests UNKNOWN/HOLD, with zero generation attempts. No side ledger exists in broker code.
- Compact Head output owns only task IDs/titles/instructions, DAG edges, criterion IDs and reason. Code materializes owner/grant/capability/schema/effect/budget/QA metadata from validated inputs, requires the supplied clean source digest and authentic Head context, and invokes unchanged A1 plan validation. Model output has no shell, process, DB, network, tool or acceptance authority.
- `createMaintenanceMission` supplies an explicit synthetic numeric-sort maintenance mission. Its ordinary A1-validated bootstrap plan has `parse_source` and bounded `head_control`. A real Head response creates revision 2 with its own task content/dependencies. It cannot self-publish or set accepted=true. The explicit `concise:true` option narrows a new owner's goal/criteria to exactly two short tasks and <=250 output tokens; it rebinds spec/grant/bootstrap digests and does not change rights, capabilities, policy or TTL. Compliance was observed once in the measured canary; it is not guaranteed for other inputs.
- `freezeBrokerArtifact` pins producer output and rubric for independent QA. No producer approval implementation is supplied. `runMinimalBenchmark` measures the deterministic script and one bounded Head request through the caller's native A2 port; emits actual usage, latency/model/digest and explicit NOT_RUN rows for unavailable routes. Full 5×3 benchmark remains NOT_RUN.

## Shared API

Public exports are in `E1/broker/index.mjs`:

```js
const f = createMaintenanceMission({suffix: 'canary'});
// Integrator creates/proposes/validates/publishes f.bootstrapPlan through A1,
// admits it to A2 and claims head_control with the current worker/fence.
const broker = createLocalModelBroker({accounting: coordinator, registry: f.registry});
const result = await broker.generateHeadProposal({
  scope: {mission_id: f.spec.mission_id, task_id: 'head_control',
    logical_request_id, attempt_id, worker_id: 'e1_worker', fence},
  spec: f.spec, grant: f.grant, source: f.source,
  domainManifest: f.domainManifest, authority: f.authority,
  headContext: f.contexts.head, plan_id: f.bootstrapPlan.plan_id,
  revision: 2, previous_digest: digest(f.bootstrapPlan)
});
// PROPOSED returns draft/plan/validation/usage/model; ordinary A1 publication
// and independent QA remain separate. BLOCK/WAIT/REPAIR never grants effects.
```

Claim `head_control` with `lease_ms:150000` before the at-most-120000 ms model request. A2's owning SQL allows leases from 100 through 600000 ms. Complete the claimed control task using `{output_schema_digest: claim.task.capability.output_schema.digest, output: result.output}` and its canonical digest; `result.output` is the compact draft, while `result.plan` is separately proposed/published as revision 2. Workers are never handed the database session or credentials.

`createOfflineModelBrokerForTests` exists only as an explicitly named test boundary in `model.mjs` and requires `OFFLINE_TEST_DOUBLE`; it is not exported by the public entrypoint and can never label evidence live or accepted. Offline accounting in unit tests is a call recorder only, not native durability evidence.

## Verification

- `node --test E1/tests/broker/broker.test.mjs`: **21/21 PASS**. Includes actual fixed-parser execution; two selector kinds/rejections; protected metadata; absent tool/cycle/criteria; forged identity; grant expiry; privacy/endpoint/permission; reservation/marker failures; proven pre-send release after clock advance; ambiguous reserve commit; backend pin mismatch; malformed JSON/tool misuse/budget escalation; no-usage; settle failure; timeout UNKNOWN; one inference semaphore; explicit concise mission bindings/unchanged grants and capabilities; valid/truncated JSON length acknowledgements settling once without proposal, and unsupported completion reasons remaining UNKNOWN. Model responses and accounting in this command are explicitly offline doubles.
- `node --test E1/tests/contracts/*.test.mjs E1/tests/integration/*.test.mjs`: **63/63 PASS**, including existing A/B compatibility. These fixtures are compatibility checks only.
- Read-only local metadata, after sandbox escalation, confirmed Ollama **0.40.12**, `qwen3:4b-instruct`, digest `0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0`, size 2497293803 bytes, GGUF 4.0B Q4_K_M. `/api/show` advertises completion/thinking/tools and context 262144; broker limits remain 4096/8192 and tool execution remains unavailable. These reads did not perform inference.
- The first native A2 PostgreSQL + actual local model request reached the 120-second timeout. Independent QA readback (00:57:40Z; retained evidence SHA-256 `4be16b01bdbc4288a16884e7c0e2d0eb2f3c6152fb0e593cd4aa382f8709be26`) observed one reservation, one SENDING and one OUTCOME_UNKNOWN event, no settlement or second send. That mission/task remain HOLD, one quota unit remains charged, usage/provider acknowledgement remain UNKNOWN/ABSENT and its only plan is bootstrap revision 1. Its deterministic parse worker and separate parse QA passed; typed Head output was not received in that attempt. [First-canary failure record](evidence2/FIRST-CANARY-HOLD.json).
- A separately granted compact mission ran from **01:14:58.041Z to 01:15:31.854Z** with context 4096, output cap 512 and timeout 120000 ms. It used the same model pin and original registry health interval. The actual Head response supplied task IDs/content and the dependency, code filled the protected fields, A1 validated/published revision 2, and native A2 ran its deterministic parser plus one semantic review. Independent QA passed each frozen result; current tasks `parse-order` and `review-logic` reached technical ACCEPTED. Plan digest: `sha256:32f1f440dfd66eebaf3ae7965f21e3ce98092caf858f56d5626362184392f2b9`. [Primary native contour](evidence2/LOCAL-CONTOUR.json).
- The authority ran in OS process 41440. Fresh process 6924 read native PostgreSQL mission COMPLETE, both current accepted task/result/plan digests, both model attempts CONFIRMED with their exact persisted usage and cursor sequence 624. That readback made zero model calls. Project quota was 3: the original UNKNOWN unit plus two confirmed calls in the compact mission; API reserve/spend remained zero. [Fresh-process readback](evidence2/COLD-READBACK.json). These are technical results for synthetic planning/analysis; source code changes, GitHub tasks and external effects were zero, and `accepted=false`/owner acceptance NOT_REQUESTED remain explicit.

## Minimal measured benchmark — one compact canary

The table covers one synthetic maintenance mission and its two plan revisions. It is a single canary, with no repeated task set, competitor routes or controlled comparison. Input/policy/schema/rubric/source/response commitments and actual nanosecond backend metrics are retained in the primary contour. Latency below is broker-observed wall time; token counts are received backend usage and are also persisted by A2.

| Operation / route | Observations in this canary | Input / output tokens | Wall latency | Accounting / independent QA |
| --- | ---: | ---: | ---: | --- |
| Deterministic parser, `e1.code.parse` / script | 2 executions: bootstrap and revision 2 | N/A | NOT_RECORDED | Native task completion; QA PASS |
| Head planning, local Qwen / `e1.head.plan` | 1 model call | 623 / 162 | 18,240 ms | CONFIRMED; typed revision 2; QA PASS |
| Semantic review, local Qwen / `e1.code.review` | 1 model call | 144 / 235 | 13,800 ms | CONFIRMED; QA PASS |
| Mac 8B, cloud routes, real browser benchmark | NOT_RUN | NOT_RUN | NOT_RUN | Outside the bound capability/authorization |
| Full 5×3 benchmark / model ranking | NOT_RUN | NOT_RUN | NOT_RUN | No quality winner established |

Both model calls used one generation wire attempt per durable reservation, and actual API cost was zero. Infrastructure/energy cost was NOT_MEASURED. The first timeout has unknown usage and is preserved separately; it is not omitted from accounting. Runtime/cache/load conditions differ across observations, so the records do not establish a causal effect of prompt shortening, p50/p95, repeatability or superiority over another model. Registry entries remain `BOUNDED_CANARY` with their initial immutable canary metadata; the measured evidence is attached externally and does not auto-promote them.

Checked primary-file SHA-256: `LOCAL-CONTOUR.json` = `644635114f8cb1e7e7e9c913e21ef3cee345faefbf20091a862df68fecf8b5e2`; `COLD-READBACK.json` = `b8be07ff76a8f6e5609bb1e41dc1078e9842cd7be73b85647d413bd45cc0582f`.

## Actual timeout diagnosis and reconciliation boundary

Read-only Windows Ollama logs show GPU discovery timeout warnings, a 42.24-second cold runner startup, 4096-token context, one slot and partial GPU placement (26/37 layers on GTX 1650 4 GiB). Prompt evaluation was slow and generation was still progressing when the HTTP request ended at exactly two minutes. This supports a cold-load/hybrid-inference latency explanation; it does not establish model quality or provide final usage. Log progress counters are diagnostic only and were not copied into a settlement.

The backend then logged cancellation/released slot/all slots idle. At 00:56:31Z `/api/ps` was empty; at 00:59:03Z an explicit `llama-server` process query returned zero. Model tag/digest remained pinned. A3 performed only metadata/log/process reads after the timeout, with no inference, model download, setting change, restart or process termination.

The broker starts one HTTP abort timer before metadata discovery; its accounting calls retain A2's separate durable semantics. After a possible send without a complete validated acknowledgement it requests A2 UNKNOWN and never retries or releases as a pre-send failure. Physical quiescence alone cannot manufacture a model response, final usage or provider acknowledgement.

Before the compact experiment, an audited A2 quiescence operation used completed cancellation, two independent idle observations and runner absence to release only the old execution lease and fence its worker. It retained the original HOLD/OUTCOME_UNKNOWN, request identity/history, unknown usage and charged quota; refund was zero, and it did not authorize resuming that logical request. [Quiescence proof and unchanged accounting](evidence2/ACTUAL-LOCAL-QUIESCENCE.json), SHA-256 `8619e92d4c2606148c462d27c8b87b970905173e706139b04c246440ea674396`. A separate QA-role cold read confirmed this lease-only release and the preserved unknown/quota. The later compact mission had its own grant and attempts; the old request was not retried and health was not extended.

## Primary API sources

Implementation checked current official Ollama documentation: [generate request/usage fields](https://docs.ollama.com/api/generate), [JSON Schema structured output](https://docs.ollama.com/capabilities/structured-outputs), [model tags/digest](https://docs.ollama.com/api/tags), [local base URL/authentication](https://docs.ollama.com/api/introduction), [errors](https://docs.ollama.com/api/errors). Timeout review additionally used [Windows log locations](https://docs.ollama.com/troubleshooting), [final-response usage](https://docs.ollama.com/api/usage), [running-model metadata](https://docs.ollama.com/api/ps), and [GPU placement/context](https://docs.ollama.com/context-length). Local primary API responses/logs additionally confirmed the installed build/model. No provider comparison or quality ranking is inferred from these documents.

## Remaining limitations

- API cost is zero; infrastructure/energy cost is NOT_MEASURED. Two current tasks have technical QA acceptance in one canary. Owner accepted-result count is zero and cost per owner-accepted result remains NO_OWNER_ACCEPTED_RESULT.
- Model unavailable/timeout or missing accounting evidence results in WAIT/HOLD. UNKNOWN is not released or retried automatically. A proven pre-send release uses only the same mandatory A2 `failBeforeSend` port and requires native FAILED acknowledgement.
- The semaphore coordinates broker instances in one process; a host service/single admitted model worker must enforce the same limit across processes. It does not control unrelated applications using Ollama.
- G4–G6 remain NOT_RUN. No cloud route, Mac 8B, model download, designer project, real CodingExecutor/GitHub task, GitHub mutation, live browser or external application was executed. The separate CodingExecutor preparation and disposable Git unit fixtures do not establish live self-development. The seeded helper was intentionally not modified by this canary.
