# E1 tooling bridge: bounded subset, not catalog-wide activation

`awe/tool_registry` remains unchanged. Its `normalizeRequest`, metadata ranking
and discovery are reused. Its E0-only binding is not a runtime permit. The
existing 4,504-record snapshot is loaded once through a host-only path, checked
against the known SHA/size/count and searched with a narrowing term. At most 64
matching rows are lazily classified; at most 20 results leave a query. No
refresh, mass install, raw catalog export, or E0 DB operation occurs.

Catalog results remain `CANDIDATE`, `permitted:false`, physical `DENY`. A URL,
inferred taxonomy tag or `manual_topic_review` flag never proves installation.
The selected subset is ripgrep (`Радар-0673`) and ripgrep-all (`Радар-0046`). The
only enabled adapter operation is literal search over a bounded stdin string.
Archive/document adapters, arbitrary paths, command lines, installs, configs,
caches, shell interpolation and network workflows are outside this profile.
`Радар-2476` MCP servers remains an unactivated candidate.

## Host review and activation

`probeInstalledTool` checks the exact installed version, actual binary SHA/size,
distribution release/source metadata, upstream-pinned license evidence, schemas and four
actual synthetic tool invocations. `signToolReview` accepts only the in-process
result of that probe. Its Ed25519 signature is a local host review, not owner
authentication, a native A2 claim or a spending grant. Private review keys stay
in host memory; only a public verification key and signed review may leave.

`activateToolReview` requires the trusted host key fingerprint, unexpired
signature, original catalog/raw digests and current binary pins. Activation
returns an A1 descriptor. A changed binary, schema, source pin, key or revoked
review fails closed. Distribution metadata identifies a release but does not
prove a reproducible upstream build; that limitation is recorded explicitly.

## Head selection and native dispatch

1. Search with `loadPinnedCatalogRepository(...).search({project_id, need,
   capabilities, text_filter, mode:'CANDIDATES', limit})`.
2. Host activation puts the reviewed A1 refs in the ordinary E1 registry/domain
   and approved mission grant. Model drafts may reference only those refs.
3. `chooseExecutor` considers `script`, `program`, `local_llm`, `cloud_llm` for a
   semantic need (for these tools, `text.literal-search`). It filters by exact
   granted refs, permissions/data/origin, measured quality suite, health and
   verified effective API debit. It then sorts cost, quality and deterministic
   type/ref ties. Local infrastructure cost is explicitly unmeasured. Cloud is
   blocked by the existing unsatisfied actual-charge contract; no candidate
   flag enables payment. Selector output is never dispatch authority.
4. A1 publishes the selected exact capability in the plan. A2 issues the normal
   claim. `createToolDispatcher` receives host `authenticate`, `resolveGrant`,
   project coordinator, activated-entry lookup and private binary resolver.
   Dispatch checks current RUNNING task/input/ref, worker, plan/fence, active
   mission/grant/lease, then native heartbeat immediately before and after the
   fixed invocation. Result still needs ordinary native complete and QA. The
   context/grant/activation lookup ports are synchronous host reads; async
   binary resolution finishes before the final native heartbeat and guard.
   Caller input/scope/choice are frozen at entry. The last synchronous check
   runs immediately before spawn, with at least four seconds left for a fixed
   three-second execution plus margin; heartbeat requests six seconds.
5. Model choices use existing A3/D09 ports, not these executable adapters. This
   module does not claim a live model dispatch or invent a parallel ledger.

The local native smoke proves two real installed utilities and signed host
review. Policy grant/snapshot doubles are labelled explicitly. No A2 tool task,
dynamic agent or G2 success is claimed before an actual native integration run.

The literal operation explicitly forces case-sensitive matching: upstream RGA
otherwise selects smart-case. Its binary directory and `lib` subdirectory may
not contain an overriding `rg.exe`, because upstream prepends both to PATH.
These behaviors were checked in the [tagged source](https://github.com/phiresky/ripgrep-all/blob/v0.10.9/src/bin/rga.rs#L110).
Installed license bytes match the tagged [RGA license](https://github.com/phiresky/ripgrep-all/blob/v0.10.9/LICENSE.md)
and [ripgrep MIT license](https://github.com/BurntSushi/ripgrep/blob/15.2.0/LICENSE-MIT)
after CRLF-to-LF normalization. Installed Scoop directories remain a trusted
host boundary: before/after hashes do not prove resistance to a hostile host
replacing and restoring binaries between checks. No hostile OS sandbox is
claimed for these installed-utility adapters.

## Reproduction

Offline: `node --test E1/tests/tooling/policy.test.mjs`.

Installed-tool smoke: host sets `AWE_TOOLING_NATIVE=1` and
`AWE_TOOLING_CATALOG` to the original local snapshot, then runs
`node --test E1/tests/tooling/native.test.mjs`. This performs no install, model
call, paid API request, PostgreSQL connection or E0 operation. It emits only
safe selected metadata and execution digests to `evidence/INSTALLED-TOOLS.json`.
