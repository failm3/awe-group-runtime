# AWE E1 contracts · AWE_E1/1

Status: `TESTED_OFFLINE`. This package validates mission and plan proposals. It does not execute tasks, reserve money, authenticate production users, or accept results.

`CONTRACT_VERSION = awe.e1.contracts/1`; `RELEASE = AWE_E1/1`.

## Machine-readable schemas

`v1/awe-e1.schema.json` is a **definition bundle**. Its root is a library container, not a validator for an individual entity. Select the exact `$defs` entry through `v1/catalog.json` (`local_ref`), or use `contractSchema('MissionSpec')` / the composition CLI schema command. Never validate a MissionSpec against the unselected bundle root.

The nine named definitions are MissionSpec, MissionGrant, PlanRevision, TaskSpec, CapabilityRef, ArtifactRef, EffectIntent, QAResult and DomainManifest. Every named contract requires the common version/release and rejects extra properties. Nested capability, effect, artifact and dependency bindings are validated recursively. Domain-specific inputs use a bootstrap-pinned, bounded JSON Schema subset; unknown keywords, remote refs, incompatible keywords and incorrectly typed constraints fail closed.

The schemas express structural requirements. `validateContract` adds local semantic constraints; `validateMissionBinding`, `validateDomainBinding` and `validatePlanRevision` add cross-document scope and policy checks. A generic JSON Schema validator alone does not establish grant authority or plan admission.

Regenerate checked-in portable schema, catalog and fixture manifests with:

```powershell
node E1/examples/write-manifests.mjs
```

`E1/examples/MANIFEST.sha256` binds exact artifact bytes. `contract-manifest.json` also records canonical contract/domain/registry digests. Artifact-byte SHA-256 and canonical JSON digests are deliberately distinct.

## Public exports

From `E1/contracts/index.mjs`:

- `RELEASE`, `CONTRACT_VERSION`, `CONTRACT_TYPES`, `SCHEMA_DOCUMENT`, `contractSchema(type)`, `schemaDigest(type)`.
- `validateContract(type, value)` returns a deeply frozen copy, or throws `ContractError` with `code`, `disposition` (`REJECT` / `WAIT`) and `path`.
- `sealContract(type, value)` returns `{type,release,contract_version,schema_digest,digest,value}`. A digest is integrity metadata, not a signature or permission.
- `validateMissionBinding(spec, grant, now)`, `validateDomainBinding(spec, domainManifest)`, `validatePlanRevision(plan, {spec,grant,capabilities,domainManifest,now})`.
- `validateCapabilityDescriptor`, `capabilityManifestDigest`, `capabilityKey`, `capabilityRegistryDigest`.
- `inspectBoundSchema`, `validateBoundValue`, `canonicalize`, `digest`.

E1 reuses `contracts/canonical.mjs` unchanged: safe integer JSON, well-formed Unicode, sorted object keys, maximum canonical entity size 64 KiB and maximum depth 32. The E1 wrapper additionally rejects array accessors, symbols, hidden properties, holes and custom prototypes before reading values. Immutable snapshot/history collections contain independently bounded records and may exceed 64 KiB; they are not one canonical contract payload.

Capability descriptors are strict bootstrap data, with a versioned CapabilityRef, pinned input/output schemas, manifest digest, executor kind, required permissions, data/origin/effect classes, health deadline, retry/timeout and minimum-cost bounds. The manifest digest is `capabilityManifestDigest(descriptor)`; it excludes only `ref.manifest_digest` to avoid a self-reference. The descriptor contains no executable dispatch handle or secret. A3 must bind reviewed implementations and real health/evidence.

## Policy boundaries

MissionGrant is bound to the exact MissionSpec digest. Actor, project, owner, mission, grant version, allowed principals, permissions, capability/schema pins, data classes, origins, destinations, expiry, action/replan/task counts and budget cap are checked before publication. Revisions require new spec/grant versions and expected current digests. A revision can narrow existing bounds. A broader mandate needs a distinct owner-authorized mission/bootstrap integration.

PlanRevision contains a typed DAG. A task binds capability version, implementation and schema digests, static input, dependency output schemas, criteria, worst-case attempt budget, deadline/timeout, provenance, effect, retry and QA rubric. Code checks capability presence/health/scope, strict input values, dependency edges/cycles, full criteria coverage, rubric digest/checks, aggregate budget including retries, action bounds and critical-path deadlines. Task outputs and blob contents do not exist at this stage; A2/A3 must verify produced bytes against these pins.

`OUTCOME_UNKNOWN` yields `WAIT / E1_RECONCILIATION_REQUIRED`. Retry policies require `on_unknown=HOLD`; only proven transient no-effect failures are expressible as retry candidates. External effects yield `WAIT / E1_EXTERNAL_EFFECT_NOT_BOUND`, including when an otherwise matching grant describes an external destination. There is no sender, worker, network call or charge path in this package.

QAResult requires different evaluator/producer IDs, scoped evidence, passing checks for PASS, and `accepted=false`. This contract does not prove real reviewer identity, independent execution, artifact correctness, or owner acceptance. Offline bootstrap also prevents one subject being both QA and a producer. Live QA remains A2/A3/A4 work.

## A/B and E0 compatibility

`E1/examples/fixtures.mjs` exports `createMissionFixture('A'|'B')`, `runFixture`, `fixtureSummary`, `fixtureCapabilities` and `createDomainManifest`. A and B use one release, registry, contract set and normal ingress. Only data-only domain/project manifests and tasks differ. Career A is fictional; product B is an independent fictional shift-handoff brief. Neither contains PII or produces an external effect. They prove contract portability for these inputs, not completed career/product missions or general autonomy.

No historical E0 source/schema/profile is modified. Compatibility tests validate all three existing AUTO-01 scenario fixtures with unchanged serializers and run the historical synthetic AUTO01 host through `MOCK_WORK_COMPLETED`, with `realAutonomyVerified=false` and `accepted=false`. This does not re-run or re-accept the historical E0 PostgreSQL runtime.
