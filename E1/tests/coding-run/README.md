# Durable coding-run verification

The store in `E1/coordinator/coding-run.mjs` adds host decision state to the
existing A2 transaction domain. It owns no task queue, model ledger or funding.
Its counters are read from native A2 attempts. A separately scoped repair can
adopt one exact confirmed failed G1 attempt only once: old project quota 1 is
fully consumed, new project quota 3 is immutable, and their aggregate is 4.

`createCodingRunStore({db,project_id})` exposes `open(binding)`, `read(run_id)` and
`advance({run_id,expected_revision,operation_id,transition})`. Binding has 19 exact
fields, including declared Head/code/product task and capability pins, original
brief/oracle/base/source, parent grant digest and explicit prior native tuple.
`read` returns effective HOLD if a native attempt is uncertain or unexpected.
Unknowns never restore an attempt slot. Existing CONFIRMED output is recovered
from frozen artifacts; rerunning the full Coding Executor is not a recovery path.

Migration 0007 adds the state table and existing-event/inbox-based idempotency.
Migration 0008 wraps that transition API with native accepted Head authority and
its exact output/attempt/QA pins. The renamed v7 implementation is not executable
by coordinator, QA, worker or public roles. Do not edit applied migration files.
The empty-only rollback exported by the module is a **v7-only** helper and is
inapplicable once initialized runs or migration 0008 exist; it is not an upgrade
rollback procedure.

The transition gate does not patch the underlying A2 reserve function. Real
model calls must exclusively use the trusted controller/accounting wrapper that
requires the corresponding successful HEAD_PENDING/CODE_PENDING operation, exact
task/fence/attempt and native A2 authority. Native A2 quotas enforce the physical
aggregate ceiling independently. Code QA PASS alone cannot yield RESULT_READY:
an independent accepted script product task must bind code result, final tree,
oracle and adopted prior result.

## Commands

Pure contract/controller checks (no PostgreSQL, model or provider):

```text
node --test E1/tests/coding-run/state.test.mjs
```

Native tests require the already verified isolated E1 descriptor and applied
0007/0008. The integrator runs them explicitly; default execution skips them.

```powershell
$env:AWE_CODING_RUN_NATIVE = '1'
$env:AWE_CODING_RUN_EVIDENCE = 'E1/coding/evidence/NATIVE-CAS.json'
$env:AWE_CODING_RUN_ADOPTION_EVIDENCE = 'E1/coding/evidence/NATIVE-ADOPTION.json'
node --test E1/tests/coding-run/native.test.mjs E1/tests/coding-run/adoption-native.test.mjs
```

Optional `AWE_E1_CODING_RUN_RESOURCE` overrides the host-only descriptor path;
the descriptor is always validated against the existing E1 resource identity.
It is never sent to a model or copied to public evidence.

The first native suite creates a fresh standalone zero-cost scope for an actual
two-session CAS race. It retains a STOPPED controller fixture with effective
native HOLD from an explicitly synthetic uncertain state; no HTTP transport is
invoked. The second suite admits fresh repair fixture scopes before opening its
admin transaction, adopts the actual failed G1 tuple read-only, and seeds only
new fixture rows inside ROLLBACK. It checks old project/mission/task/attempt/QA
hashes before/after and leaves no prior adoption ownership behind. Fresh fixture
missions are cancelled on cleanup; original G1 rows are never updated or deleted.

All seeded Head/code/test/product/QA results are labelled
`EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST`. They prove SQL constraints and permissions,
**not** AWE authorship, real inference, code quality, repair or autonomy. Only a
separately recorded actual AWE run can establish those claims.
