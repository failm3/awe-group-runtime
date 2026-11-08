# AWE_E1 C1 offline infrastructure

This release implements isolation preflight and a local filesystem/process fixture. PostgreSQL creation, start, connection, migration and restore are **BLOCKED**. No real identity, vault, model endpoint, installed service or authority uptime is verified. The fixed child cannot run a mission, complete a task, send an effect or access D03/D09. There is one existing AWE coordinator and one accounting boundary; C1 adds neither.

Run from the verified E1 source worktree using Node `24.21.0`. The expected source evidence commit is `3579aeeda379caf78dafe5351704956f1ecc0ea5`; the historical executed E0 source is `c53d1fb3606218a4f3961f37f57ebc41ac6681ef`. The original `92ef` tree and all E0 storage are excluded. A source pin is provenance, not permission or an authenticity signature.

## Materialize config and inspect preflight

The JSON template contains literal `${E1_ROOT}` placeholders and intentionally fails validation until explicitly bound. This PowerShell command derives storage from the imported module's actual worktree, validates the template and prints a sanitized report. It does not create directories or start services.

```powershell
@'
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {LOCAL_ROOT, withLocalRoot, preflight, migrationPlan} from './E1/infra/index.mjs';
const template = JSON.parse(fs.readFileSync('./E1/infra/templates/awe-e1.offline.json', 'utf8'));
const config = withLocalRoot(template, path.join(LOCAL_ROOT, template.namespace));
console.log(JSON.stringify({preflight: preflight(config), migrations: migrationPlan(config)}, null, 2));
'@ | node --input-type=module
```

Choose a distinct namespace and storage root for another domain project. `project_id` and infrastructure `origin` are separate from A1 artifact provenance. Infrastructure origin is an exact canonical HTTPS origin under `awe-e1.invalid`, used only for offline scope binding. It grants no network access. Database configuration accepts no DSN or password and is always disabled. Paths must stay inside the current worktree's `E1/.local/<namespace>` or an explicitly named `awe-e1-*` OS temporary directory. Windows device/UNC/short-name/stream/trailing-dot/trailing-space paths, traversal and existing links are rejected. Every storage operation rechecks existing path components.

Use `withLocalRoot(template, absoluteRoot)` for a parsed template. `loadInfraConfig(filename)` accepts an already materialized JSON config, rejects links, limits file size and emits only stable error codes. It never reads environment credentials or falls back to E0.

## Offline smoke and recovery

```powershell
node --require ./E1/tests/infra/fixtures/preload.cjs --test --test-isolation=none --test-concurrency=1 E1/tests/infra/*.test.mjs
```

Tests create unique roots under `E1/.local/awe_e1_c1_<random>` and remove only those verified absolute roots. The root test guard denies network and subprocess APIs except the fixed Node fixture child. The child independently preloads `fixture-guard.cjs`, has a fixed entrypoint, receives no task payload or inherited credentials, uses no shell and hides its Windows window. The guard is JavaScript defense in depth, not an OS sandbox.

Observed in the managed default sandbox: atomic rename works in workspace storage; atomic rename in OS temporary storage returned `EPERM`. Use the workspace root for these tests. The checkpoint implementation retains atomic temp-write/fsync/rename; it does not fall back to an in-place overwrite. Directory fsync is not portable on Windows, so a sudden power-loss durability guarantee is **NOT_PROVEN**.

The supervisor API is `createFixtureSupervisor({config, vault, vault_access?, manifest?})` with `start({workload_id, initial_cursor})`, `checkpoint(cursor)`, `status()`, `stop()` and the explicitly synthetic `crashFixture()`. `start()` is idempotent while its one owned child runs. A local exclusive lock denies another supervisor. Graceful stop preserves the same workload/cursor; an unexpected child exit is persisted and a later `start()` performs bounded recovery. The restart budget persists across vault WAIT and cannot be reset by availability toggling. No automatic second authority or stale-lock takeover exists. After loss of the supervisor itself, a remaining lock requires independent review; do not delete a lock while an owner might still run.

Use `try/finally { await supervisor.stop(); }` around a smoke. Corrupt checkpoint, full/unavailable storage or uncertain ownership produces HOLD and does not reset the cursor. A checkpoint is a checksummed local fixture record, not an authenticated mission ledger or an anti-tamper storage boundary against another OS writer.

## Scoped identity and vault handles

`createScopedVault({config, grants, now, available})` accepts declarations and scoped handles only; it accepts and returns no credential bytes. Grant fields are `{grant_id, principal_id, project_id, origin, purpose, expires_at}`; `expires_at` is epoch milliseconds. Supported purposes map to exactly one role: `worker-data`, `qa-signing`, `issuer-signing`, `coordinator-storage`, `security-audit`.

The fixture issuer calls `issueHandle(grantId, issuerContext)`. Every `resolveHandle(handle, actorContext)` checks the current principal/project/origin, enrolled role, immutable grant copy, expiry, monotonic observed clock and both grant/handle revocation. A worker cannot resolve a QA signing handle. `revoke(id, ownerContext)` denies other principals. `setAvailable(false)` causes WAIT; `setAvailable(true)` does not undo revocation/expiry. Clock rollback is rejected. Context contains only `{principal_id, project_id, origin}`.

To bind recovery to the current worker handle, pass `vault_access: {handle, context: workerContext}` to the supervisor. Vault unavailability, revocation or expiry causes WAIT without advancing or erasing the saved cursor. `status()` exposes only state, static version, counters and digests; raw cursor, credentials, CV, email bodies, private receipts and arbitrary IDs never enter health output.

These calls do **not** authenticate an OS principal. The process is a trusted local fixture, and its caller could claim a declared actor ID. Real OS accounts, ACL enforcement, credential adapter and separately held QA key remain required and BLOCKED. `service-profile.json` and `local-model-profile.json` are uninstalled declarations. Neither Qwen candidate has been called, measured or shown equivalent.

## Objects, manifests and migration handoff

`createFixtureObjectStore(config)` provides `put(bytes)`, verified `read(ref)`, `backup(ref)` and `restore(ref)` for synthetic local objects up to 1 MiB. Refs contain scope and SHA-256 only. A missing object can be restored from a verified local copy. A corrupt object or foreign ref causes HOLD; corrupt originals are not silently overwritten. This tests a filesystem object copy only, not encrypted independent-node backup, PostgreSQL restore, RTO or RPO.

`createReleaseManifest({config, build_digest?, registry_version?, policy_version?})` records fixed source/release, migration/model state, worker IDs and live blockers. Unmeasured versions/digests stay null/UNKNOWN/BLOCKED. `validateReleaseManifest(config, manifest)` checks the full canonical body, fixed pins and recomputed digest; supervisor snapshots the validated result. A declared build digest does not prove an independently verified build or a signed release.

`migrationPlan(config)` hashes the two SQL templates and returns a **BLOCKED** text plan with `migration_test=NOT_RUN`, `postgres_restore_test=NOT_RUN`, zero database connections and required owner scope. There is deliberately no SQL execution adapter or PostgreSQL dependency. The additive schema contains installation/version metadata only. Public grants are revoked; the templates create no credentials, roles, queue, coordinator or financial ledger.

Before a future separately authorized E1 database run: independently bind the new database/project/PGDATA, provision distinct OS and database roles, verify ACLs and QA-key separation, pin migration bytes, take a verified backup, then run expand/migrate/readback. For binary rollback drain first, retain schema/history/D03/D09/outbox and switch to a compatible previously verified binary. Do not downgrade data or restore an older outbox to roll back code. Restore must target a fresh fenced namespace, disable the prior writer/sender, increase the authority epoch and reconcile external effects before dispatch. Those operations and their acceptance tests are not performed by this release.
