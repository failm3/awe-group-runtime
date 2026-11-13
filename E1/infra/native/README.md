# Authorized local E1 resource

This runbook concerns the bounded Windows/WSL Ubuntu test resource `awe_e1_a2a3_20261108`. It is not production bootstrap or permission to create other resources. The owner authorized this resource on 2026-11-08. Never reuse the E0 cluster, its socket, port, roles, data or configuration.

The test cluster uses PostgreSQL 18 on port **5433**, database `awe_e1_test`, separate Unix/DB principals and PGDATA under `/var/lib/awe-e1-test/awe_e1_a2a3_20261108`. Unix peer authentication binds each connection to its OS principal. TCP listens only on loopback and is rejected by HBA. Non-admin roles cannot create databases or roles; worker has no runtime schema access. The coordinator and independent QA receive different restricted functions. Windows workers receive scoped loopback credentials, never the resource descriptor.

`preflight-wsl.sh` checks available port, memory, disk, binaries and preexisting PostgreSQL process fingerprints. `provision-e1.sh` refuses an existing base or account/group, verifies port 5433 again, creates only the pinned E1 cluster, then compares preexisting process fingerprints. Its `E0_PRIVATE_METADATA` input points to an operator-owned, unpublished identity file solely for checking that the new E1 Unix owner cannot read E0's `PG_VERSION`. Do not place that input, process snapshots, logs, dumps, descriptors or PGDATA in Git. The delivered provisioning copy uses an environment reference instead of the original private host path; it was syntax checked, not executed a second time.

An already created resource must not be provisioned again. Place the host-owned descriptor outside version control at `.private/e1-resource.json`. Its fields and every path/role/port are checked by `E1/coordinator/resource.mjs`. Apply runtime migrations only with:

```powershell
node E1/host/migrate.mjs --authorized-e1-only .private/e1-resource.json
```

The adapter verifies actual database, mapped role, PGDATA, socket and preexisting resource identity before any DDL. Migration `0001` creates the one durable coordinator/ledger domain. `0002` adds an operator-only execution-quiescence proof without refunding UNKNOWN usage/quota. Both are additive; runtime evidence/outbox tables have no destructive down migration. A rollback drains dispatch and restores the previous code binding while preserving persisted evidence.

Actual checks are recorded in `E1/evidence2/RESOURCE.json`, `C1-NATIVE.json` and `C1-PINNED-RESTORE.json`: clean/repeated C1 migration, additive rollback without data drop, restart only E1, two synthetic rows restored with equal digest, and nine preexisting PostgreSQL processes unchanged. An initial placeholder migration digest in the test metadata was corrected to the SQL's real SHA-256; a fresh dump/restore then verified both metadata and rows. `pin-c1-validation.sh` is the exact correction/check command; its fixed restore database must not already exist. The earlier restart proof is separate and was not repeated during model work.

No E0 connection was opened. A read-only file-access denial was tested from E1's Unix identity. This is separation for trusted local staging processes, not an OS sandbox against a hostile administrator. The WSL adapter uses the existing host's root-to-`runuser` bridge; untrusted task text cannot supply its command or resource path. Hostile same-host isolation, production AuthN/vault, 24-hour soak and disaster recovery are not proven by these tests.
