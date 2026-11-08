# Independent Issue 3 QA

Read `REPORT.md` and `SUMMARY.json` for scope and current evidence. Result: 29 offline checks, the same 29 in a public-only clean export, 7 synthetic host checks and 9 native E1 checks pass. Actual paid generation and the original cloud mission are NOT_RUN. Funding, real charged ACK and provider input/cap contracts remain unverified; paid execution is disabled.

Offline tests require Node 24.21.0 and no host configuration:

```text
node E1/qa3/run-offline.mjs E1/qa3/pricing-adversarial.test.mjs E1/qa3/funding-adversarial.test.mjs E1/qa3/broker-adversarial.test.mjs E1/qa3/host-boundary.test.mjs
node E1/qa3/verify-portability.mjs
```

Use the runner/preload: the guard rejects actual network and subprocess dispatch. `node E1/qa3/run-host-synthetic.mjs` additionally needs Python 3; optional `QA3_PYTHON` chooses its executable. Host custody I/O and discovery are mocked, with an audit hook denying real key reads or network.

`node E1/qa3/run-native.mjs` requires separately authorized access to the existing verified E1 PostgreSQL descriptor. It uses unique `prj_qa3_*` projects and explicitly synthetic funding/charges, performs no DDL or cluster lifecycle changes, and never calls Router.Cheap. UNKNOWN remains unknown: booked confirmed zero is not a claim of zero actual charge. Known held observations, overruns and missing-charge counts are reported separately.

Publish only `PUBLICATION-REVIEW.json`'s exact allowlist. Keep local full command records, `.portable`, private descriptors, key material, PGDATA and raw runtime/provider receipts outside publication.
