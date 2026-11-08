# Independent QA4

Read `REPORT.md`, `SUMMARY.json` and `CHECKPOINT.json`. The original frozen data remains unchanged. Coded cycle 04 passes the bounded synthetic mission; earlier cycles preserve their coding BLOCKED/PARTIAL results. Real Career/production acceptance and generic coding are not claimed. Owner financial authorization is present; actual paid Router execution is technically blocked.

Targeted offline commands, with no host credentials or provider calls:

```text
node E1/qa4/run-targeted.mjs
node E1/qa4/run-sut-targeted.mjs
node --require ./E1/qa3/offline-guard.cjs --test E1/qa4/cloud4-authority.test.mjs
```

Actual native/sandbox inspectors require separately authorized existing E1/WSL access. They do not migrate or start/stop resources and never call paid providers. Do not run them as a substitute for a host authorization. QA-role credentials for per-task leaves arrive only over IPC.

`fixtures.mjs` supplies public source data; `createFrozenOracle` owns expected answers. Hidden expected values and score holdouts must not enter producer/model prompts. Native/code receipts demonstrate observed bounded execution, whereas offline test doubles only exercise checker logic. Publish only the reviewed allowlist; retain private configuration and full raw receipts locally.
