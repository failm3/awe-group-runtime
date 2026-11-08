# Resumable checkpoint · SANDBOX-RECRUIT-01

Current result: bounded synthetic mission PASS on cycle04, independent native/cold QA verified. Cloud authorization ISSUED and native PREPARED_PROVIDER_BLOCKED; paid generations zero. All earlier PARTIAL runs and their evidence remain intact.

Development branch `codex/e1-sandbox-recruit-01-20261108`, source base `3c22522c52cb6428757fd391e8630c912016b61b`. Read this file, [Astra checkpoint](astra4/CHECKPOINT.md), [QA checkpoint](qa4/CHECKPOINT.json), [outcome](SANDBOX-RECRUIT-REPORT.md) and the enclosing release manifest before resuming. Verify actual HEAD/worktree/resource and owner directive updates; do not infer fresh runtime evidence from this record.

Private, host-local files are deliberately not exported:

- `.private/RUN-CONTROL.json`: stop at 2026-11-08T05:33:52.393Z, at most 12 cycles / 6 local model wires; 5 wires used, one unspent. Never reset counters to obtain new authority.
- `.private/e1-resource.json`: existing guarded E1 resource on 5433. No worker receives it; no automatic E0 fallback.
- `.private/recruit-cycle01.json`, `recruit-cycle02_4101.json`, `recruit-cycle03_4101.json`, `recruit-cycle04_4101.json`: real mission IDs, checkpoints and exact adopted-code pins. The four missions completed; do not invoke start/resume again as a retry.
- `.private/score-author-score01_4101.json` and its response/synthetic Git worktree: original model candidate and native binding; do not regenerate the accepted source.
- Verified owner Issue snapshots, host public signing pin and resource/test logs. Signing/provider private keys remain in their original protected WSL host stores, never in Git, model input, argv or environment.

Read-only reproduction on this verified host, with the existing private descriptor:

```text
node E1/recruit/cli.mjs cold .private/recruit-cycle04_4101.json
node E1/qa4/verify-cold.mjs .private/recruit-cycle04_4101.json E1/recruit/evidence/cycle04_4101.json
node E1/qa4/verify-score-cold.mjs E1/recruit/coding/evidence/score01_4101.json
```

These commands do not generate model responses. Confirm their explicit command interfaces before reuse if sources have changed. A public export omits private configuration and must fail closed instead of selecting a database or inventing owner credentials.

Real host-attested authorization binding `router_cheap_staging` is on the same cumulative key: original receipt digest `sha256:ab0759a45e953ad01eafecf14ad455d7d9133b696979a80781c3e635c9060851`, current prepared amendment `sha256:e88054feccd4ed7a4a7af9ff61b57e5f2f8d50773a82c4142ee5fcfa033b0372`. Scope covers the six projects in the public signed amendment. No enabled funding row exists. Original receipt history, attempt counts and unknown liabilities must never be deleted or reset. The grant expiry is the bounded run stop time; no silent expiry extension or re-funding is allowed.

Before any paid operation, establish guaranteed actual account-debit bounds after all coefficients, exact source prices/usage/charged ACK and full input bounds, then bind live transport to actual native authority. Existing owner financial approval remains valid within its issued scope; do not ask for the same consent again. Missing provider proof is a technical stop. No live endpoint or model may bypass it.

Next independent streams: verified provider-contract/bounded-alternative work; extending the restricted code capability toward the separately scoped generic GitHub executor; adversarial QA and operator-free host recovery evidence. Real recruiting effects and production remain forbidden. A session/credit/rate interruption means persist and stop; no process is promised to continue after exit.
