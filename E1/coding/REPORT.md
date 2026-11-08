# G1 implementation and actual first attempt

P0/P1/P2/P3 were implemented on the existing A1/A2/A3/PG/Coding Executor. The first actual one-shot G1 **FAILED**. It must never be reported as full autonomy or successful G1.

- Source before generation: `9e3aa737db653e6e8d8d712da0557fe1ac2677ca`; original runtime base `9c3eaa182a862dadd5a326836408063b45f7219c`.
- Frozen task: [Issue #8](https://github.com/failm3/awe-group-runtime/issues/8). Sol acquired and pinned a GitHub snapshot; AWE did not ingest GitHub itself.
- Actual AWE local Qwen generation: **1 wire**, 763 input / 554 output tokens, 65,050ms measured latency, **0 API micros**. Infrastructure and Codex costs are not measured here.
- AWE generated both `normalizer.py` and `cli.py`; actual Git commit `0e79374b60ab35e089ab36d6d9e6787dd63dc6e9`, tree `e71dc3f0a66d1f29a09cdb572ed6d03666bf5592`.
- `cli.py` contains literal backslash-n tokens outside Python string literals. The real sandbox reported SyntaxError. Sol did not fix or normalize these candidate bytes.
- Independent Astra QA replayed actual code, independently read raw Git objects and performed native WAIT_QA → FAILED. Exactly one QA_FAIL and zero QA_PASS; one CONFIRMED model attempt and consumed quota remain. The mission stays ACTIVE under existing A2 semantics; it is not COMPLETE.

Evidence: [runtime report](evidence/g1_normalize_01.json), [independent negative witness](../qa-coding/evidence/FAIL-g1_normalize_01.json), [preflight](evidence/PREFLIGHT.json), [AWE-generated files](artifacts/g1_normalize_01/).

Sol and engineers implemented the host adapters, versioned scoped contracts, runner, fixtures, grants/publication and QA plumbing. Sol chose and started this bounded test. AWE's actual contribution was the raw patch/code; there was no model-authored plan or autonomous repair in this run.

Next experiment: **TWO_FILE_BOUNDED_REPAIR**, with the immutable failed attempt adopted explicitly. Aggregate cap 4 includes the consumed original wire; at most one new Head plus two new code attempts. No reset through a new project or task. This will exercise durable automatic continuation; the full audit G2 three-file gate remains NOT_PROVEN.

The separate tool-library stream located the original 4,504 records by exact import hash. Existing tool_registry discovery remains metadata-only. E1 review/selection/dispatch and the small installed-tool proof are separate work, not proof that AWE has dispatched native tool tasks yet. No mass parsing or installation.

E0, original worktrees and PG5432 were not modified. Cloud remains disabled by the existing financial gates. No merge, external recruiting action or production release.

## Final bounded repair result

The actual repair trial is **STOPPED_MODEL_ATTEMPT_CAP_EXHAUSTED**, not PASS. Four CONFIRMED wires include the original code, one accepted bounded Head decision, and two repair generations: 4725 input / 1789 output tokens, API micros 0, UNKNOWN 0. The r02 candidate retained the CLI SyntaxError; r03 repeated both files unchanged and was rejected as CODING_NO_CHANGE. Original G1 failure remains immutable.

Two supervised child exits and automatic restarts were observed after model fsync and native completion. They continued the same native attempt/result without another wire. This is bounded cooperative child-process recovery, not arbitrary SIGKILL/power-loss or successful G2. Sol performed one explicitly recorded post-stop terminal finalization; the new mission is CANCELLED, outer STOPPED, leases 0, remaining quota 0.

[Terminal state](evidence/STOPPED-repair_normalize_01.json), [independent negative cold witness](../qa-repair/evidence/STOPPED-repair_normalize_01.json), [quality observations](evidence/QUALITY-OBSERVATIONS.json), [failed r02 and rejected r03](artifacts/repair_normalize_01/). Source code and model outputs are preserved separately; no candidate was repaired by Codex. Full three-file G2 and dynamic G3 remain NOT_PROVEN.

The tool-library bridge and deterministic native utility proof are tracked separately under E1/tooling/. A local model catalog also lists gpt-oss:20b, but no generation, route binding, resource fit or quality claim was made for it. A closed trial must never be restarted through a new identity to hide consumed counters.
