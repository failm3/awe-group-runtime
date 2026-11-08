# GitHub audit snapshot — 09.11.2026

**Synchronization only. Partial source export, not a self-contained executable release.** No product logic was edited, no AWE/LLM/provider/utility was executed, no database was connected, no migration or test suite was run during this synchronization.

The source worktree remains at `c9f8fd548175b68029e8dcecc061b77a154170c9` with its existing uncommitted overlay. Its branch and all three local commits were preserved. This export starts at the published Runtime PR #9 head `b68c35480836dbafd27208d0eca69383fb0532b9`; 66 reviewed files were copied byte-for-byte from the latest local state. [MANIFEST.json](MANIFEST.json) records each SHA-256, size, source identity and exclusion.

## Publication boundary

Three current source files contain absolute host-specific PostgreSQL bindings. Publishing their existing commits would publish those paths. Under the owner's explicit no-local-absolute-path rule, these files and the commits containing them were left local; their contents were neither rewritten nor redacted:

- `E1/coordinator/coding-run.mjs`
- `E1/coordinator/migrations/0007-coding-run-state.sql`
- `E1/coordinator/migrations/0008-coding-head-authority.sql`

The manifest supplies their exact hashes. Some exported modules/tests depend on those omitted files: **do not treat this partial export as a runnable package or claim all source is public**. Completing the source publication requires a separate decision about the binding paths, or a later authorized portability change. Neither was performed here. Generic OS/sandbox paths and explicit synthetic test paths are code constants, not exported private host locations.

Private configuration, credentials, signing material, PGDATA, raw logs and unrelated legacy evidence remain local. No key file was opened. The separate clean-verification worktree was preserved: its modified test is already byte-identical to the published PR #9 version; its historical test report is archived separately in Academy, not substituted for current runtime evidence. Older cloud/recruit/base worktrees were not merged into this branch.

## What the saved evidence actually says

- P0/P1/P2/P3 source, Head REPAIR, recovery/session, mission-runner and tool-library code are represented here as found. The missing native decision-state/DDL bindings are listed above.
- Original G1 generated two files but failed with a CLI SyntaxError. The bounded repair exhausted four confirmed model wires including that original attempt. Repair r02 still failed; r03 was rejected as no change. The saved native state is STOPPED/CANCELLED, with zero leases and zero remaining quota. G1 did not pass; full three-file G2 and dynamic G3 are not proven.
- Recorded usage is 4725 input / 1789 output tokens and zero local API charge, with no UNKNOWN among these four real calls. This synchronization did not remeasure infrastructure, Codex cost or any current balance.
- The stored independent stopped witness reports 66 original source pins and two cooperative child restarts. It is historical execution evidence, not a fresh synchronization-time test or proof of arbitrary crash/power-loss recovery.
- Tool metadata discovery, scoped review/activation, a four-type selection policy and native utility canary source exist. Stored installed-tool probe reports and selection-policy test source are included. A complete corrected native cold tool result is **not present** in this snapshot. The last retrospective timestamp/verifier changes were interrupted by the session usage limit; they are published as unexecuted/unverified source. No final tool-cold PASS or live tool-versus-LLM comparison is claimed.
- Router.Cheap paid generation, production, merge, new agent provisioning and full autonomous coding acceptance remain unproven or disabled.

The implementation reports dated 08.11.2026 are preserved unchanged as historical work-in-progress. This synchronization note defines the current publication boundary and overrides any implication that the omitted modules or pending cold proof were published or freshly verified.
