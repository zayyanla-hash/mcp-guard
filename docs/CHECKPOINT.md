# v0.2.0 readiness checkpoint

Objective: finish the documented offline CLI release and add explicitly approved isolated local discovery against a reviewed project-owned fixture. Repository: zayyanla-hash/mcp-guard. Starting release commit 6928ee10c28aa81c6952b1ab14cd588cd3fdb645 remains immutable at v0.1.0. This checkpoint is recorded in the readiness-v0.2 worktree before release commit/public verification; the final checkpoint asset contains the resulting identities.

Files changed: analyzer/CLI/inventory/reporting contracts and tests; bounded whole-source child/watchdog; discovery/isolation/probe modules and reviewed/adversarial fixtures; package version and transitive npm-shrinkwrap; default offline and separate opt-in discovery test scripts; recorded examples; README/rule/threat/discovery/release/portfolio docs; CI. No production runtime defaults/model configuration or unrelated repository changed.

Personally observed validation on macOS/Node26.9.0:

```text
✔ common explicit connection and access credentials are reported while ordinary environment names stay quiet (5.349458ms)
ℹ tests 121
ℹ suites 0
ℹ pass 121
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 4970.353208
✔ timeout and cancellation remove only the launched child (229.436084ms)
ℹ tests 12
ℹ suites 0
ℹ pass 12
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 5454.979542
```

Exact portable commands executed from the readiness root:

- `npm ci --ignore-scripts` → 0
- `npm test` → 0
- `npm run validate` → 0
- `npm run test:discovery` → 0
- `npm run demo -- --out demo-output-ready` → 0
- `node dist/cli.js --help` → 0
- `node dist/cli.js --version` → 0
- `node dist/cli.js invalid-command` → 2
- `node dist/cli.js audit fixtures/vulnerable --format json` → 1
- `node dist/cli.js audit fixtures/corrected --format json` → 0
- `node dist/cli.js audit fixtures/ambiguous --format json` → 3
- `node dist/cli.js discover` → 3

The explicit reviewed-fixture discovery command additionally preserved a validated inventory and scan result to new external paths, and snapshot creation from that acquired inventory returned 0. Full exact local command paths/stdout/stderr are in work/readiness-validation/commands.json and logs. Live acquisition is reproduced via examples/discovery/tools.json, scan.json and snapshot.json. The demo source fixtures still yield five findings before correction and zero after; descriptor drift remains visible.

Verified OS controls: outside fake-canary regular-file read/write, socket creation, child spawning, and environment inheritance are denied. Timeout/cancellation kill the launched PID. Discovery only requests tools/list through official SDK client/server2.2.0, pinned2026-07-28 stdio. Arbitrary server commands/configurations remain blocked. Directory enumeration/file metadata/system IPC remain outside this reviewed-fixture confinement claim. Linux/other platforms explicitly block discovery rather than fall back; static commands remain supported on tested platforms.

Remaining gate work at checkpoint: final archive install/discovery check, publish readiness code only to zayyanla-hash, verify all four CI jobs, create v0.2.0 release with checksum/checkpoint, and verify the public downloaded installation. SARIF and independent real-world accuracy remain outside this release. Broad security certification is not claimed.

Recommended next action: package and verify the compiled release before publishing; preserve v0.1.0 and its historical local/cloud evidence boundaries.
