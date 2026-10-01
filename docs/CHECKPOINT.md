# Local release checkpoint

Objective: deliver an evidence-linked experimental offline MCP Guard CLI and a reproducible GitHub-first release under zayyanla-hash.

Repository identifier: zayyanla-hash/mcp-guard; local release checkout outputs/mcp-guard-release. Initial tracked source commit: f66a376. A final hardening/validation commit is pending at this checkpoint; exact release identity is saved in the final handoff. Exact commit/CI/archive identities are preserved in the final session handoff.

Files changed: package.json, package-lock.json, tsconfig.json, .gitignore, src/*, tests/*, fixtures/*, examples/seeded/*, docs/*, README.md, LICENSE, SECURITY.md, CHANGELOG.md and .github/workflows/ci.yml. No production runtime or unrelated repository was modified.

Observed local validation on Node 26.9.0 / npm 11.19.1:

```text
✔ compound assignment retains an explicit incomplete assessment (0.587125ms)
ℹ tests 110
ℹ suites 0
ℹ pass 110
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 3554.614959
```

Exact commands and exits, from the release root:

- `npm test` → 0
- `npm run validate` → 0
- `npm run demo -- --out demo-output-published` → 0
- `node dist/cli.js --help` → 0
- `node dist/cli.js --version` → 0
- `node dist/cli.js invalid-command` → 2
- `node dist/cli.js audit fixtures/vulnerable --format json` → 1
- `node dist/cli.js audit fixtures/corrected --format json` → 0
- `node dist/cli.js audit fixtures/ambiguous --format json` → 3
- `node dist/cli.js inventory fixtures/inventories/vulnerable.json --format json` → 1
- `node dist/cli.js inventory fixtures/inventories/corrected.json --format json` → 0
- `node dist/cli.js diff demo-output-published/before.snapshot.json demo-output-published/after.snapshot.json --format json` → 1
- `node dist/cli.js discover` → 3
- Report rendering from preserved vulnerable JSON to a new external HTML path: exit 0.
- Local archive install with scripts disabled: exit 0; installed help/version/demo: exit 0. A final archive is repacked after this checkpoint.

Expected nonzero exits are required checks, not test failures. Initial development validation found a macOS canonical-path test expectation and a missed dynamic lookup; both were fixed and then rerun. Independent review cases were added rather than weakening assertions.

Remaining work at this checkpoint: push the created public repository only to zayyanla-hash, inspect actual four-matrix CI results, publish v0.1.0 archive/checksum, verify public download/install, and save the final handoff with identities. Live discovery remains explicitly blocked, SARIF omitted, static coverage limited to documented patterns. No model credentials are required by the product.

Recommended next action: publish the locally verified source to the designated GitHub owner, then verify CI before creating the release. See docs/PORTFOLIO.md for the ranked follow-on experiments.
