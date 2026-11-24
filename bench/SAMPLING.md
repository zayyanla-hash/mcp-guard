# Benchmark Sampling Design

All external benchmark servers are sampled by `bench/select.mjs` from a snapshot of the official MCP Registry (`https://registry.modelcontextprotocol.io/v0.1/servers`) using fixed seed `20261123`.

## What Is Frozen

- **The sample is frozen in the manifests**, not in the snapshot. `bench/manifest.json` and `bench/python-manifest.json` pin each server's repository URL, commit SHA, license, stratum and split. Benchmark runs and labeling sheets read only these.
- **The registry snapshot is not committed.** `bench/registry-snapshot.json` (about 86 MB) is git-ignored. Each manifest records its `snapshotSha256`, `snapshotBytes` and `snapshotFetchedAt` so a kept copy can be checked against it.
- **Re-running the selector does not reproduce the sample**, even with `--from-snapshot`. Eligibility checks resolve each repository's current `HEAD` and fetch license files over the network at run time, so qualifying servers and pinned commits drift. Treat a re-run as a new sample, not a re-check of this one.
- **Manual scoping.** `mcparmory-registry-com-mcparmory-mailersend` carries a hand-set `subpath` (`servers/mailersend`) with a `subpathNote`. Its registry entry gives no `repository.subfolder`, and the repository holds 76 servers, so without the subpath the sheet would list every server's tools. A re-run of the selector drops this override.

## Eligibility Criteria

A registry entry qualifies if and only if:

1. It is an active `isLatest` server entry with an `npm` (TypeScript/JavaScript) or `pypi` (Python) package declaration.
2. It links a public GitHub repository whose `HEAD` commit SHA resolves via `git ls-remote`.
3. It is **not** a Vambrace fixture (`zayyanla-hash/vambrace`, `zayyanla-hash/mcp-guard`) and **not** `modelcontextprotocol/typescript-sdk`.
4. Its repository carries a verified OSI-approved license (`MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `MPL-2.0`, `GPL-2.0`/`3.0`, `LGPL-2.1`/`3.0`, `AGPL-3.0`, `EPL-2.0`, `Unlicense`, `0BSD`, `BSL-1.0`, `Zlib`, `Artistic-2.0`, or `CC0-1.0`) in its license file or package manifest.

Qualifying servers are ordered deterministically per language by `sha256("20261123:<lang>:<registryName>:<repoUrl>")`.

## Two Sampling Strata

1. **Stratum 1 — `random-registry` (unselected registry baseline)**
   - Targets up to **40 TypeScript/JavaScript** and **20 Python** qualifying servers (stopping at what qualifies if fewer are available).
   - Measures real-world registration patterns and rule precision/coverage on an unconditioned sample of published MCP servers.

2. **Stratum 2 — `sink-enriched` (sink-bearing servers)**
   - Drawn strictly from qualifying servers **not already sampled in Stratum 1**, continuing in the same seeded order (`seed: 20261123`).
   - Targets up to **15 TypeScript/JavaScript** and **10 Python** servers whose source files match at least one sink token via **plain-text search** (never using the Vambrace analyzer):
     - **TypeScript/JavaScript fixed list**: `exec`, `execSync`, `spawn` with `shell`, `child_process`, `readFile`, `writeFile`, `unlink`, `fetch`, `axios`, `http.request`, `process.env`.
     - **Python fixed list**: `subprocess`, `os.system`, `open`, `requests`, `httpx`, `os.environ`.

## Split and Reporting Discipline

- Each stratum is partitioned independently **by server** into `dev` (60%) and `test` (40%). No server appears in both splits or both strata.
- Blank dev worksheets record `stratum` on every row (`bench/labels/todo/typescript-dev.csv`, `bench/labels/todo/python-dev.csv`).
- `bench/score.mjs` and `bench/run.mjs` report metrics **separately per stratum** (`by_stratum`) as well as in aggregate, so improvements on sink-bearing servers never obscure registry-wide coverage or vice versa.
