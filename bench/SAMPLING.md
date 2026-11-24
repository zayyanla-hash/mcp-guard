# Benchmark Sampling Design

All external benchmark servers are sampled deterministically by `bench/select.mjs` from a frozen snapshot of the official MCP Registry (`bench/registry-snapshot.json`, `https://registry.modelcontextprotocol.io/v0.1/servers`) using fixed seed `20261123`.

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
