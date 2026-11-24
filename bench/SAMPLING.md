# Benchmark Sampling Design

All external benchmark servers are sampled by `bench/select.mjs` from a snapshot of the official MCP Registry (`https://registry.modelcontextprotocol.io/v0.1/servers`) using fixed seed `20261123`.

## What Is Frozen

- **The sample is frozen in the manifests**, not in the snapshot. `bench/manifest.json` and `bench/python-manifest.json` pin each server's repository URL, commit SHA, license, stratum and split. Benchmark runs and labeling sheets read only these.
- **The registry snapshot is not committed.** `bench/registry-snapshot.json` (about 86 MB) is git-ignored. Each manifest records its `snapshotSha256`, `snapshotBytes` and `snapshotFetchedAt` so a kept copy can be checked against it.
- **Re-running the selector does not reproduce the sample**, even with `--from-snapshot`. Eligibility checks resolve each repository's current `HEAD` and fetch license files over the network at run time, so qualifying servers and pinned commits drift. Treat a re-run as a new sample, not a re-check of this one.
- **Manual scoping.** `mcparmory-registry-com-mcparmory-mailersend` carries a hand-set `subpath` (`servers/mailersend`) with a `subpathNote`. Its registry entry gives no `repository.subfolder`, and the repository holds 76 servers, so without the subpath the sheet would list every server's tools. The selector also carries this manual override. Demo Time (`apps/mcp`) and Janosik (`mcp`) are scoped to their matching registry npm packages, since their registry entries omit subfolders. Other monorepos with a declared registry subfolder use that scope.

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
   - Takes the first **15 TypeScript/JavaScript** and **10 Python** eligible servers whose **server code** matches at least one **strong** token via plain-text search (never using the Vambrace analyzer).
   - **Server code only.** The scan skips files under `test`, `tests`, `__tests__`, `spec`, `e2e`, `fixtures`, `__mocks__`, `script(s)`, `doc(s)`, `example(s)`, `bench(mark(s))` and `.github` directories, plus `*.test.*`, `*.spec.*`, `test_*.py`, `*_test.py`, `conftest.py`, `setup.py`/`*_setup.py`, `*.config.*` files, and build, release and install helpers named `build*`, `release*`, `version*`, `publish*`, `prepare*`, `postinstall*`, `install*` or `setup*` (`.js`/`.ts`). A sink that only appears there says nothing about what the server runs.
   - **TypeScript/JavaScript strong tokens:** a `child_process` import or `require`; a bare `exec(`/`execSync(` call in a file that loads `child_process` (method calls such as `regex.exec(` or `db.exec(` do not count); `spawn` with an explicitly enabled `shell` option; `writeFile`; `unlink`.
   - **Python strong tokens:** `import subprocess`/`from subprocess import` or `asyncio.create_subprocess_exec`/`_shell` (the word "subprocess" in a comment or docstring does not count); `os.system`/`os.popen`.
   - Other tracked tokens (e.g. `fetch`, `process.env`, `readFile`, `open`, `requests`, `httpx`) can be recorded in `matchedSinks` but cannot qualify a server on their own. A textual match is an enrichment signal, not a finding or human label.
   - Resume against the original verified snapshot with `node bench/select.mjs --from-snapshot --refresh-sink-enriched`: keep both pinned Stratum 1 lists unchanged, start after each final Stratum 1 rank, verify each candidate lazily, and stop at the quota. License recognition reads license blobs from the pinned shallow Git repository without checking out or executing candidate code. The optional source scan reads only plain text under the selected scope. This command refreshes Stratum 2; it is not a reproducibility check for its newly pinned commits.

## Split and Reporting Discipline

- Each stratum is partitioned independently **by server** into `dev` (60%) and `test` (40%). No server appears in both splits or both strata.
- Blank dev worksheets record `stratum` on every row (`bench/labels/todo/typescript-dev.csv`, `bench/labels/todo/python-dev.csv`).
- `bench/score.mjs` and `bench/run.mjs` report metrics **separately per stratum** (`by_stratum`) as well as in aggregate, so improvements on sink-bearing servers never obscure registry-wide coverage or vice versa.

## Sampling log

- **2026-11-24 (UTC):** Stratum 2 re-picked from the original snapshot under the strong-token rule. All pinned Stratum 1 records, including the manual MailerSend scope, were kept unchanged.
- **2026-11-24 (UTC), second re-pick:** Stratum 2 re-picked again after review found that 10 of 15 TypeScript and 3 of 10 Python picks had strong tokens only in tests, scripts, docs or setup files, or only as `regex.exec(`/`db.exec(` method calls. The scan now reads server code only and matches real imports and calls. Stratum 1 is unchanged.
