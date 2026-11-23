# Changelog

## 1.1.0-rc1 (Release Candidate)

- Release candidate for Python MCP server support via WASM `web-tree-sitter` and `tree-sitter-python` (MIT, zero native builds) under `engine: 'vambrace-py'`.
- Recognizes FastMCP/Server `@mcp.tool()` decorators and `add_tool` calls, porting `MG001`–`MG004` and `MG006` to Python sinks (`subprocess`, `os.system`, `open`/`pathlib`, `requests`/`httpx`, `os.environ`) with explicit `UNRESOLVED_*` diagnostics.
- Added Python controls (`fixtures/python/`) and benchmark scaffolding in `BENCHMARK.md` while keeping TypeScript analysis behavior isolated from Python scanning.
- Retagged pre-release work as `v1.0.0-rc1` / `v1.1.0-rc1` release candidates and updated the deprecated `mcp-guard` CLI alias notice to target removal in `v2.0.0`.

## 1.0.0-rc1 (Release Candidate)

- Phase 1: Added 1-level local server factory support in `src/analyzer.ts` (`UNRESOLVED_FACTORY` diagnostics for deeper/imported/dynamic factories) and pre-registered `evaluation/v2/` (24/24 SDK example registrations recognized).
- Phase 2: Added benchmark infrastructure (`bench/`), Wilson 95% confidence intervals, AST evasion suite, grep/Opengrep baselines, performance tracking, and auto-generated `BENCHMARK.md`.
- Phase 3: Added SARIF 2.1.0 output (`--format sarif`) validated against OASIS schema, OWASP MCP Top 10 rule tags, GitHub Action (`action/`), verifiable release workflow (Syft SBOM, Sigstore keyless signing, npm provenance), `vambrace deps` (OSV-Scanner opt-in), and `vambrace config` (`MG008`–`MG012`).
- Phase 4: Added `MG007` tool poisoning checks with exact span/offset evidence, `--ignore-order` diff mode, optional `--engine cisco-yara` / `--engine promptguard` adapters + Python sidecar, and advisory `vambrace explain` with JSON schema validation, faithfulness checking, and exit-code invariance.
- Phase 5: Added Linux ToolHive container discovery backend (fail-closed), `vambrace.policy.yaml` schema + `--policy` enforcement, deterministic `vambrace policy compile --target agentgateway|mcp-context-protector`, and `e2e/` gateway verification harness.

## 0.3.0

- Renamed the project, npm package, and CLI from `MCP Guard` (`mcp-guard`) to `Vambrace` (`vambrace`).
- Kept `mcp-guard` as a deprecated binary alias emitting a one-line stderr notice until v0.4.0.
- Added `AGENTS.md` standing rules and `NOTICE` dependency/license attribution while keeping `src/analyzer.ts` and `evaluation/` unchanged from v0.2.1.

## 0.2.1

- Added an explicit `audit --fixture-root` annotation for repositories containing seeded examples. JSON, terminal, and HTML reports identify operator-declared fixture paths while retaining every finding, coverage diagnostic, and policy exit. Paths are validated within the audit root; the declaration does not establish safety.
- Preserved the vulnerable and ambiguous fixtures as positive and uncertainty controls.

## 0.2.0

Added explicitly approved reviewed-fixture discovery through official SDK v2 under runtime-verified macOS OS restrictions. Added parent source-watchdog, cancellation/PID cleanup and adversarial protocol tests. Fixed registration/process aliases, credential sinks, local schema refs, contradictory coverage and output-path redaction. Packaged shrinkwrap locks transitive dependencies. Default validation remains offline; isolated discovery has a separate opt-in gate.

## 0.1.0

Initial experimental offline release: source auditing for five implementation rules, MG005 inventory/schema validation, deterministic snapshots/drift, terminal/JSON/self-contained HTML, paired seeded fixtures, coverage-aware exits, bounds/redaction, and no target execution. Optional live discovery is explicitly blocked.
