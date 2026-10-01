# MCP Guard architecture

MCP Guard has two input paths and one reporting contract. The paths keep source implementation patterns separate from supplied tool metadata.

```text
JavaScript / TypeScript tree ── bounded scanner ── AST source rules ──┐
                                                                     ├─ validated audit result ── text / JSON / HTML / CI exit
Tool inventory JSON ────────── bounded data checks ── snapshots/diff ┘

Reviewed-fixture discovery (explicit opt-in, macOS probe) ── inventory JSON
```

## 1. Source path

`src/scanner.ts` walks the selected source root, applies file and resource bounds, and sends files to a worker with a deadline. It records excluded, failed, or truncated inputs in coverage. `src/analyzer.ts` parses each supported file with the TypeScript compiler API, then uses the checker to identify imports and locally registered handlers. The analysis follows a bounded set of direct expressions and API calls; it is not whole-program taint analysis.

The five source observations are MG001 shell input, MG002 tool input reaching filesystem paths without a recognized supported containment check, MG003 tool-controlled outbound destinations, MG004 environment exposure to output, and MG006 a direct filesystem mutation mapped to a `readOnlyHint: true` tool. MG005 belongs to descriptor inspection. The scope deliberately does not recognize arbitrary wrappers, imported helper effects, or deployment policy.

AST and symbol information give the rules a meaningful distinction from searching for words such as `exec` or `process.env`: text in comments and strings is data; an imported alias can still refer to a known API. The analysis still makes only the supported local mapping. Unresolved or unsupported behavior must not be read as proof of safety.

## 2. Inventory path

`src/inventory.ts` accepts JSON data, not an executable server. It validates the envelope, descriptor fields, supported protocol labels, and the supported JSON Schema 2020-12 subset. It resolves local pointer and anchor references without network access. Remote references, unsupported dialects/features, and malformed inputs create diagnostics and incomplete coverage rather than fabricated invalidity findings.

Snapshots preserve meaningful content and array ordering while sorting object keys for deterministic hashes. Diffs report selected descriptor changes. The acquisition context is a declaration supplied by the caller; it is not independently verified. Inventory output describes advertised tools and schemas, not handler behavior, actual access, or a malicious change.

## 3. Findings and policy

`src/types.ts` defines the shared result contract. A finding stores:

- **Evidence type and location:** static pattern with source coordinates, or metadata observation with a JSON Pointer.
- **Confidence:** high or medium, describing support for this recorded observation.
- **Severity:** low, medium, or high, used by the threshold policy.
- **Assumptions and limitations:** conditions required for the interpretation and what the rule does not establish.
- **Coverage:** a separate audit-level account of inspected, excluded, failed, truncated, and unresolved work.

`src/policy.ts` gives incomplete coverage exit 3. Otherwise, a finding at or above the requested threshold or any recorded descriptor change exits 1; a complete result below threshold exits 0. Invalid input and processing errors exit 2. Exit 0 means only that the assessment completed within declared scope and stayed below the selected policy threshold.

`src/reporting.ts` validates result data before rendering terminal, JSON, or HTML output. Evidence is redacted through shared helpers; output is derived from recorded results rather than hand-authored findings. `src/cli.ts` keeps report and snapshot outputs as new files and rejects invalid fixture-root declarations.

## 4. Execution boundary

Normal `audit`, `inventory`, `snapshot`, `diff`, and `report` operations do not start an audited target. Discovery is a separate explicit operation. It accepts no arbitrary command, URL, server configuration, or executable path. It selects a fixed reviewed fixture, pins the official SDK protocol, requests only `tools/list`, and has frame, byte, time, page, and memory bounds.

Before that fixture starts, `src/isolation.ts` runs a macOS Seatbelt probe against project-owned canaries for outside-file reads and writes, socket creation, child spawning, and fake-secret environment inheritance. The launcher allows only reviewed fixture basenames and blocks discovery on platforms without a verified backend. The checks establish a narrow reviewed-fixture boundary; they do not establish confinement of directory metadata, system IPC, or arbitrary hostile code.

## 5. Evidence links

- Rule behavior and assumptions: [RULES.md](RULES.md), [SUPPORTED-PATTERNS.md](SUPPORTED-PATTERNS.md), and [LIMITATIONS.md](LIMITATIONS.md).
- Seeded evaluation contract and denominators: [EVALUATION.md](EVALUATION.md).
- Release checkpoint and observed validation: [CHECKPOINT.md](CHECKPOINT.md).
- Source-analysis regression: [6928ee1](https://github.com/zayyanla-hash/mcp-guard/commit/6928ee10c28aa81c6952b1ab14cd588cd3fdb645) adds conservative handling for unresolved writes and open flags.
- Discovery boundary: [ff3ce86](https://github.com/zayyanla-hash/mcp-guard/commit/ff3ce869fd5ee625db1cc2846643db96d18cc880).
- Fixture-reporting boundary: [ae5115e](https://github.com/zayyanla-hash/mcp-guard/commit/ae5115ea07cdfb77436aba59f2f198ba1d448595).
