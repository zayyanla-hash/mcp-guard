# MCP Guard

A local CLI for reviewing specific risky MCP implementation patterns, validating offline tool inventories, and comparing declared capabilities over time.

**Status: v0.2.1, scoped developer release.** Static analysis supports a documented subset of JavaScript/TypeScript. Findings include evidence and assumptions; incomplete assessments are visible. This is a defensive auditor, not a runtime firewall or a security certification.

## Try the recorded offline demonstration

Requires Node.js 24 or newer and npm. No model credentials or external servers are needed.

```sh
git clone https://github.com/zayyanla-hash/mcp-guard.git
cd mcp-guard
npm ci --ignore-scripts
npm run validate
npm run demo
```

The demo parses project-owned seeded fixtures, records five source-rule findings, rescans a corrected fixture with zero findings in the supported scope, validates paired inventory descriptors, detects description/schema drift, and writes inspectable JSON and HTML to `demo-output/`. A repeat demo requires a different output directory:

```sh
npm run demo -- --out demo-output-2
```

These results measure seeded examples, not real-world detection accuracy. No fixture server is started.

## Install the GitHub release

Distribution is through the GitHub release archive. The registry package named `mcp-guard` belongs to someone else; do not install it as this project.

```sh
npm install --global https://github.com/zayyanla-hash/mcp-guard/releases/download/v0.2.1/mcp-guard-0.2.1.tgz --ignore-scripts
mcp-guard --help
mcp-guard --version
```

The archive contains compiled code; installation does not require a build. Its runtime dependencies are locked by the packaged npm-shrinkwrap.json, including TypeScript (parser), Ajv (schema meta-validation), the official MCP SDK and Zod (reviewed fixture schemas).

## Commands

Build once with `npm run build` when running from source.

```sh
npm run guard -- audit ./fixtures/vulnerable --format json --out ../scan.json
npm run guard -- audit ./fixtures/corrected
npm run guard -- inventory ./fixtures/inventories/valid.json
npm run guard -- snapshot ./fixtures/inventories/valid.json --out ../before.json
npm run guard -- snapshot ./fixtures/inventories/drift.json --out ../after.json
npm run guard -- diff ../before.json ../after.json
npm run guard -- report ../scan.json --out ../report.html
```

When scanning a repository that contains seeded test fixtures, the operator can label a fixture directory without suppressing findings:

```sh
npm run guard -- audit . --fixture-root fixtures --format json --out ../repository-scan.json
npm run guard -- report ../repository-scan.json --out ../repository-scan.html
```

The report calls this an **operator-declared fixture path**. MCP Guard does not verify that code under the path is harmless. The label does not change findings, coverage, or CI exit codes. Use it only for an actual test-fixture directory within the selected source root.

Outputs must be new files. Source audit output must be outside the selected target root. No baseline is overwritten automatically. `--threshold low|medium|high` sets the finding policy (default medium); descriptor drift requires review independently of severity. `--format terminal|json` applies to audit, inventory, and diff. There are no automatic suppressions or executable configuration plugins.

| Exit | Meaning |
|---|---|
| 0 | Complete within declared scope, below finding threshold, no descriptor drift |
| 1 | Findings meet threshold or observable descriptor drift requires review |
| 2 | Invalid input, resource-processing failure, or execution error |
| 3 | Required coverage incomplete, unsupported analysis, or discovery blocked |

Incomplete coverage takes priority over finding severity. A successful exit does not establish that a target is secure. A report-rendering exit only describes report generation.

## Isolated local discovery (macOS)

Explicitly approve only the reviewed built-in fixture:

```sh
npm run discovery:demo
npm run guard -- discover --fixture reviewed --approve-execution --format json --inventory-out ../discovered-tools.json
npm run guard -- snapshot ../discovered-tools.json --out ../discovered.snapshot.json
npm run test:discovery
```

The exact executable/argument array is shown before startup. A runtime OS probe must prove that outside canary reads/writes, sockets and child spawning are denied. The server receives a minimal environment, no credential inheritance, bounded memory/stdio/time, and uses official SDK stdio framing with protocol 2026-07-28 pinned. Only tools/list is requested; no tools or resources are invoked. Arbitrary server/config/URL execution is blocked. Linux and other platforms fail closed for this command. See [discovery and isolation](docs/DISCOVERY.md).

`npm run validate` remains offline and never starts a fixture server. `npm run validate:all` additionally opts into the reviewed fixture's isolation/discovery tests. Both gates run in CI; macOS verifies live success, while Linux verifies explicit blocking.

## Six core rules

| Rule | Supported observation |
|---|---|
| MG001 | Tool input reaches shell command construction or shell-enabled process execution |
| MG002 | Tool input reaches filesystem paths without an established supported containment check |
| MG003 | Tool input controls an outbound destination; destination policy is unresolved |
| MG004 | Whole environment or explicit secret-bearing environment values reach return/log output |
| MG005 | Invalid descriptor/schema structure, with unsupported schema features reported separately |
| MG006 | A mapped read-only declaration contradicts a direct filesystem mutation |

See [rule contracts](docs/RULES.md), [supported patterns](docs/SUPPORTED-PATTERNS.md), [limitations](docs/LIMITATIONS.md), and [threat model](docs/THREAT-MODEL.md).

## Inventory contract and drift

Offline JSON uses `{ "tools": [...] }`, with optional `protocolVersion`, `metadata`, and an explicit `acquisitionContext` recording source, transport, and authorization context. Context is a user-supplied declaration. It is not permission verification.

Snapshots preserve all meaningful content and array ordering, normalize object key ordering, and carry a SHA-256 hash. Description, schema, annotation, tool additions/removals, required-field removal, and context changes are explained. A change is a review observation, not evidence of a malicious rug pull. A stable snapshot says nothing about unseen implementation changes.

JSON Schema 2020-12 meta-validation is supported. Remote references are never resolved. Unknown features, protocols, handlers, parse failures, traversal limits, and unsupported files can make coverage incomplete. Optional annotations are not required and do not enforce permissions. Local JSON pointer/anchor references are checked offline; unresolved references make coverage incomplete.

## Release and contribution

[Evaluation](docs/EVALUATION.md) describes tests and denominators. [Contributor guide](docs/CONTRIBUTING.md), [security reporting](SECURITY.md), and [release scope](docs/RELEASE.md) define maintenance and evidence boundaries. [CI](.github/workflows/ci.yml) uses no secrets and never executes audit targets.

This release was integrated using Codex with Luna assisting inventory/report work and review. Historical local-worker bootstrap trials are distinct from the cloud-assisted product implementation; [the evidence note](docs/LOCAL-HARNESS-EVIDENCE.md) explains that boundary.
