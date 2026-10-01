# Recruiter case study: MCP Guard

## A narrow security review that keeps evidence and uncertainty visible

**One-line summary.** I built MCP Guard, an experimental TypeScript CLI that audits a documented subset of MCP servers for six source and descriptor patterns, records evidence for each observation, compares declared tool inventories, and makes incomplete coverage visible in CI.

### The engineering problem

An MCP server can publish tool names and schemas, but those declarations do not show what a handler does or whether its capabilities changed after review. A useful review aid has to connect a supported implementation pattern to source evidence, distinguish a descriptor defect from behavior, and say when it could not finish an assessment. A clean result must not imply universal safety.

### What I built

The source analyzer parses JavaScript and TypeScript with the TypeScript compiler API. It resolves imported API identity and local registration-to-handler mappings before checking direct patterns for shell use, filesystem paths, outbound destinations, environment exposure, and read-only declarations contradicted by filesystem mutation. It does not infer behavior from matching words in comments or strings. A separate inventory path checks descriptor and JSON Schema structure, preserves snapshots, and reports selected changes such as tool additions, description edits, and required-input removal.

Every finding carries a rule, severity, confidence, evidence type, source coordinates or JSON Pointer, observed text, assumptions, limitations, and remediation. These fields answer different questions: severity describes potential impact under stated conditions, confidence describes how directly the supported pattern matched, and coverage says whether the declared analysis completed. Incomplete coverage takes precedence in the CI exit policy. A source finding is static evidence, while a descriptor finding is an observation about supplied metadata; neither proves deployed permissions or exploitation.

The default audit is offline and never executes its target. The separate discovery command can execute only a reviewed project-owned fixture, after explicit approval and a passing macOS Seatbelt probe. The probe checks denial of outside-canary reads and writes, sockets, child processes, and inherited fake-secret environment values. Other platforms block that command. This is reviewed-fixture isolation, not a general-purpose sandbox for arbitrary code.

### Decisions that shaped the scope

- **AST and symbol identity instead of string matching.** Text matching would confuse comments, strings, aliases, and real API calls. Parsing lets the supported rules follow syntax and imported API identity. Unsupported wrappers and interprocedural behavior remain manual-review cases rather than being guessed.
- **Evidence, confidence, severity, and coverage stay separate.** A high-severity observation can still be incomplete or uncertain. One score would hide whether the tool observed a supported pattern, how directly it matched, and what it failed to inspect.
- **Inventory is treated as declared capability.** Acquisition context is caller-supplied and unverified. A descriptor diff describes metadata change; it does not establish that implementation behavior changed or that a server is malicious.
- **Explicit fixture labels preserve findings.** The v0.2.1 `--fixture-root` option labels an operator-declared path in output but retains findings, coverage, and exit behavior. It does not decide whether files are harmless.
- **Arbitrary discovery and broad helper recognition stay out of scope.** Arbitrary server/config execution and general-purpose sandbox claims would exceed the demonstrated controls. Likewise, `path.join`, `path.resolve`, HTTPS, or a helper named `safePath` do not by themselves prove a policy. Fixed-capability corrected fixtures and explicit unresolved diagnostics are safer evidence boundaries.

### Evidence and limits

The published v0.2.1 checkpoint records 123 passing offline tests, 12 passing macOS discovery/isolation tests, the seeded demo outcomes, and four CI jobs across Linux/macOS and Node 24/26. These are implementation checks against project-owned controls, not an independent accuracy estimate. The evaluation cases were visible during development; challenges that changed implementation are regressions, not a holdout. There is no measured real-world detection rate, commercial-scanner comparison, production adoption claim, or security certification.

The released evidence is available at [v0.2.1 commit](https://github.com/zayyanla-hash/mcp-guard/commit/ae5115ea07cdfb77436aba59f2f198ba1d448595), with the [release archive and checksum](https://github.com/zayyanla-hash/mcp-guard/releases/tag/v0.2.1). Useful regression history includes [conservative handling of unresolved writes and open flags](https://github.com/zayyanla-hash/mcp-guard/commit/6928ee10c28aa81c6952b1ab14cd588cd3fdb645), [bounded reviewed-fixture discovery and isolation](https://github.com/zayyanla-hash/mcp-guard/commit/ff3ce869fd5ee625db1cc2846643db96d18cc880), and [fixture-path labels that retain findings](https://github.com/zayyanla-hash/mcp-guard/commit/ae5115ea07cdfb77436aba59f2f198ba1d448595).

The [browser demonstration](https://zayyanla-hash.github.io/mcp-guard/) presents recorded seeded findings, corrected controls, descriptor evidence, and drift. A separate [external coverage study](EVALUATION-EXTERNAL.md) uses 24 actual handlers across seven unchanged official SDK source files at a pinned revision. The analyzer reported four recognized registrations in aggregate; manual review identified 20 factory-bound registrations outside the supported shape. All seven files had incomplete coverage, so its zero findings do not establish safety and there are no scored accuracy controls. This study identifies a concrete coverage gap rather than a real-world detection rate. See [the architecture note](ARCHITECTURE.md), [walkthrough script](WALKTHROUGH.md), and [review package](REVIEW-PACKAGE.md) for a technical tour and ways to assess the work.
