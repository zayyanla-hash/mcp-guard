# Recruiter case study

## MCP Guard — evidence and uncertainty in an offline security CLI

**Portfolio sentence:** Built an experimental TypeScript CLI that identifies six narrowly scoped MCP audit observations, preserves source or JSON-pointer evidence, compares deterministic capability snapshots, and reports incomplete coverage through CI-compatible exits.

The problem: engineers can see a server's declared tools without understanding risky handler patterns or whether metadata changed after review. A useful auditor must keep source behavior, declarations, confidence and coverage separate.

The implementation uses a real TypeScript AST, lexical import identity, same-file handler mapping, bounded worker analysis, and a data-only inventory adapter. Snapshots preserve meaningful content and array ordering while sorting object keys. Reports are rendered from recorded, validated results; they contain no invented findings or aggregate security score.

The project-owned seeded demonstration identifies shell input, filesystem paths, outbound destinations, environment exposure and a read-only contradiction. Corrected controls remove those findings in the supported scope. A paired descriptor fixture exercises the sixth rule. Subsequent description/schema changes produce inspectable drift under equivalent declared acquisition context.

Security review added conservative diagnostics for branch reassignment, nonliteral shell options, computed calls and generated-source exclusions. This illustrates a deliberate engineering tradeoff: incomplete assessment is preferable to a misleading clean verdict. The default auditor never executes targets and needs no model credentials.

**Evidence:** source and negative controls in tests/source.test.mjs; bounded scanner controls in tests/scanner.test.mjs; inventory/report/CLI suites; generated reports in examples/seeded; reproducible offline demo and least-privilege CI.

**Boundaries:** scoped release, limited registration/language support, no whole-program analysis, reviewed-fixture discovery only on verified macOS isolation, no independent real-world accuracy estimate, and no security certification. Luna-assisted implementation and historical local harness trials are disclosed separately. Test counts and release state should be read from the current checkpoint.

## Next three experiments

1. **Expand one dataflow boundary safely.** Add constant options and helper summaries for one reviewed filesystem containment pattern. Acceptance: positives, fixed-path negatives, traversal/absolute/prefix/symlink behavior controls and unresolved helper diagnostics; no clean result for unmodeled helper effects.
2. **Evaluate on an authorized external corpus.** Define expected outcomes before tuning for at least 20 public, license-compatible reviewed tool handlers; preserve provenance and count detected/missed/unsupported outcomes. Acceptance: a reproducible report with denominators and disagreement notes, without executing targets or claiming independent holdout status after tuning.
3. **Add one independently verified Linux isolation backend.** Acceptance: filesystem/network/process denial controls, bounded resources, cancellation cleanup and official-SDK fixture discovery in Linux CI; unsupported platforms must remain blocked until these probes pass.
