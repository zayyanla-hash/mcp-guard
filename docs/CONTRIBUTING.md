# Contributing

Use Node 24+ and npm. Run `npm ci --ignore-scripts`, `npm run validate`, and `npm run demo -- --out NEW-directory`. Keep dependencies pinned and the lockfile committed. Never install or execute code from an audit target.

Extensions live in src/analyzer.ts (direct AST patterns), src/scanner.ts (walking/isolation), src/inventory.ts (data-only descriptors/diff), and src/reporting.ts (validated presentation). src/types.ts defines recorded contracts; src/policy.ts keeps coverage, severity and CI outcomes separate. Worker entrypoints enforce analysis deadlines.

For each rule change, define a true positive, corrected negative, benign similar API and unsupported example before tuning. Include aliases, source-like comments and strings, incomplete coverage, secret redaction and malformed-input cases. Keep severity and confidence separate. Don't change tests just to make a release green. Once challenge cases influence development, call them regressions, not an independent holdout.

Do not invent fixture findings. Reports must come from scan results. Do not add target-supplied executable plugins, implicit suppressions, network refs, or automatic baseline replacement. Keep offline default validation usable without secrets or models.

Pull requests should state supported syntax, known misses and exact validation commands. Public artifacts must omit private scans, credentials and unrelated runtime traces. Use security reporting guidance for sensitive discoveries.
