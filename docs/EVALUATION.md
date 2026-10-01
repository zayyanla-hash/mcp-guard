# Fixture evaluation

The table covers the explicitly enumerated 30 source cases in tests/source.test.mjs and the paired descriptor fixture test in tests/inventory.test.mjs. Additional parser, traversal, reporting, snapshot, CLI and review regressions are separate checks; they are not added to these rule denominators.

| Rule | Supported positives detected / expected | Misses in these positives | Supported negatives falsely flagged / tested | Unsupported enumerated cases |
|---|---:|---:|---:|---:|
| MG001 | 5 / 5 | 0 | 0 / 3 | 2 |
| MG002 | 3 / 3 | 0 | 0 / 1 | 1 |
| MG003 | 2 / 2 | 0 | 0 / 1 | 1 |
| MG004 | 4 / 4 | 0 | 0 / 3 | 0 |
| MG005 paired descriptors | 1 / 1 | 0 | 0 / 1 | 0 |
| MG006 | 1 / 1 | 0 | 0 / 3 | 0 |

Unsupported source cases include shadowed imports, unknown shell helpers, misleading safePath and outbound wrappers. Some still produce conservative findings, but all are incomplete and excluded from supported-positive/negative denominators. There are no parser failures in the 30 enumerated source controls; a separate malformed-source test asserts failure coverage.

The defining end-to-end source fixture yields five findings (MG001/2/3/4/6); its corrected peer yields zero findings for these checks. The paired inventory supplies MG005. The drift fixture changes description, required inputs, and tools under equivalent declared context. The demo preserves JSON, hashes and HTML derived from actual scans.

Independent skeptical review discovered missed aliased shell options, computed environment/API access, branch reassignment and generated-source exclusions. These became regression controls and conservative incomplete diagnostics; they are not an independent holdout after influencing implementation. Constant computed environment access is now detected. Static containment-helper recognition remains unsupported.

Tests never execute scanned repositories. The reviewed containment behavior fixture is project-owned code executed deliberately against disposable files; it verifies traversal, absolute paths, prefix confusion and symlink escapes without claiming race safety. Network tests parse calls or schemas without contacting any service. Fake secret canaries check redaction and snapshot rejection.

Run `npm run validate` for actual current counts. All checks must pass without skips. Passing seeded fixtures does not imply a real-world detection rate, zero false positives, or comparison with commercial tools.

## External reference coverage

The [external coverage study](EVALUATION-EXTERNAL.md) is separate from seeded controls. It preserves unchanged official SDK examples, immutable source checksums, and expectations frozen before the first analyzer run. Reproduce with `npm run evaluate`; incomplete and unsupported assessments remain unscored. This single-repository study is not an independent holdout or representative accuracy estimate.
