# Vambrace Benchmark Report

Generated automatically by `npm run bench` (2026-11-23T10:25:08.575Z). Never hand-edited.

- **Split:** `dev` (3 servers, 5 source files, seed `20261123`)
- **Frozen labels SHA-256:** `75d161afcbca9fad44083b9b203a095204dd385c33e1cd9b3c7649f223dc4feb`
- **Handler coverage:** 87.5% (14/16 handlers, 95% Wilson CI [64.0%, 96.5%])
- **Silent misses (positive handler with no finding and no incomplete diagnostic):** **0**

## Per-rule accuracy (TypeScript analyzer)

| Rule | TP | FP | FN | TN | Unsupported | Silent misses | Precision (95% Wilson CI) | Recall (95% Wilson CI) | F1 |
|---|---:|---:|---:|---:|---:|---:|---|---|---:|
| MG001 | 1 | 0 | 0 | 13 | 2 | 0 | 100.0% [20.6%, 100.0%] | 100.0% [20.6%, 100.0%] | 1.0000 |
| MG002 | 1 | 0 | 0 | 13 | 2 | 0 | 100.0% [20.6%, 100.0%] | 100.0% [20.6%, 100.0%] | 1.0000 |
| MG003 | 1 | 0 | 0 | 13 | 2 | 0 | 100.0% [20.6%, 100.0%] | 100.0% [20.6%, 100.0%] | 1.0000 |
| MG004 | 1 | 0 | 0 | 13 | 2 | 0 | 100.0% [20.6%, 100.0%] | 100.0% [20.6%, 100.0%] | 1.0000 |
| MG006 | 1 | 0 | 0 | 13 | 2 | 0 | 100.0% [20.6%, 100.0%] | 100.0% [20.6%, 100.0%] | 1.0000 |

## Baselines

| Baseline | Status | Total hits | Details |
|---|---|---:|---|
| Naive grep (`bench/baselines/grep.mjs`) | ok | 12 | MG001:4, MG002:3, MG003:3, MG004:2 |
| Opengrep (`bench/baselines/opengrep/`) | skipped | 0 | opengrep binary not installed |

## Evasion resilience (TypeScript compiler API AST transforms)

Tested 20 transformed variants across MG001–MG004: **20 detected**, **0 flagged incomplete**, **0 silent misses**.

| Control | Transform | Outcome | Complete | Diagnostics |
|---|---|---|---|---|
| MG001-exec | aliased_import | detected | yes | none |
| MG001-exec | destructured_args | detected | yes | none |
| MG001-exec | one_level_wrapper | detected | no | NESTED_FUNCTION, UNRESOLVED_VALUE, UNRESOLVED_CALL |
| MG001-exec | computed_property_access | detected | no | UNRESOLVED_VALUE, UNRESOLVED_COMPUTED_VALUE |
| MG001-exec | template_literal_command | detected | yes | none |
| MG002-readFile | aliased_import | detected | yes | none |
| MG002-readFile | destructured_args | detected | yes | none |
| MG002-readFile | one_level_wrapper | detected | no | NESTED_FUNCTION, UNRESOLVED_VALUE, UNRESOLVED_CALL |
| MG002-readFile | computed_property_access | detected | no | UNRESOLVED_VALUE, UNRESOLVED_COMPUTED_VALUE |
| MG002-readFile | template_literal_command | detected | yes | none |
| MG003-fetch | aliased_import | detected | yes | none |
| MG003-fetch | destructured_args | detected | yes | none |
| MG003-fetch | one_level_wrapper | detected | no | NESTED_FUNCTION, UNRESOLVED_VALUE, UNRESOLVED_CALL |
| MG003-fetch | computed_property_access | detected | no | UNRESOLVED_VALUE, UNRESOLVED_COMPUTED_VALUE |
| MG003-fetch | template_literal_command | detected | yes | none |
| MG004-env | aliased_import | detected | yes | none |
| MG004-env | destructured_args | detected | yes | none |
| MG004-env | one_level_wrapper | detected | no | NESTED_FUNCTION |
| MG004-env | computed_property_access | detected | yes | none |
| MG004-env | template_literal_command | detected | yes | none |

## Performance

- **Samples:** 15 (5 files)
- **Per-file latency:** p50 = 1.008 ms, p95 = 3.603 ms
- **Process RSS:** p50 = 163.75 MiB, p95 = 169.063 MiB

## Python slice (separate v1.1 evaluation)

- **Frozen Python labels SHA-256:** `3da659eb977968849c33d38ee2ae743166e85e44ed615b48475186b9f2748906`
- **Handler coverage:** 83.3% (10/12 handlers, 95% Wilson CI [55.2%, 95.3%])
- **Silent misses:** **0**

| Rule | TP | FP | FN | TN | Unsupported | Silent misses | Precision (95% Wilson CI) | Recall (95% Wilson CI) | F1 |
|---|---:|---:|---:|---:|---:|---:|---|---|---:|
| MG001 | 1 | 0 | 0 | 9 | 2 | 0 | 100.0% [20.6%, 100.0%] | 100.0% [20.6%, 100.0%] | 1.0000 |
| MG002 | 1 | 0 | 0 | 9 | 2 | 0 | 100.0% [20.6%, 100.0%] | 100.0% [20.6%, 100.0%] | 1.0000 |
| MG003 | 1 | 0 | 0 | 9 | 2 | 0 | 100.0% [20.6%, 100.0%] | 100.0% [20.6%, 100.0%] | 1.0000 |
| MG004 | 1 | 0 | 0 | 9 | 2 | 0 | 100.0% [20.6%, 100.0%] | 100.0% [20.6%, 100.0%] | 1.0000 |
| MG006 | 1 | 0 | 0 | 9 | 2 | 0 | 100.0% [20.6%, 100.0%] | 100.0% [20.6%, 100.0%] | 1.0000 |
