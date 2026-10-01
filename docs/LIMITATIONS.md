# Known limitations

This experimental release supports a narrow direct-registration subset, not all MCP servers. It does not detect all vulnerabilities or certify safety. No whole-program/interprocedural taint analysis, dependency scanning, automatic remediation, runtime policy enforcement, auth configuration verification, launch configuration execution, or LLM security verdict is implemented.

The first handler parameter is treated as input; response encoding and all possible output paths are not modeled. Branches, mutation, imported wrappers, dynamic registrations, computed API access and SDK generations may need manual review. Unrecognized syntax can be missed even when declared-scope checks finish. Findings state potential impact under assumptions and cannot prove actual permissions or exploitation.

No supported static containment or destination-policy helper is recognized. Fixed capabilities are the corrected fixture controls. Race-safe filesystem containment, DNS/redirect/address policy, arbitrary secret recognition, approval requirements and runtime permissions are not claimed.

Supported offline descriptor protocol labels are 2025-11-25 and 2026-07-28, with JSON Schema 2020-12. No protocol transport is implemented. No SDK is installed or used for live discovery; `discover` is explicitly blocked. Unsupported labels and features remain visible. SARIF is not implemented.

Inventories are declarations. Context equivalence is caller supplied; it is not independently verified. Snapshot hashes establish integrity of stored content, not trust in the server. A stable descriptor does not imply unchanged implementation. Schema diffs identify changes and required-field removal without generic widening claims.

Limits can reject legitimate very large/deep sources or reports. Source scans are limited to a responsive local immutable checkout. Resource bounds are best effort without an OS sandbox. Result JSON, inventories and snapshots accepted by CLI are limited to 1 MiB; use smaller scans when reports exceed this limit. Bounds errors are explicit non-success results.

Evaluation is seeded and development fixtures were visible during implementation. There is no independent real-world accuracy estimate or comparison with commercial scanners. Public release readiness means a reproducible experimental CLI with evidence boundaries, not blanket production-security readiness.
