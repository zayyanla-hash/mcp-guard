# v0.2.1 release gate

Distribution: GitHub archive and checksum under zayyanla-hash/mcp-guard. Runtime transitive dependencies are locked by npm-shrinkwrap.json, which is included in the archive. The npm registry name belongs to another project.

Required gates: clean scoped diff, npm ci --ignore-scripts, offline test and validate commands, seeded demo, CLI help/version/invalid input, reviewed-fixture discovery under verified OS restrictions, denial probes, timeout/cancellation/PID cleanup, malicious-protocol fixtures, archive installation, independent public download checksum/install, and Linux/macOS Node24/26 CI. No skipped mandatory tests.

The v0.2.1 audit-context regression additionally requires that `audit --fixture-root fixtures` labels the declared fixture paths in JSON, terminal and HTML, while producing the same findings, coverage and exit as an unannotated scan. Invalid or escaping roots must fail.

No release claim implies universal vulnerability detection or security certification. Unrecognized syntax remains a documented analysis limit. Arbitrary discovery is blocked. SARIF is unavailable. Historical local harness trials remain distinct from cloud/Luna-assisted implementation.

Official references inspected 2026-10-01:
- https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- https://github.com/modelcontextprotocol/typescript-sdk
- https://ts.sdk.modelcontextprotocol.io/v2/migration/support-2026-07-28

Installed client and server packages: @modelcontextprotocol/client 2.2.0 and @modelcontextprotocol/server 2.2.0. Supported live protocol: 2026-07-28, explicitly negotiated modern era. Transport: official SDK serialization/read-buffer with a controlled stdio adapter; only tools/list pages are requested. SDK's no-cursor convenience aggregation is bypassed with an explicit initial empty cursor for this verified fixture so page bounds and cursor loops remain observable. Legacy/other protocol versions fail. No tool call, prompt fetch, resource read or remote metadata link is performed.
