# Release gate and scope

v0.1.0 is distributed as a GitHub archive in zayyanla-hash/mcp-guard. It is not an npm registry publication.

Release acceptance requires a pinned install, build, full offline test suite, demo, help/version/invalid-command checks, archive installation, and CI. All tests must run, with no skipped mandatory tests. A release checkpoint records actual results and commit identity. Production claims remain limited to supported offline operation with documented preconditions.

Optional discovery and SARIF remain unavailable. No arbitrary server is started. Publishing this experimental release does not establish independent security assurance or general production readiness.

Official references inspected 2026-09-30:
- https://modelcontextprotocol.io/specification/latest/server/tools (latest resolved to 2026-07-28)
- https://modelcontextprotocol.io/specification/latest/basic/authorization
- https://modelcontextprotocol.io/specification/latest/basic/security_best_practices
- https://github.com/modelcontextprotocol/typescript-sdk

No installed MCP SDK or supported live transport is claimed. Source recognition covers the direct McpServer registerTool pattern, without executing or verifying SDK lifecycle. Future discovery must verify official SDK imports, transport, lifecycle and pagination first, and must enforce execution isolation rather than infer permission from metadata.
