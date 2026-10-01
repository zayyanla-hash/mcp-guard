# Read-only fixture discovery

MCP Guard can collect a tool descriptor from its reviewed, project-owned stdio fixture. Discovery is disabled unless the CLI receives both `--approve-execution` and `--fixture reviewed`. It accepts no server config, command, argument list, URL, or executable path. The CLI never exposes the adversarial test fixtures.

Discovery uses the official MCP TypeScript client v2 SDK and pins the protocol to `2026-07-28`. It launches only the built-in fixture through the project isolation launcher, inventories `tools/list` pages, and never calls a tool, reads a resource, or requests a prompt. The protocol revision is explicitly negotiated because v2 clients otherwise default to the 2025-era exchange. See the [SDK guide for protocol revision 2026-07-28](https://ts.sdk.modelcontextprotocol.io/v2/migration/support-2026-07-28).

The transport rejects every server-initiated JSON-RPC request before the client can handle it. This is a fail-closed guard for sampling, elicitation, and other unrequested server requests. The client also disables automatic input fulfilment.

Discovery has fixed bounds: 15 seconds total, 4 seconds per MCP request, 1 MiB combined child stdio, 256 KiB per MCP frame, 500 tools, and 32 `tools/list` pages. Repeated pagination cursors fail explicitly. A protocol mismatch, malformed page, size limit, timeout, cancellation, or unexpected child exit is a non-success result; it does not fall back to a different protocol or launch source.

The test-only fixtures cover a silent server, repeated pagination cursor, unsolicited sampling request, legacy protocol mismatch, and oversized descriptor. They are reachable by fixed names from tests only. Production discovery always selects `reviewed.mjs`.

Discovery output records the pinned protocol, stdio transport, absence of authorization, project fixture provenance, server identity when reported by the SDK, page count, and tool descriptors. A live descriptor is still a declaration; it does not establish server implementation behavior or runtime permissions.

## OS enforcement and platform boundary

macOS Seatbelt must pass a runtime probe before a fixture starts. The probe tests project-owned outside canary read/write denial, socket-creation denial, process-spawn denial, and absent fake-secret environment inheritance. The fixture can read project/runtime code and permitted system runtime paths, but cannot write project files, access outside regular-file data, use sockets, or spawn children. Only the closed fixture basename allowlist is executable. It runs unprivileged with a 128 MiB V8 heap ceiling, bounded stdio and a hard process timer. Timeout/cancellation tests verify the launched PID is gone. Platform policy allows metadata reads and system IPC; this is a reviewed-fixture backend, not permission to run arbitrary hostile repositories. No temporary-directory-only sandbox or unrestricted fallback is used.

Linux and other platforms explicitly return a blocked discovery result; CI checks that behavior rather than skipping it. Offline commands remain portable to the tested Linux/macOS Node versions. `--inventory-out` preserves a validated, snapshot-ready acquired inventory as a new file; `--out` records the audit result. Neither overwrites baselines.

The verified backend restricts regular-file data, writes, sockets and child creation. Directory enumeration, file metadata and system IPC are not confined by this profile. Attempts to deny all outside-directory data prevented Node startup on the tested host. This is why discovery accepts only reviewed built-in fixtures and never arbitrary repository/server code.
