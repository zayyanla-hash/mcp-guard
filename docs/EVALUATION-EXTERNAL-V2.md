# External public-source evaluation v2 (1-level local factory support)

Generated 2026-11-23T10:05:58.660Z.

## v1 vs v2 comparison

| Metric | v1 (top-level only) | v2 (1-level local factory) |
|---|---:|---:|
| Recognized registrations (of 24) | 4 | 24 |
| Incomplete coverage files (of 7) | 7 | 5 |
| Findings | 0 | 0 |
| Parse failures | 0 | 0 |
| Coverage diagnostics | 27 | 77 |

Pre-registered expectations SHA-256: `703ee03a26bc8f4bc488947030777ddd50f3207e31b54d2a5cfdc6a12b08a17d` (committed before `src/analyzer.ts` changes at `40d7e3e03ccdb3affb23d92556f4121fadbd4319`).

| Rule | Supported positive | Supported negative | Unsupported | Unscored: coverage incomplete | Findings on scored handlers | False flags / negatives |
|---|---:|---:|---:|---:|---:|---:|
| MG001 | 0 | 5 | 17 | 2 | 0 | 0 / 5 |
| MG002 | 0 | 5 | 17 | 2 | 0 | 0 / 5 |
| MG003 | 0 | 5 | 17 | 2 | 0 | 0 / 5 |
| MG004 | 0 | 5 | 17 | 2 | 0 | 0 / 5 |
| MG006 | 0 | 5 | 17 | 2 | 0 | 0 / 5 |

## Per-file breakdown

| File | Handlers | Recognized | Complete coverage | Diagnostics |
|---|---:|---:|---|---:|
| `vendor/modelcontextprotocol-typescript-sdk/examples/tools/server.ts` | 2 | 2 | yes | 0 |
| `vendor/modelcontextprotocol-typescript-sdk/examples/guides/servers/tools.examples.ts` | 4 | 4 | no | 7 |
| `vendor/modelcontextprotocol-typescript-sdk/examples/stickynotes/server.ts` | 3 | 3 | no | 11 |
| `vendor/modelcontextprotocol-typescript-sdk/examples/repl/server.ts` | 6 | 6 | no | 17 |
| `vendor/modelcontextprotocol-typescript-sdk/examples/elicitation/server.ts` | 4 | 4 | no | 32 |
| `vendor/modelcontextprotocol-typescript-sdk/examples/gateway/server.ts` | 3 | 3 | yes | 0 |
| `vendor/modelcontextprotocol-typescript-sdk/examples/server-quickstart/src/index.ts` | 2 | 2 | no | 10 |

## Handler outcomes

| Handler | Source line | Registration shape | Findings |
|---|---:|---|---:|
| [`calc`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/tools/server.ts#L21) | 21 | local server factory (1-level) | 0 |
| [`echo`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/tools/server.ts#L45) | 45 | local server factory (1-level) | 0 |
| [`search`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/guides/servers/tools.examples.ts#L27) | 27 | top-level McpServer registration | 0 |
| [`product-details`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/guides/servers/tools.examples.ts#L45) | 45 | top-level McpServer registration | 0 |
| [`clear-catalog`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/guides/servers/tools.examples.ts#L65) | 65 | top-level McpServer registration | 0 |
| [`product-card`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/guides/servers/tools.examples.ts#L84) | 84 | top-level McpServer registration | 0 |
| [`add_note`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/stickynotes/server.ts#L51) | 51 | local server factory (1-level) | 0 |
| [`remove_note`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/stickynotes/server.ts#L67) | 67 | local server factory (1-level) | 0 |
| [`remove_all`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/stickynotes/server.ts#L81) | 81 | local server factory (1-level) | 0 |
| [`greet`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/repl/server.ts#L49) | 49 | local server factory (1-level) | 0 |
| [`multi-greet`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/repl/server.ts#L65) | 65 | local server factory (1-level) | 0 |
| [`collect-user-info`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/repl/server.ts#L84) | 84 | local server factory (1-level) | 0 |
| [`start-notification-stream`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/repl/server.ts#L146) | 146 | local server factory (1-level) | 0 |
| [`add-resource`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/repl/server.ts#L167) | 167 | local server factory (1-level) | 0 |
| [`list-files`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/repl/server.ts#L182) | 182 | local server factory (1-level) | 0 |
| [`register_user`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/elicitation/server.ts#L74) | 74 | local server factory (1-level) | 0 |
| [`plan_trip`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/elicitation/server.ts#L114) | 114 | local server factory (1-level) | 0 |
| [`link_account`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/elicitation/server.ts#L170) | 170 | local server factory (1-level) | 0 |
| [`confirm_payment`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/elicitation/server.ts#L223) | 223 | local server factory (1-level) | 0 |
| [`echo`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/gateway/server.ts#L22) | 22 | local server factory (1-level) | 0 |
| [`uppercase`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/gateway/server.ts#L26) | 26 | local server factory (1-level) | 0 |
| [`request_count`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/gateway/server.ts#L34) | 34 | local server factory (1-level) | 0 |
| [`get-alerts`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/server-quickstart/src/index.ts#L89) | 89 | local server factory (1-level) | 0 |
| [`get-forecast`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/server-quickstart/src/index.ts#L136) | 136 | local server factory (1-level) | 0 |
