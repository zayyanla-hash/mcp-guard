# External public-source evaluation

Generated 2026-10-01T08:51:54.619Z.

The offline runner reviewed 24 actual tool registrations from 7 source files in one official repository at commit `433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0`. The analyzer reported 4 recognized registrations in aggregate across files; the remaining 20 are a count difference, not individually identified handlers. File-level recognized counts matched the frozen manual expectations in 7 of 7 files. The analyzer emitted 27 coverage diagnostics across 7 files; there were 0 findings and 0 parse failures.

Expectations were frozen before the first analyzer run (SHA-256 `6d3acbbff59eaab40e85a6ce356605eed562d5a2830aef2300b64eb0e877fce3`). This is a single-repository reference-example coverage corpus, not an independent holdout or a representative accuracy estimate.

No supported positive controls were present, so recall and miss rate are not measurable. The corpus contains no confirmed vulnerabilities; any static finding is a pattern observation, not proof of exploitability.

| Rule | Supported positive | Supported negative | Unsupported | Unscored: coverage incomplete | Unscored: mixed rule labels | Findings on scored handlers | Misses / positives | False flags / negatives |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| MG001 | 0 | 0 | 23 | 1 | 1 | 0 | n/a (0/0) | n/a (0/0) |
| MG002 | 0 | 0 | 23 | 1 | 1 | 0 | n/a (0/0) | n/a (0/0) |
| MG003 | 0 | 0 | 23 | 1 | 1 | 0 | n/a (0/0) | n/a (0/0) |
| MG004 | 0 | 0 | 23 | 1 | 1 | 0 | n/a (0/0) | n/a (0/0) |
| MG006 | 0 | 0 | 23 | 1 | 1 | 0 | n/a (0/0) | n/a (0/0) |

The two unscored columns describe overlapping reasons and must not be added together.

## Handler outcomes

| Handler | Source line | Manual registration shape | Findings mapped by tool name |
|---|---:|---|---:|
| [`calc`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/tools/server.ts#L21) | 21 | registration in local server factory (manual expectation) | 0 |
| [`echo`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/tools/server.ts#L45) | 45 | registration in local server factory (manual expectation) | 0 |
| [`search`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/guides/servers/tools.examples.ts#L27) | 27 | top-level McpServer registration (manual expectation) | 0 |
| [`product-details`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/guides/servers/tools.examples.ts#L45) | 45 | top-level McpServer registration (manual expectation) | 0 |
| [`clear-catalog`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/guides/servers/tools.examples.ts#L65) | 65 | top-level McpServer registration (manual expectation) | 0 |
| [`product-card`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/guides/servers/tools.examples.ts#L84) | 84 | top-level McpServer registration (manual expectation) | 0 |
| [`add_note`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/stickynotes/server.ts#L51) | 51 | registration in local server factory (manual expectation) | 0 |
| [`remove_note`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/stickynotes/server.ts#L67) | 67 | registration in local server factory (manual expectation) | 0 |
| [`remove_all`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/stickynotes/server.ts#L81) | 81 | registration in local server factory (manual expectation) | 0 |
| [`greet`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/repl/server.ts#L49) | 49 | registration in local server factory (manual expectation) | 0 |
| [`multi-greet`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/repl/server.ts#L65) | 65 | registration in local server factory (manual expectation) | 0 |
| [`collect-user-info`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/repl/server.ts#L84) | 84 | registration in local server factory (manual expectation) | 0 |
| [`start-notification-stream`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/repl/server.ts#L146) | 146 | registration in local server factory (manual expectation) | 0 |
| [`add-resource`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/repl/server.ts#L167) | 167 | registration in local server factory (manual expectation) | 0 |
| [`list-files`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/repl/server.ts#L182) | 182 | registration in local server factory (manual expectation) | 0 |
| [`register_user`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/elicitation/server.ts#L74) | 74 | registration in local server factory (manual expectation) | 0 |
| [`plan_trip`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/elicitation/server.ts#L114) | 114 | registration in local server factory (manual expectation) | 0 |
| [`link_account`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/elicitation/server.ts#L170) | 170 | registration in local server factory (manual expectation) | 0 |
| [`confirm_payment`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/elicitation/server.ts#L223) | 223 | registration in local server factory (manual expectation) | 0 |
| [`echo`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/gateway/server.ts#L22) | 22 | registration in local server factory (manual expectation) | 0 |
| [`uppercase`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/gateway/server.ts#L26) | 26 | registration in local server factory (manual expectation) | 0 |
| [`request_count`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/gateway/server.ts#L34) | 34 | registration in local server factory (manual expectation) | 0 |
| [`get-alerts`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/server-quickstart/src/index.ts#L89) | 89 | registration in local server factory (manual expectation) | 0 |
| [`get-forecast`](https://github.com/modelcontextprotocol/typescript-sdk/blob/433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0/examples/server-quickstart/src/index.ts#L136) | 136 | registration in local server factory (manual expectation) | 0 |

## Provenance and limits

Reproduce from the repository root with `npm run evaluate`. The default run writes its timestamped report under ignored `evaluation/artifacts/external-evaluation/` and checks summary counts against the recorded `evaluation/report.json`; it does not modify committed evidence. Run `npm run evaluate -- --record` only when intentionally updating the recorded JSON and this document after reviewing a changed result. The vendored files are unmodified, checksum-verified copies of the cited upstream files. The upstream LICENSE is included in full because that repository documents an MIT-to-Apache-2.0 transition and retains older MIT grants where relicensing consent was not obtained. Each handler row links to its exact upstream line; findings retain analyzer output in the generated report JSON.

The analyzer implementation is pinned by the pre-run commit and source/distribution checksums recorded above. The runner validates those checksums, vendored source checksums, and the frozen expectation hash before analysis. The analyzer exposes a recognized-registration count per file, not registration identities. The table lists manual source-registration shapes only; those labels are not independent analyzer classifications. Aggregate registration counts matched the manually frozen counts by file. All files had incomplete coverage, and the direct-registration file mixes rule-level expectations, so its one manual negative control is unscored. Per-rule unsupported counts follow manual expectations, not handler-by-handler analyzer identity. MG005 is not assessed because this source-only corpus contains no descriptor inventories.

Targets are analyzed as text data. No target code is imported or executed; no dependencies are installed; no tests, network requests, credentials, third-party configuration, or external services are scanned.
