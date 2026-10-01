# Supported pattern matrix

| Area | Supported | Outside scope / incomplete |
|---|---|---|
| Language | ESM `.js`, `.mjs`, `.ts`, `.mts` parsed by TypeScript | CommonJS, JSX/TSX, other languages |
| Registration | const server created from imported SDK v1 or v2 `McpServer`; direct `server.registerTool` with literal name/config | legacy `.tool`, computed/dynamic registrations, wrappers, unknown receivers |
| Handler mapping | Inline function/arrow or same-file named function/const arrow | Imported helpers/handlers, nested callbacks, interprocedural flows |
| Imports | Named aliases, namespace/default builtin imports with lexical symbol identity | Runtime loaders, reassigned aliases, computed API lookup |
| Dataflow | First handler parameter, destructuring, stable local aliases, templates, object/array literals, direct transformations | Mutable/conditional flow, arbitrary helpers, closures, mutation, unresolved mappings |
| Shell | child_process exec/execSync; spawn/execFile variants with literal shell enabled | Argument injection, executable behavior, generic process safety |
| Paths | Direct recognized fs/fs-promises operations, path join/resolve/normalize flows | Containment helper recognition, runtime permissions, races |
| Network | Global fetch and imported http/https get/request direct input destination | DNS, redirect, private-address policy, all HTTP libraries |
| Exposure | Entire process.env or explicit secret-key environment values returned/logged | Arbitrary secrets, comprehensive logger coverage, file-derived credentials |
| Annotation contradiction | Literal readOnlyHint true plus supported direct fs mutation | Annotation enforcement, missing approvals, imported effects |
| Inventory | Descriptor types, duplicates, object input/output schemas, JSON Schema 2020-12 meta-validation | Remote refs, unknown custom features/dialects, runtime permission verification |

Recognized unresolved paths yield diagnostics and exit 3. The analyzer is not a proof system; a syntactically unrecognized registration or unforeseen unsupported construct can evade mapping. Read coverage and limitations alongside findings.

Exclusions: node_modules, VCS directories, dist/build/coverage/.next/vendor/__pycache__, declaration files and `.min.js` generated files. Non-source files are listed as excluded. Skipped minified files and generated/vendor directories additionally mark coverage incomplete; select the source root explicitly when compiled artifacts are outside the intended assessment. Supported scope is source selected by this policy, not dependencies or compiled artifacts.

Defaults: 2,000 supported files; 4,000 directory entries; 20 MiB source; 1 MiB/file; depth 20; 30 seconds CLI parent-watchdog budget (internal walker cooperative); 2 seconds/file worker. Limits reached mean incomplete. An empty source set or no recognized tools is incomplete.
