# Threat model

The selected source repository and all JSON metadata are untrusted data. The auditor aims to keep target code, commands, instructions, and configuration from executing; preserve uncertainty; and avoid exposing recognizable secrets in reports.

Static scans use the TypeScript parser with an in-memory compiler host, no library loading and no module resolution. The scanner never imports target modules, runs scripts/tests, installs dependencies, or obeys source comments. Inventory validation uses a pinned meta-schema validator, without remote-reference resolution, target code, custom executable formats, model calls, or fetching metadata links.

Files are read under an explicitly selected root. Symlinks are skipped; source types, directories, files, total bytes, depth, entries, worker memory, and analysis time are bounded. A directory scan checks real paths and file identity, uses no-follow file opens, and records exclusions and failures. Selected JSON inputs must be regular non-symlink files and are bounded to 1 MiB. Artifact workers have a 5-second processing deadline and 256 MiB old-generation limit. Source analysis workers have a 2-second per-file deadline and the same memory limit.

**Precondition: use an immutable checkout without concurrent hostile filesystem changes.** No-follow leaf checks do not provide race-safe ancestor containment. This is not an OS sandbox. Source walking has cooperative deadlines; a blocking filesystem operation on a hung mount may outlive them. Worker memory limits are not whole-process memory quotas. Keep targets on responsive local filesystems.

Source findings and rendered output are redacted before CLI persistence. Redaction is intentionally narrow and does not recognize every credential. Avoid feeding real secrets; use fake canaries. Snapshots retain descriptor semantics and hashes, so detectable secret-bearing metadata is rejected rather than silently rewritten. Never publish private scan artifacts automatically.

Terminal controls are escaped; HTML is escaped and self-contained with no scripts, assets, or automatic links. Report inputs are validated and bounded. Outputs use exclusive creation and source output cannot be inside the target root. Parent-directory races still require a stable trusted output location.

No live target discovery is implemented. `discover` exits 3 and starts no process. Arbitrary target execution remains blocked; no unrestricted fallback is offered.
