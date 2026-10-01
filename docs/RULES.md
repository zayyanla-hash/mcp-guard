# Rule contracts (version 1.0.0)

Every finding carries rule/version, severity, confidence, evidence type, source location or JSON pointer, redacted excerpt, observed pattern, rationale, assumptions, remediation, limitations, and a stable fingerprint. Fingerprints identify the recorded rule/location/pattern; moving a source line may change them. Inventory snapshots are separate artifacts.

## MG001 — shell input

Supported direct tool input reaching exec/execSync command text or a shell-enabled spawn/execFile call is reported. Fixed commands and fixed executables with structured arguments are negative controls. This is static evidence, not confirmed exploitation. Prefer a fixed executable with structured arguments and validate executable-specific behavior. Structured arguments do not resolve argument injection.

## MG002 — filesystem path input

Supported direct reads/writes/deletes/directory operations using tool-derived paths are reported. path.join/resolve alone do not establish containment; a helper named safePath is unresolved. The release recognizes no arbitrary containment helper. Corrected negative controls use fixed capabilities. The reviewed project-owned behavior fixture separately tests containment for traversal, absolute paths, root-prefix confusion and symlinks; it applies to existing paths and is not race-safe. Helpers remain manual review cases.

## MG003 — destination input

Supported input into fetch/http/https URL arguments is a capability observation. HTTPS or URL parsing is not an allowlist. Intentional general-purpose fetching is not automatically SSRF. Prefer fixed destination capabilities and enforce network policy. Redirects, DNS changes, encoded addresses and downstream transport behavior remain unresolved. Tests make no network requests.

## MG004 — environment exposure

Whole environment objects returned or logged, and explicit secret-bearing environment values reaching those sinks, are reported. Reading NODE_ENV, inspecting only environment names, or an unused secret-named variable does not alone constitute exposure. Use fake values. Redaction is not comprehensive secret detection.

## MG005 — inventory validity

Invalid descriptor types, names, duplicate names and supported schema structure produce findings. Valid permissive strings/open object schemas and missing optional annotations do not. Unsupported dialects/features/remote references yield incomplete diagnostics, not fabricated invalid-schema conclusions. Meta-validation does not validate runtime handler inputs or guarantee compatibility.

## MG006 — declaration contradiction

A literal readOnlyHint true and a mapped direct filesystem mutation produce evidence locations for both. Missing optional hints are not vulnerabilities. Annotations are declarations, not permissions. Imported or unresolved handler effects are not assessed. HTTP authentication and host human approval are outside this rule.
