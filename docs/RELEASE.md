# Release verification and gates

Distribution: GitHub release archive, Syft SPDX SBOM, Sigstore keyless bundles, GitHub artifact attestations, and npm package `vambrace` with provenance (`npm publish --provenance`). Runtime transitive dependencies are locked by `npm-shrinkwrap.json`, which is included in the archive.

## Verify a release

```sh
# 1. Verify archive SHA-256
sha256sum -c SHA256SUMS

# 2. Verify Sigstore keyless signature on tarball and SBOM
cosign verify-blob \
  --bundle vambrace-<version>.tgz.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "^https://github\.com/zayyanla-hash/vambrace/" \
  vambrace-<version>.tgz

cosign verify-blob \
  --bundle vambrace.sbom.spdx.json.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "^https://github\.com/zayyanla-hash/vambrace/" \
  vambrace.sbom.spdx.json

# 3. Verify GitHub artifact build provenance attestation
gh attestation verify vambrace-<version>.tgz --repo zayyanla-hash/vambrace

# 4. Verify npm provenance signatures after install
npm audit signatures
```

Required gates: clean scoped diff, `npm ci --ignore-scripts`, `npm run validate`, `npm run evaluate`, `npm run validate:site`, SARIF 2.1.0 schema compliance, and cross-OS Node 24/26 CI. No release claim implies universal vulnerability detection or security certification.

Official references inspected 2026-10-01:
- https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- https://github.com/modelcontextprotocol/typescript-sdk
- https://ts.sdk.modelcontextprotocol.io/v2/migration/support-2026-07-28

Installed client and server packages: @modelcontextprotocol/client 2.2.0 and @modelcontextprotocol/server 2.2.0. Supported live protocol: 2026-07-28, explicitly negotiated modern era. Transport: official SDK serialization/read-buffer with a controlled stdio adapter; only tools/list pages are requested. SDK's no-cursor convenience aggregation is bypassed with an explicit initial empty cursor for this verified fixture so page bounds and cursor loops remain observable. Legacy/other protocol versions fail. No tool call, prompt fetch, resource read or remote metadata link is performed.
