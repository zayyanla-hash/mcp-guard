# v0.2.1 audit-context checkpoint

Objective: preserve all deliberately vulnerable and ambiguous fixtures while making whole-repository reports clearly identify fixture locations declared by the operator. This fixes a misleading presentation gap found when MCP Guard audited its own repository. The declaration is unverified and never suppresses findings or changes coverage and exit codes.

Base: public v0.2.0 commit ff3ce869fd5ee625db1cc2846643db96d18cc880. Current branch: audit-context-v0.2.1. Files changed: `src/cli.ts`, `src/reporting.ts`, `src/types.ts`, `src/version.ts`, `tests/cli.test.mjs`, `tests/reporting.test.mjs`, `README.md`, `CHANGELOG.md`, `docs/RELEASE.md`, `docs/CHECKPOINT.md`, `package.json`, and `npm-shrinkwrap.json`. No fixture source or unrelated repository was modified.

Observed locally on macOS/Node 26.9.0: `npm run validate` exit 0, 123/123 offline tests; `npm run test:discovery` exit 0, 12/12 tests; `npm run demo -- --out ../../work/audit-context-demo` exit 0 with expected vulnerable 1/corrected 0/inventory 1/drift 1 outcomes. A direct `audit <repo> --fixture-root fixtures --format json` returned exit 3, six findings, incomplete coverage, and `declaredFixtureRoots: ["fixtures"]`; the generated HTML shows all six as operator-declared fixture paths. The same six findings and incomplete coverage remained after annotation. `git diff --check` exit 0.

Remaining release gates at this checkpoint: package install and smoke, commit, CI on supported Linux/macOS Node versions, public v0.2.1 archive/checksum release, and public-install verification. The released v0.2.0 checkpoint and tag remain preserved. No general claim of production safety or arbitrary-target discovery is made.

Next action: finish package and hosted validation, then publish only to `zayyanla-hash`; capture final commit, CI and public checksum in a separate release checkpoint asset.
