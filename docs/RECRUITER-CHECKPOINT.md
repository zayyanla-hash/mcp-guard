# Recruiter evidence checkpoint — 2026-10-01

## Objective and state

Add an inspectable browser demonstration, a reproducible external source coverage study, an engineering case study, a walkthrough script, and an outside-review package. Preserve v0.2.1 scanner behavior and seeded fixtures. Work occurs on `recruiter-evidence` from baseline `ae5115ea07cdfb77436aba59f2f198ba1d448595`; the containing Git commit records the final changed-file identity.

## Changed files

`site/` (static page, styling, behavior, recorded data and validator); `evaluation/` (seven unchanged official SDK source files, upstream LICENSE, source checksums, frozen expectations, runner and report); `.github/workflows/pages.yml`; `.github/workflows/ci.yml`; `.gitignore`; `package.json`; `README.md`; `docs/ARCHITECTURE.md`; `docs/PORTFOLIO.md`; `docs/EVALUATION.md`; `docs/EVALUATION-EXTERNAL.md`; `docs/WALKTHROUGH.md`; `docs/REVIEW-PACKAGE.md`; this checkpoint. No scanner, fixture or dependency versions changed.

## Commands and observed results

- `npm run validate:all`: exit 0; 123 offline tests and 12 macOS discovery/isolation tests passed, none failed or skipped.
- `npm run demo -- --out artifacts/recruiter-demo`: initially exit 2 because the new output parent did not exist. After `mkdir -p artifacts`, exit 0 and demo PASS. Child policy outcomes: vulnerable 1, corrected 0, invalid inventory 1, corrected inventory 0, drift 1.
- `npm run validate:site`: exit 0; preserved seeded finding fields, coverage, drift data and snapshot hashes match; JavaScript syntax checks pass.
- `node dist/cli.js --help`: exit 0.
- `node dist/cli.js --version`: exit 0, `0.2.1`.
- `node dist/cli.js invalid-command`: exit 2, unknown command diagnostic.
- `npm run evaluate`: exit 0; frozen checksums and recorded summary reproduced; outputs under ignored `evaluation/artifacts/external-evaluation/`. The target source was not executed.
- `git diff --check`: exit 0.
- Browser checks: source and corrected tabs, descriptor and drift evidence, keyboard ArrowDown/End navigation, install/demo clipboard text, mobile layout. No browser console errors observed.

## External study boundary

24 actual registrations from seven unchanged official TypeScript SDK files at `433eb413dc305ebeb93b8ebcde0095a8fc0d5fa0`. Frozen expectation hash: `6d3acbbff59eaab40e85a6ce356605eed562d5a2830aef2300b64eb0e877fce3`. Analyzer aggregate: four recognized registrations. Manual review: 20 factory-bound registrations outside the supported shape; all seven files have incomplete coverage, 27 diagnostics, no findings or parse failures. No scored accuracy controls. See the generated study for reproduction and per-rule denominators.

## Publication gates and handoff

At this checkpoint, local checks above are complete. Final root reproduction of the external runner, GitHub CI and Pages deployment are pending; final publication evidence is recorded in the session handoff outside this source tree. Publish only to `zayyanla-hash/mcp-guard`. Existing v0.2.1 release and tags remain unchanged.

Next: reproduce `npm run evaluate`, finish independent evidence review, publish the branch and fast-forward main after four CI jobs pass, then verify the deployed browser demonstration. No video has been recorded and no external reviewer has been contacted. Future engineering work should address factory-bound registrations with explicit unsupported controls rather than tune this corpus into an accuracy claim.
