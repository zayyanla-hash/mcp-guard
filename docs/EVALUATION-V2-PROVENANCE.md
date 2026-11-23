# Evaluation v2 Provenance

**Authorship disclosure:** An AI coding agent wrote `evaluation/v2/expectations.json`, not a human. Although the file was committed before the Phase 1 changes to `src/analyzer.ts`, the expectations are **pending independent human review** and must not be treated as human-verified ground truth.

Under `AGENTS.md` rule 12, agents never create, edit, or infer benchmark labels or study expectations. `evaluation/v2/expectations.json` has been left untouched while awaiting human review.

## Verified Git History

The commit ordering below can be reproduced directly from `git log`:

| Artifact | Commit Hash | Date (Author) | Commit Subject |
|---|---|---|---|
| `evaluation/v2/expectations.json` (initial freeze) | `d5e9688e0b2f8a4ebe2a60670a71e7bb1550de93` | `2026-11-23T02:01:58-08:00` | `Phase 1 Session 2a: freeze v2 expectations before analyzer changes` |
| `src/analyzer.ts` (first v2 / 1-level factory change) | `0ef40d7bb5c06c068c508d1e30c8204baefe8f0c` | `2026-11-23T02:06:18-08:00` | `Phase 1: add 1-level local factory support and v2 external evaluation` |

### Prior `src/analyzer.ts` Baseline History

Before the Phase 1 v2 change (`0ef40d7bb5c06c068c508d1e30c8204baefe8f0c`), `src/analyzer.ts` had the following earlier commits from v0.1.0–v0.2.0:

| Commit Hash | Date (Author) | Commit Subject |
|---|---|---|
| `f66a3762ab1fea93cc3e1fb8a2ee0df545ccc2ba` | `2026-09-30T22:56:14-07:00` | `Build experimental offline MCP audit and capability drift CLI` |
| `6928ee10c28aa81c6952b1ab14cd588cd3fdb645` | `2026-09-30T22:58:16-07:00` | `Treat unresolved writes and open flags conservatively; record final validation` |
| `ff3ce869fd5ee625db1cc2846643db96d18cc880` | `2026-10-01T00:47:15-07:00` | `Harden v0.2 auditing and add verified isolated fixture discovery` |

## Integrity & Review Verification Commands

```sh
git log --format="%H %aI %s" -- evaluation/v2/expectations.json evaluation/v2/expectations.sha256
git log --format="%H %aI %s" -- src/analyzer.ts
shasum -a 256 evaluation/v2/expectations.json
# Expected SHA-256 recorded at d5e9688e0b2f8a4ebe2a60670a71e7bb1550de93:
# 703ee03a26bc8f4bc488947030777ddd50f3207e31b54d2a5cfdc6a12b08a17d  evaluation/v2/expectations.json
```

Human reviewers auditing `evaluation/v2/expectations.json` should inspect each entry against `vendor/modelcontextprotocol-typescript-sdk/examples/` independently, record their sign-off, and update any revised expectations together with a new frozen `.sha256`.
