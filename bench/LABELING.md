# Benchmark Labeling Guide

Blank labeling worksheets live under `bench/labels/todo/` (`typescript-dev.csv` and `python-dev.csv`). They are generated strictly from the `dev` split by `node bench/sheet.mjs --split dev`.

**Policy:** Human reviewers author all labels and rationales. Agents never create, edit, or infer benchmark labels or study expectations (`AGENTS.md` rule 12).

## Dev/Test Split Discipline

- `bench/manifest.json` (TypeScript) and `bench/python-manifest.json` (Python) partition servers strictly **by server** using fixed seed `20261123`.
- A server never appears in both `dev` and `test`.
- `test` split manifest entries record server metadata only. Test-split sheets and labels are never stored in this repository (`AGENTS.md` rule 9).

## Label Meanings

Each handler row includes `<RULE>_label` (`MG001`, `MG002`, `MG003`, `MG004`, `MG006`) and `<RULE>_rationale`:

- **`positive`**: Independent source reading confirms the handler exhibits the unsafe pattern defined by that rule contract in `docs/RULES.md`.
- **`negative`**: Independent source reading confirms the handler does **not** exhibit the rule's unsafe pattern (for example, fixed constants, `shell=False` structured arguments, safe read-only usage, or benign non-secret env access).
- **`unsupported`**: The handler cannot be assigned `positive` or `negative` honestly within the rule contract or lies outside supported registration/semantic boundaries (such as unmapped factories or cross-module dispatch). Rows marked `unsupported` are excluded from per-rule precision/recall denominators and reported in coverage/unsupported counts.

Do not copy `<RULE>_detected` blindly when filling `<RULE>_label`; inspect the linked source file and line independently.

## Rationale Requirement

Write **one rationale line per row** explaining the basis for the row's label assignment(s) (no embedded newlines inside CSV cells). Cite the key sink, guard, constant, annotation, or unresolved boundary on that handler line.

## Freezing, Hashing, and Committing Human Labels

1. Review `bench/labels/todo/typescript-dev.csv` and `bench/labels/todo/python-dev.csv` and save completed human-labeled sheets outside `todo/`, for example:
   - `bench/labels/typescript-dev.csv`
   - `bench/labels/python-dev.csv`
2. Verify every `<RULE>_label` is `positive`, `negative`, or `unsupported`, with one rationale line per row.
3. Generate and freeze the SHA-256 manifests:

```sh
shasum -a 256 bench/labels/typescript-dev.csv > bench/labels/typescript-dev.sha256
shasum -a 256 bench/labels/python-dev.csv > bench/labels/python-dev.sha256
```

4. Score and regenerate `BENCHMARK.md` locally:

```sh
node bench/score.mjs --labels bench/labels/typescript-dev.csv --sha256-file bench/labels/typescript-dev.sha256
node bench/score.mjs --labels bench/labels/python-dev.csv --sha256-file bench/labels/python-dev.sha256
npm run bench -- --split dev \
  --labels bench/labels/typescript-dev.csv \
  --sha256-file bench/labels/typescript-dev.sha256 \
  --py-labels bench/labels/python-dev.csv \
  --py-sha256-file bench/labels/python-dev.sha256
```

5. Commit the human-authored dev CSV files, `.sha256` files, and updated `BENCHMARK.md` in a human commit. Keep any `test`-split CSV and `.sha256` outside the repository.
