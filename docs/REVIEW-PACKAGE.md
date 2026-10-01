# MCP Guard external review package

This package is ready to share with a technically curious reviewer. No reviewer has been contacted and no external feedback is represented here.

## What to review

MCP Guard v0.2.1 is an experimental offline CLI for a documented JavaScript/TypeScript source subset and supplied MCP tool inventories. The useful review question is whether the evidence and boundaries are honest and understandable, not whether the project proves an MCP server is safe.

Start with:

1. [README.md](../README.md) for installation, commands, release status, and scope.
2. [PORTFOLIO.md](PORTFOLIO.md) for the concise engineering case study.
3. [RULES.md](RULES.md) and [LIMITATIONS.md](LIMITATIONS.md) for observations and known misses.
4. [EVALUATION.md](EVALUATION.md) for the seeded cases and denominators.
5. [DISCOVERY.md](DISCOVERY.md) for the separate, reviewed-fixture execution boundary.

The review target is the public [v0.2.1 source commit](https://github.com/zayyanla-hash/mcp-guard/commit/ae5115ea07cdfb77436aba59f2f198ba1d448595). The [published release](https://github.com/zayyanla-hash/mcp-guard/releases/tag/v0.2.1) includes its archive and checksum. The [browser demonstration](https://zayyanla-hash.github.io/mcp-guard/) shows recorded seeded evidence. The [external coverage study](EVALUATION-EXTERNAL.md) contains 24 actual handlers from seven unchanged official SDK files, with frozen expectations and pinned checksums. All seven files have incomplete coverage; zero findings does not establish safety or detection accuracy.

## Optional local check

Review can remain read-only. If you choose to run the repository locally, use Node 24 or newer and follow the documented offline path:

```sh
npm ci --ignore-scripts
npm run validate
npm run demo -- --out NEW-demo-directory
```

The audit scans supplied source as data and does not execute it. Do not run discovery to assess arbitrary repositories: the command is restricted to a reviewed project-owned fixture, and platforms without a verified isolation backend block it. The test/demo outcomes are seeded controls, not a real-world accuracy estimate.

## Feedback questions

- Are the distinction among severity, confidence, evidence, and coverage clear from the finding and report?
- Do the rules describe useful, supportable observations, or does any wording imply more than the implementation establishes?
- Is there a plausible supported direct pattern that should be tested as a positive or corrected negative?
- Is the boundary between descriptor declarations and server implementation behavior clear?
- Does the v0.2.1 fixture-path label read as provenance only, with findings and policy outcomes retained?
- What is the single most important limitation or missing review aid for a first-time user?

Please identify the rule, example, or document section behind each comment. Distinguish a reproducible defect from a scope request or wording suggestion. Do not send secrets or private target code; use the repository's security reporting guidance for a sensitive vulnerability.

## How feedback will be summarized

No feedback has been received for this package. When a review is actually completed, record the reviewer's permission to attribute them, the date and scope, concrete findings separately from suggestions, reproducible evidence, and whether each item was accepted, deferred, or declined. Do not describe a small external review as independent validation of overall detection accuracy.
