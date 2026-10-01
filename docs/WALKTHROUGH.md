# MCP Guard walkthrough script

**Status:** narration and shot plan only. No screen recording has been produced. The [browser demonstration](https://zayyanla-hash.github.io/mcp-guard/) presents recorded seeded evidence.

## 60–90 second narration

> MCP Guard is an experimental offline CLI for a documented subset of MCP servers. It keeps two kinds of evidence separate: implementation patterns in JavaScript or TypeScript, and capabilities declared in a tool inventory.
>
> Here, the vulnerable fixture demonstrates several direct patterns. The analyzer parses syntax and import identity, then reports the source location and the assumptions behind each observation. Comments and strings do not become findings just because they contain alarming words. A finding is not proof of exploitation: severity, confidence, and coverage are recorded separately.
>
> Now I’ll compare the paired corrected fixture. It removes the supported observations in this example, which demonstrates the controls without claiming that all risks are gone. The inventory view checks descriptor structure and shows selected changes between declared snapshots. It cannot tell us whether the implementation changed.
>
> Finally, the release keeps uncertainty visible: unsupported or uninspected work makes coverage incomplete. Routine audits are offline and never execute their target. Discovery is a separate, explicitly approved path limited to a reviewed fixture under verified macOS restrictions. This is a scoped review aid, not a firewall or a security certification.

At a measured pace, this script should take about 70–85 seconds. Keep the terminal output legible; do not improvise a claim about production use, outside accuracy, or protection against all MCP risks.

## Shot list

| Time | Screen and action | Point to make |
|---|---|---|
| 0–10 sec | Open the project README at the status and demo sections. | Establish version and experimental scope. Mention the offline default. |
| 10–28 sec | Run the vulnerable fixture audit and show the JSON evidence fields or terminal finding. | Point to rule ID, source location, observed pattern, severity, confidence, assumptions, and remediation. |
| 28–40 sec | Run the corrected fixture audit. | Show the paired control and say “zero findings for these supported checks,” not “secure.” |
| 40–55 sec | Open the recorded inventory diff example or run the diff command. | Show that description/schema changes are observations about declared metadata. |
| 55–70 sec | Open the coverage section or `docs/LIMITATIONS.md`. | Show that incomplete work stays explicit and blocks a clean CI exit. |
| 70–85 sec | End on `docs/DISCOVERY.md` and the isolation boundary. | Explain that discovery is opt-in and restricted to a reviewed fixture; arbitrary targets are blocked. |

## Commands for the shot list

Run from the repository root after dependencies are installed. Use a fresh output directory for each demo run.

```sh
npm run build
npm run guard -- audit ./fixtures/vulnerable --format json
npm run guard -- audit ./fixtures/corrected --format json
npm run guard -- snapshot ./fixtures/inventories/valid.json --out ../walkthrough-before.json
npm run guard -- snapshot ./fixtures/inventories/drift.json --out ../walkthrough-after.json
npm run guard -- diff ../walkthrough-before.json ../walkthrough-after.json
npm run demo -- --out ../../work/mcp-guard-walkthrough-demo
```

The first two commands display results directly. Snapshot commands create new files outside the fixture tree. The demo writes generated JSON/HTML evidence to a new directory. The recorded example under `examples/seeded/` is also suitable when the live terminal is not prepared. Do not run discovery as part of this walkthrough: it is a separate opt-in operation.

## Optional résumé bullets

Use only bullets that fit the role and your own contribution; the project README discloses Codex/Luna assistance.

- Built an experimental TypeScript CLI that parses supported MCP server patterns, attaches source or JSON Pointer evidence, and reports incomplete analysis through explicit coverage and CI exit behavior.
- Added offline tool-inventory validation and deterministic snapshots that surface selected declared-capability changes without claiming to detect implementation drift.
- Added opt-in discovery limited to a reviewed fixture after verified macOS isolation checks; arbitrary target execution remains blocked.

Do not add adoption, customer, impact, or real-world accuracy metrics. The external coverage study reports 24 handlers, four recognized registrations in aggregate and 20 manually identified factory-bound registrations outside the supported shape. All files have incomplete coverage: use it to explain coverage gaps, not detection accuracy.
