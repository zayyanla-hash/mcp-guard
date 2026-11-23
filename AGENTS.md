# Standing rules for every session

1. Never execute an audit target. Parse source as data. Only the reviewed built-in fixture may ever run.
2. Never edit frozen files: evaluation/**/expectations.json, any *.sha256 file, benchmark labels. If one looks wrong, stop and ask.
3. Never weaken, skip or delete a test to pass a gate.
4. Tests make no network calls. An engine that needs the network sits behind an opt-in flag, off by default.
5. Exit codes are fixed: 0 complete, 1 findings or drift, 2 error, 3 incomplete. Incomplete outranks findings.
6. Every finding keeps rule version, evidence, confidence, assumptions, limitations, remediation, fingerprint and engine name.
7. No secrets anywhere. Tests use fake canaries.
8. Inside the package: MIT or Apache-2.0 code only. LGPL tools run as external binaries. Model weights are user downloads. Record each one in NOTICE.
9. Benchmark test-split labels are not in this repo. Never ask for them.
10. Before finishing: npm run validate, npm run evaluate, npm run validate:site, then the phase gate. Paste the output.
11. Stop and ask if a gate fails twice, a frozen file would change, a license is unclear, or the task grows past this phase.
