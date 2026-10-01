# MCP Guard recruiter walkthrough

This is a plain static HTML/CSS/JavaScript presentation. It has no build step, frontend framework, remote scripts, analytics, or font dependencies.

## Preview locally

From the repository root, run any ordinary static file server, for example:

```sh
python3 -m http.server 8000 --directory site
```

Then open `http://localhost:8000`. The page also works when served from GitHub Pages under a project subpath because its assets use relative paths.

## Fixture provenance and boundaries

`data.js` is a curated static copy derived from `examples/seeded/*.json`. Finding evidence, assumptions, limitations, locations, remediation notes, fingerprints, descriptor changes and snapshot hashes are retained for the outcomes shown. The interface explicitly labels these as seeded fixtures and describes the supported-scope and discovery limitations.

The separate evaluation summary is taken from `docs/EVALUATION-EXTERNAL.md`. It covers 24 manually reviewed tool registrations in seven unchanged files from one pinned official TypeScript SDK repository. The analyzer reported four recognized registrations in aggregate across files, without mapping handler identities. Manual source review identified 20 factory-bound registrations outside the supported shape. All seven files had incomplete coverage. The static page links to the full report for provenance and limits; these results do not establish detection accuracy.
