#!/usr/bin/env node
process.stderr.write('mcp-guard is now vambrace. This alias will be removed in v0.4.0.\n');
await import('./cli.js');
