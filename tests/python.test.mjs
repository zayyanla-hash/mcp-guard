import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { analyzePythonSource } from '../dist/python-analyzer.js';
import { scanSource } from '../dist/scanner.js';
import { policyExit } from '../dist/policy.js';

const load = (rel) => readFileSync(new URL(`../fixtures/python/${rel}`, import.meta.url), 'utf8');

test('Python positive controls detect MG001, MG002, MG003, MG004, and MG006 with engine vambrace-py', async () => {
  const res = await analyzePythonSource('fixtures/python/positive/server.py', load('positive/server.py'));
  assert.equal(res.coverage.complete, true);
  assert.equal(res.coverage.recognizedTools, 5);
  assert.deepEqual(res.findings.map(f => f.ruleId), ['MG001', 'MG002', 'MG003', 'MG004', 'MG006']);
  assert.ok(res.findings.every(f => f.engine === 'vambrace-py'));
  assert.ok(res.findings.every(f => f.locations[0].line > 0));
  assert.equal(policyExit(res), 1);

  const scanned = await scanSource('fixtures/python/positive');
  assert.equal(scanned.coverage.complete, true);
  assert.equal(scanned.findings.length, 5);
  assert.equal(policyExit(scanned), 1);
});

test('Python negative controls (including add_tool and read open) produce zero findings and complete coverage', async () => {
  const res = await analyzePythonSource('fixtures/python/negative/server.py', load('negative/server.py'));
  assert.equal(res.coverage.complete, true);
  assert.equal(res.coverage.recognizedTools, 5);
  assert.deepEqual(res.findings, []);
  assert.equal(policyExit(res), 0);

  const readOpen = await analyzePythonSource(
    'read-open.py',
    'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("r")\n@mcp.tool(read_only=True)\ndef r():\n    return open("/fixed", "r").read()\n'
  );
  assert.equal(readOpen.coverage.complete, true);
  assert.deepEqual(readOpen.findings, []);
});

test('Python unresolved factories, dynamic sinks, and parse errors yield incomplete coverage (exit 3) with zero guessed findings', async () => {
  const unres = await analyzePythonSource('fixtures/python/unresolved/server.py', load('unresolved/server.py'));
  assert.equal(unres.coverage.complete, false);
  assert.deepEqual(unres.findings, []);
  assert.ok(unres.coverage.diagnostics.some(d => d.code === 'UNRESOLVED_FACTORY'));
  assert.equal(policyExit(unres), 3);

  const dynamicSink = await analyzePythonSource(
    'dyn.py',
    'from mcp.server.fastmcp import FastMCP\nimport os\nmcp = FastMCP("d")\n@mcp.tool()\ndef f(x: str) -> str:\n    return helper(x)\n'
  );
  assert.equal(dynamicSink.coverage.complete, false);
  assert.ok(dynamicSink.coverage.diagnostics.some(d => d.code === 'UNRESOLVED_CALL'));

  const badSyntax = await analyzePythonSource('bad.py', 'def broken(:\n  pass\n');
  assert.equal(badSyntax.coverage.complete, false);
  assert.ok(badSyntax.coverage.diagnostics.some(d => d.code === 'PARSE_ERROR'));
});

test('Python os.environ secret key and logging sink detection', async () => {
  const code = `import os\nimport logging\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP("s")\n@mcp.tool()\ndef t() -> str:\n    logging.warning(os.environ["API_KEY"])\n    return "done"\n`;
  const res = await analyzePythonSource('env.py', code);
  assert.equal(res.coverage.complete, true);
  assert.deepEqual(res.findings.map(f => f.ruleId), ['MG004']);
});
