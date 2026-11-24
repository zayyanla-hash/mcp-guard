import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fetchManifest, loadManifest, validateSplitByServer } from '../bench/fetch.mjs';
import { wilsonInterval, scoreRows, scoreFromFiles, verifyLabelsSha256 } from '../bench/score.mjs';
import { grepScanSource } from '../bench/baselines/grep.mjs';
import { runOpengrepBaseline } from '../bench/baselines/opengrep/run.mjs';
import { runEvasionSuite } from '../bench/evasion/run.mjs';
import { generateLabelingSheet, generatePythonLabelingSheet, extractTsToolNames, extractPythonToolNames, UNENUMERATED_TOOL } from '../bench/sheet.mjs';
import { measurePerf } from '../bench/perf.mjs';
import { runBenchmark, serverCoverageMarkdown } from '../bench/run.mjs';

test('wilsonInterval computes bounded 95% confidence intervals', () => {
  const full = wilsonInterval(10, 10);
  assert.ok(full.low > 0.7 && full.low < 0.75);
  assert.equal(full.high, 1);
  const empty = wilsonInterval(0, 0);
  assert.deepEqual(empty, { low: null, high: null });
});

test('scoreRows computes TP, FP, FN, TN, silent misses, coverage, and F1', () => {
  const rows = [
    { analyzer_complete: 'true', analyzer_diagnostics: '', MG001_label: 'positive', MG001_detected: '1', MG002_label: 'negative', MG002_detected: '0', MG003_label: 'negative', MG003_detected: '0', MG004_label: 'negative', MG004_detected: '0', MG006_label: 'negative', MG006_detected: '0' },
    { analyzer_complete: 'true', analyzer_diagnostics: '', MG001_label: 'positive', MG001_detected: '0', MG002_label: 'negative', MG002_detected: '1', MG003_label: 'negative', MG003_detected: '0', MG004_label: 'negative', MG004_detected: '0', MG006_label: 'negative', MG006_detected: '0' },
    { analyzer_complete: 'false', analyzer_diagnostics: 'UNRESOLVED_CALL', MG001_label: 'positive', MG001_detected: '0', MG002_label: 'negative', MG002_detected: '0', MG003_label: 'negative', MG003_detected: '0', MG004_label: 'negative', MG004_detected: '0', MG006_label: 'negative', MG006_detected: '0' },
    { analyzer_complete: 'false', analyzer_diagnostics: 'UNRESOLVED_FACTORY', MG001_label: 'unsupported', MG001_detected: '0', MG002_label: 'unsupported', MG002_detected: '0', MG003_label: 'unsupported', MG003_detected: '0', MG004_label: 'unsupported', MG004_detected: '0', MG006_label: 'unsupported', MG006_detected: '0' },
  ];
  const s = scoreRows(rows);
  assert.equal(s.total_handlers, 4);
  assert.equal(s.covered_handlers, 3);
  assert.equal(s.coverage, 0.75);
  assert.equal(s.per_rule.MG001.tp, 1);
  assert.equal(s.per_rule.MG001.fn, 2);
  assert.equal(s.per_rule.MG001.silent_misses, 1);
  assert.equal(s.per_rule.MG001.unsupported, 1);
  assert.equal(s.per_rule.MG002.fp, 1);
  assert.equal(s.per_rule.MG002.tn, 2);
  assert.equal(s.by_stratum.unassigned.total_handlers, 4);
});

test('server coverage keeps every row and weights servers equally in the macro', () => {
  const large = Array.from({ length: 9 }, () => ({ server_id: 'large', handler_name: 'tool' }));
  const s = scoreRows([...large, { server_id: 'small', handler_name: UNENUMERATED_TOOL }]);
  assert.equal(s.total_handlers, 10);
  assert.equal(s.coverage, 0.9);
  assert.equal(s.server_macro_coverage, 0.5);
  assert.equal(s.unenumerated_servers, 1);
  assert.deepEqual(s.largest_server, { server_id: 'large', total_handlers: 9, row_share: 0.9 });
  assert.deepEqual(s.by_server, {
    large: { covered_handlers: 9, total_handlers: 9, placeholder_rows: 0, coverage: 1, row_share: 0.9 },
    small: { covered_handlers: 0, total_handlers: 1, placeholder_rows: 1, coverage: 0, row_share: 0.1 }
  });
  assert.match(serverCoverageMarkdown('TypeScript', s).join('\n'), /9\/10 rows, 90\.0%[\s\S]+Server-macro coverage:\*\* 50\.0%/);
  assert.equal(scoreRows([]).largest_server, null);
});

test('scoreFromFiles enforces SHA-256 verification and refuses mismatch', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'vambrace-bench-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const csvPath = path.join(dir, 'labels.csv');
  const csvContent = 'analyzer_complete,analyzer_diagnostics,MG001_label,MG001_detected,MG002_label,MG002_detected,MG003_label,MG003_detected,MG004_label,MG004_detected,MG006_label,MG006_detected\ntrue,,positive,1,negative,0,negative,0,negative,0,negative,0\n';
  await writeFile(csvPath, csvContent);
  const realSha = createHash('sha256').update(csvContent).digest('hex');
  const shaPath = path.join(dir, 'labels.sha256');
  await writeFile(shaPath, `${realSha}  labels.csv\n`);
  const ok = scoreFromFiles({ labelsPath: csvPath, sha256Path: shaPath });
  assert.equal(ok.per_rule.MG001.tp, 1);
  assert.throws(() => verifyLabelsSha256(csvPath, '0'.repeat(64)), /SHA-256 mismatch/);
});

test('grep baseline flags comments while opengrep skips cleanly when absent', () => {
  const hits = grepScanSource('sample.ts', '// exec(args.cmd)\nconst s = "fetch(args.url)";\n');
  assert.equal(hits.length, 2);
  const og = runOpengrepBaseline(['fixtures/vulnerable'], { execImpl: () => { throw new Error('ENOENT'); } });
  assert.equal(og.status, 'skipped');
});

test('evasion suite generates AST variants with zero silent misses', () => {
  const ev = runEvasionSuite();
  assert.equal(ev.total, 20);
  assert.equal(ev.summary.silent_miss, 0);
  assert.ok(ev.summary.detected > 0);
});

test('labeling sheet, perf, and explicit missing-labels rejection run offline cleanly', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'vambrace-sheet-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const tsManifest = loadManifest(path.resolve('bench/manifest.json'));
  const pyManifest = loadManifest(path.resolve('bench/python-manifest.json'));
  const tsSplit = validateSplitByServer(tsManifest);
  const pySplit = validateSplitByServer(pyManifest);
  assert.equal(tsSplit.seed, 20261123);
  assert.equal(pySplit.seed, 20261123);
  for (const srv of [...tsManifest.servers, ...pyManifest.servers]) {
    assert.ok(!/vambrace|typescript-sdk/i.test(srv.url), `Manifest should not contain fixtures or SDK examples: ${srv.url}`);
  }

  // Test sheet generation offline via temporary local manifests (tests never depend on bench/.cache)
  const localTsManifest = path.join(dir, 'ts-manifest.json');
  const localPyManifest = path.join(dir, 'py-manifest.json');
  await writeFile(localTsManifest, JSON.stringify({
    schemaVersion: 1, seed: 20261123, splitBy: 'server',
    servers: [{ id: 'local-ts', url: 'https://example.invalid/ts.git', commit: '0'.repeat(40), license: 'MIT', selectionReason: 'unit test', split: 'dev', localFallback: 'fixtures/factory' }]
  }));
  await writeFile(localPyManifest, JSON.stringify({
    schemaVersion: 1, seed: 20261123, splitBy: 'server',
    servers: [{ id: 'local-py', url: 'https://example.invalid/py.git', commit: '0'.repeat(40), license: 'MIT', selectionReason: 'unit test', split: 'dev', localFallback: 'fixtures/python/positive' }]
  }));
  const sheet = generateLabelingSheet({ split: 'dev', manifestFile: localTsManifest, outFile: path.join(dir, 'ts-sheet.csv') });
  assert.ok(sheet.rowCount > 0);
  const text = await readFile(sheet.outFile, 'utf8');
  assert.match(text, /MG001_label/);
  const pySheet = await generatePythonLabelingSheet({ split: 'dev', manifestFile: localPyManifest, outFile: path.join(dir, 'py-sheet.csv') });
  assert.ok(pySheet.rowCount > 0);
  const pyText = await readFile(pySheet.outFile, 'utf8');
  assert.match(pyText, /MG001_label/);
  assert.throws(() => generateLabelingSheet({ split: 'test', manifestFile: localTsManifest, outFile: path.join(dir, 'bad.csv') }), /refuses test split/);
  await assert.rejects(() => generatePythonLabelingSheet({ split: 'test', manifestFile: localPyManifest, outFile: path.join(dir, 'bad-py.csv') }), /refuses test split/);

  // Verify checked-in blank todo sheets remain unlabeled
  const checkedInTs = readFileSync(path.resolve('bench/labels/todo/typescript-dev.csv'), 'utf8');
  const checkedInPy = readFileSync(path.resolve('bench/labels/todo/python-dev.csv'), 'utf8');
  assert.match(checkedInTs, /MG001_label/);
  assert.match(checkedInPy, /MG001_label/);

  // Verify fetchManifest records failures without throwing
  const failManifest = path.join(dir, 'fail-manifest.json');
  await writeFile(failManifest, JSON.stringify({
    schemaVersion: 1, seed: 20261123, splitBy: 'server',
    servers: [{ id: 'broken-repo', url: 'https://example.invalid/broken.git', commit: 'a'.repeat(40), license: 'MIT', selectionReason: 'failure test', split: 'dev' }]
  }));
  const fetchRes = fetchManifest({ manifestFile: failManifest, targetCache: path.join(dir, 'cache'), execImpl: () => { throw new Error('clone failed'); } });
  assert.equal(fetchRes.failedCount, 1);
  assert.equal(fetchRes.results[0].status, 'failed');
  const perf = measurePerf(['fixtures/vulnerable/server.ts'], 2);
  assert.equal(perf.samples, 2);
  assert.ok(perf.latency_ms.p50 >= 0);
  await assert.rejects(() => runBenchmark({ split: 'dev', writeOutputs: false }), /No labels file given/);
  await assert.rejects(() => runBenchmark({ split: 'test', writeOutputs: false }), /No labels file given/);
  const scoreRes = spawnSync(process.execPath, [path.resolve('bench/score.mjs')], { encoding: 'utf8', timeout: 15000 });
  assert.notEqual(scoreRes.status, 0);
  assert.match(scoreRes.stderr, /no labels file given/i);
  const runRes = spawnSync(process.execPath, [path.resolve('bench/run.mjs')], { encoding: 'utf8', timeout: 15000 });
  assert.notEqual(runRes.status, 0);
  assert.match(runRes.stderr, /No labels file given/i);
});

test('sheet extractors list multi-line decorators, constant names and low-level tool objects', () => {
  const py = [
    'from mcp.server.fastmcp import FastMCP',
    'mcp = FastMCP("demo")',
    '',
    '@mcp.tool(',
    '    name="list_services",',
    '    annotations={"title": "List (all) services", "readOnlyHint": True},',
    ')',
    'async def list_services() -> str:',
    '    return "ok"',
    '',
    '@mcp.tool()',
    '# comment between decorator and def',
    'def ping() -> str:',
    '    return "pong"'
  ].join('\n');
  assert.deepEqual(extractPythonToolNames(py).map(t => [t.name, t.line]), [['list_services', 8], ['ping', 13]]);

  const tsText = [
    "const LOOKUP = 'lookup_order';",
    "server.registerTool(LOOKUP, { description: 'x' }, async () => ({ content: [] }));",
    "server.tool('literal_tool', {}, async () => ({ content: [] }));",
    'const TOOLS = [',
    "  { name: 'low_level_read', description: 'r', inputSchema: { type: 'object' } },",
    "  { name: 'not_a_tool', value: 1 }",
    '];',
    'server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));'
  ].join('\n');
  assert.deepEqual(extractTsToolNames('x.ts', tsText).map(t => t.name).sort(), ['literal_tool', 'lookup_order', 'low_level_read']);
});

test('labeling sheets keep servers whose tools cannot be enumerated', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'vambrace-unenumerated-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const emptySrc = path.join(dir, 'src');
  await mkdir(emptySrc, { recursive: true });
  await writeFile(path.join(emptySrc, 'index.ts'), "export const helper = () => 1;\n");
  const manifestFile = path.join(dir, 'manifest.json');
  await writeFile(manifestFile, JSON.stringify({
    schemaVersion: 1, seed: 20261123, splitBy: 'server',
    servers: [
      { id: 'no-tools', url: 'https://example.invalid/a.git', commit: '0'.repeat(40), license: 'MIT', selectionReason: 'unit test', stratum: 'random-registry', split: 'dev', localFallback: emptySrc },
      { id: 'not-fetched', url: 'https://example.invalid/b.git', commit: '1'.repeat(40), license: 'MIT', selectionReason: 'unit test', stratum: 'random-registry', split: 'dev' }
    ]
  }));
  const sheet = generateLabelingSheet({ split: 'dev', manifestFile, outFile: path.join(dir, 'sheet.csv') });
  assert.equal(sheet.rowCount, 2);
  const csv = await readFile(sheet.outFile, 'utf8');
  assert.match(csv, new RegExp(`no-tools,random-registry,dev,[^,]*,${UNENUMERATED_TOOL},,false,TOOLS_NOT_ENUMERATED`));
  assert.match(csv, new RegExp(`not-fetched,random-registry,dev,[^,]*,${UNENUMERATED_TOOL},,false,SOURCE_NOT_FETCHED`));

  const scored = scoreRows([
    { server_id: 'a', handler_name: UNENUMERATED_TOOL, analyzer_complete: 'false', analyzer_diagnostics: 'TOOLS_NOT_ENUMERATED' },
    { server_id: 'b', handler_name: 'read_file', analyzer_complete: 'true', analyzer_diagnostics: '' }
  ]);
  assert.equal(scored.total_handlers, 2);
  assert.equal(scored.covered_handlers, 1);
  assert.equal(scored.unenumerated_servers, 1);
});
