import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { wilsonInterval, scoreRows, scoreFromFiles, verifyLabelsSha256 } from '../bench/score.mjs';
import { grepScanSource } from '../bench/baselines/grep.mjs';
import { runOpengrepBaseline } from '../bench/baselines/opengrep/run.mjs';
import { runEvasionSuite } from '../bench/evasion/run.mjs';
import { generateLabelingSheet } from '../bench/sheet.mjs';
import { measurePerf } from '../bench/perf.mjs';
import { runBenchmark } from '../bench/run.mjs';

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
  const sheet = generateLabelingSheet({ split: 'dev', outFile: path.join(dir, 'sheet.csv') });
  assert.equal(sheet.rowCount, 16);
  const text = await readFile(sheet.outFile, 'utf8');
  assert.match(text, /MG001_label/);
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
