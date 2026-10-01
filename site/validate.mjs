import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = async (name) => JSON.parse(await readFile(path.join(root, 'examples/seeded', name), 'utf8'));
const window = {};
vm.runInNewContext(await readFile(path.join(root, 'site/data.js'), 'utf8'), { window });
const demo = JSON.parse(JSON.stringify(window.MCP_GUARD_DEMO));
assert.ok(demo, 'static demo data is present');
const [source, corrected, inventory, drift, before, after] = await Promise.all([
  readJson('vulnerable.json'), readJson('corrected.json'), readJson('inventory.json'),
  readJson('drift.json'), readJson('before.snapshot.json'), readJson('after.snapshot.json'),
]);
assert.deepStrictEqual(demo.source.findings, source.findings, 'every source finding field is preserved');
assert.deepStrictEqual(demo.source.coverage, source.coverage, 'source coverage is preserved');
assert.deepStrictEqual(demo.corrected.findings, corrected.findings, 'corrected result is preserved');
assert.deepStrictEqual(demo.corrected.coverage, corrected.coverage, 'corrected coverage is preserved');
assert.deepStrictEqual(demo.inventory.findings, inventory.findings, 'MG005 evidence is preserved separately');
assert.deepStrictEqual(demo.inventory.coverage, inventory.coverage, 'inventory coverage is preserved');
assert.deepStrictEqual(demo.drift.changes, drift.changes, 'every descriptor drift change is preserved');
assert.deepStrictEqual(demo.drift.before.payload, before.payload, 'before snapshot payload is preserved');
assert.deepStrictEqual(demo.drift.after.payload, after.payload, 'after snapshot payload is preserved');
assert.equal(demo.drift.before.hash, before.hash, 'before snapshot hash is preserved');
assert.equal(demo.drift.after.hash, after.hash, 'after snapshot hash is preserved');
assert.equal(demo.source.findings.length, 5, 'seeded vulnerable source has five findings');
assert.equal(demo.corrected.findings.length, 0, 'corrected source has zero supported-scope findings');
assert.equal(demo.inventory.findings.length, 1, 'MG005 remains a separate descriptor finding');
assert.equal(demo.drift.changes.length, 5, 'seeded drift has five recorded changes');
const html = await readFile(path.join(root, 'site/index.html'), 'utf8');
assert.match(html, /href="styles\.css"/);
assert.match(html, /src="data\.js"/);
assert.match(html, /src="app\.js"/);
assert.doesNotMatch(html, /<script[^>]+src="https?:/i, 'no remote scripts');
assert.doesNotMatch(html, /fonts\.googleapis|googletagmanager|google-analytics/i, 'no remote font or analytics integration');
const evaluation = JSON.parse(await readFile(path.join(root, 'evaluation/report.json'), 'utf8'));
const externalCounts = {
  handlers: evaluation.counts.handlers,
  source_file_count: evaluation.scope.source_file_count,
  recognized_registration_count: evaluation.counts.recognized_registration_count,
  unrecognized_registration_count_by_file_count: evaluation.counts.unrecognized_registration_count_by_file_count,
  diagnostics: evaluation.counts.diagnostics,
  parse_failures: evaluation.counts.parse_failures,
  findings: evaluation.counts.findings,
  coverage_incomplete_files: evaluation.counts.coverage_incomplete_files,
};
assert.deepStrictEqual(externalCounts, {
  handlers: 24,
  source_file_count: 7,
  recognized_registration_count: 4,
  unrecognized_registration_count_by_file_count: 20,
  diagnostics: 27,
  parse_failures: 0,
  findings: 0,
  coverage_incomplete_files: 7,
}, 'external evaluation counts match the reviewed report');
assert.equal(evaluation.handlers.length, externalCounts.handlers, 'manual registration rows match total');
assert.equal(evaluation.files.length, externalCounts.source_file_count, 'source-file rows match total');
assert.equal(evaluation.files.reduce((sum, file) => sum + file.recognized_registration_count, 0), externalCounts.recognized_registration_count, 'recognized count is an aggregate across files');
assert.equal(evaluation.handlers.filter(handler => handler.manual_registration_shape === 'registration in local server factory (manual expectation)').length, externalCounts.unrecognized_registration_count_by_file_count, 'manual factory-bound count matches the aggregate count difference');
assert.equal(evaluation.files.filter(file => !file.coverage.complete).length, externalCounts.coverage_incomplete_files, 'incomplete coverage count matches file records');
assert.equal(evaluation.files.reduce((sum, file) => sum + file.diagnostics.length, 0), externalCounts.diagnostics, 'diagnostic count matches file records');
assert.equal(evaluation.files.filter(file => file.parse_failure).length, externalCounts.parse_failures, 'parse failure count matches file records');
assert.equal(evaluation.findings.length, externalCounts.findings, 'finding count matches report records');
for (const [key, count] of Object.entries(externalCounts)) {
  const displayed = [...html.matchAll(new RegExp(`data-evaluation-count="${key}">([0-9]+)<`, 'g'))];
  assert.equal(displayed.length, 1, `one visible external evaluation count for ${key}`);
  assert.equal(Number(displayed[0][1]), count, `displayed ${key} matches the recorded evaluation`);
}
console.log('MCP Guard static demo validation passed: seeded evidence, external evaluation summary, relative assets, and dependency boundary.');
