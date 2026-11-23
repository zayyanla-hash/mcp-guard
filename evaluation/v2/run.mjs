import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { analyzeSource } from '../../dist/analyzer.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const v1Dir = path.resolve(here, '../v1');
const project = path.resolve(here, '../..');
const record = process.argv.includes('--record');
if (process.argv.slice(2).some(arg => arg !== '--record')) throw new Error('Usage: node evaluation/v2/run.mjs [--record]');
const readJson = (filePath) => JSON.parse(readFileSync(filePath, 'utf8'));
const sha = (buffer) => createHash('sha256').update(buffer).digest('hex');

const manifest = readJson(path.join(v1Dir, 'source-manifest.json'));
const v1Report = readJson(path.join(v1Dir, 'report.json'));
const expectationsBytes = readFileSync(path.join(here, 'expectations.json'));
const expectations = JSON.parse(expectationsBytes);
const frozenLine = readFileSync(path.join(here, 'expectations.sha256'), 'utf8').trim();
const frozenSha = frozenLine.split(/\s+/)[0];
if (sha(expectationsBytes) !== frozenSha) throw new Error('Frozen v2 expectations hash mismatch; refusing to run.');
if (!expectations.created_before_first_analyzer_run) throw new Error('v2 expectation provenance is not frozen.');
if (manifest.revision.length !== 40 || !/^[0-9a-f]{40}$/.test(manifest.revision)) throw new Error('Source revision must be an immutable 40-character commit.');
if (manifest.handler_count !== expectations.handlers.length || manifest.handler_count !== 24) throw new Error('Corpus handler count changed; review and refreeze explicitly.');
if (manifest.repository !== 'https://github.com/modelcontextprotocol/typescript-sdk') throw new Error('Unexpected upstream repository.');

const analyzerSource = readFileSync(path.join(project, 'src/analyzer.ts'));
const analyzerDistribution = readFileSync(path.join(project, 'dist/analyzer.js'));
const checkoutCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: project, encoding: 'utf8' }).trim();

for (const source of [...manifest.files, manifest.license_file]) {
  const bytes = readFileSync(path.join(v1Dir, source.path));
  if (sha(bytes) !== source.sha256) throw new Error(`Vendored data checksum mismatch: ${source.path}`);
}

const expectedBySource = new Map();
for (const handler of expectations.handlers) {
  const list = expectedBySource.get(handler.source) ?? [];
  list.push(handler);
  expectedBySource.set(handler.source, list);
}
const analyses = [];
const allFindings = [];
const fileStats = [];
let parseFailures = 0;
let recognizedRegistrations = 0;
let registrationSlotsUnrecognizedByCount = 0;
let diagnosticCount = 0;
for (const source of manifest.files) {
  const text = readFileSync(path.join(v1Dir, source.path), 'utf8');
  const result = analyzeSource(source.path, text);
  const handlers = expectedBySource.get(source.path) ?? [];
  const recognized = result.coverage.recognizedTools;
  if (recognized > handlers.length) throw new Error(`Analyzer recognized more registrations than manually reviewed in ${source.path}`);
  const expectedRegistered = handlers.filter(h => h.expected_registration_status === 'supported').length;
  if (recognized !== expectedRegistered) throw new Error(`Registration support count differs from frozen expectation in ${source.path}: ${recognized} vs ${expectedRegistered}`);
  const failed = result.coverage.diagnostics.some(d => d.code === 'PARSE_ERROR');
  if (failed) parseFailures++;
  diagnosticCount += result.coverage.diagnostics.length;
  recognizedRegistrations += recognized;
  registrationSlotsUnrecognizedByCount += handlers.length - recognized;
  analyses.push({ source: source.path, result });
  allFindings.push(...result.findings.map(f => ({ ...f, source_file: source.path })));
  fileStats.push({
    source: source.path,
    handlers: handlers.length,
    recognized_registration_count: recognized,
    expected_recognized_registration_count: expectedRegistered,
    registration_count_matches_frozen_expectation: recognized === expectedRegistered,
    parse_failure: failed,
    diagnostics: result.coverage.diagnostics,
    coverage: result.coverage
  });
}

const byId = new Map(analyses.map(({ source, result }) => [source, result]));
const handlerResults = expectations.handlers.map((expected) => {
  const analysis = byId.get(expected.source);
  const actualFindings = analysis.findings.filter(f => f.observed?.includes(`Tool: ${expected.name}`));
  return {
    id: expected.id,
    source: expected.source,
    name: expected.name,
    registration_line: expected.registration_line,
    upstream_line_url: expected.upstream_line_url,
    registration_shape: expected.registration_shape,
    actual_findings_by_rule: Object.fromEntries(expectations.rules.map(rule => [rule, actualFindings.filter(f => f.ruleId === rule).length]))
  };
});

const perRule = Object.fromEntries(expectations.rules.map(rule => {
  const expectedPositive = expectations.handlers.filter(h => h.expected_by_rule[rule]?.status === 'supported-positive');
  const expectedNegative = expectations.handlers.filter(h => h.expected_by_rule[rule]?.status === 'supported-negative');
  const unsupported = expectations.handlers.filter(h => h.expected_by_rule[rule]?.status === 'unsupported');
  const scorable = (handler) => {
    const result = byId.get(handler.source);
    const sourceHandlers = expectedBySource.get(handler.source) ?? [];
    const sourceRuleLabels = new Set(sourceHandlers.map(h => h.expected_by_rule[rule]?.status));
    return sourceRuleLabels.size === 1
      && handler.expected_by_rule[rule]?.status !== 'unsupported'
      && sourceHandlers.every(h => h.expected_registration_status === 'supported')
      && result.coverage.recognizedTools === sourceHandlers.length
      && result.coverage.complete;
  };
  const positive = expectedPositive.filter(scorable);
  const negative = expectedNegative.filter(scorable);
  const observed = handlerResults.filter(h => {
    const expected = expectations.handlers.find(x => x.id === h.id);
    return expected.expected_by_rule[rule]?.status !== 'unsupported' && scorable(expected);
  }).reduce((n, h) => n + h.actual_findings_by_rule[rule], 0);
  const misses = positive.filter(h => (handlerResults.find(a => a.id === h.id)?.actual_findings_by_rule[rule] ?? 0) === 0).length;
  const falseFlags = negative.filter(h => (handlerResults.find(a => a.id === h.id)?.actual_findings_by_rule[rule] ?? 0) > 0).length;
  const unexpectedOnUnsupported = handlerResults.filter(h => {
    const expected = expectations.handlers.find(x => x.id === h.id);
    return expected.expected_by_rule[rule]?.status === 'unsupported' && h.actual_findings_by_rule[rule] > 0;
  }).reduce((n, h) => n + h.actual_findings_by_rule[rule], 0);
  const unscoredDueToUnattributedIdentity = [...expectedPositive, ...expectedNegative].filter(h => {
    const fileHandlers = expectedBySource.get(h.source) ?? [];
    return new Set(fileHandlers.map(x => x.expected_by_rule[rule]?.status)).size !== 1;
  }).length;
  const unscoredDueToIncompleteCoverage = [...expectedPositive, ...expectedNegative].filter(h => !byId.get(h.source).coverage.complete).length;
  return [rule, {
    supported_positive_handlers: positive.length,
    positive_denominator: positive.length,
    supported_negative_handlers: negative.length,
    false_flag_denominator: negative.length,
    manually_unsupported_handlers: unsupported.length,
    expected_but_unscored_due_incomplete_coverage: unscoredDueToIncompleteCoverage,
    expected_but_unscored_due_identity: unscoredDueToUnattributedIdentity,
    observed_findings_on_scored_supported_handlers: observed,
    misses: positive.length ? misses : null,
    false_flagged_negative_controls: negative.length ? falseFlags : null,
    findings_on_rule_unsupported_handlers: unexpectedOnUnsupported,
    unscored_due_to_incomplete_coverage: unscoredDueToIncompleteCoverage,
    unscored_due_to_unattributed_handler_identity: unscoredDueToUnattributedIdentity,
    recall: positive.length ? (positive.length - misses) / positive.length : null,
    false_flag_rate: negative.length ? falseFlags / negative.length : null
  }];
}));

const report = {
  format_version: 2,
  study_version: 'v2',
  generated_at: new Date().toISOString(),
  execution: 'Offline source-text analysis with 1-level local factory support. Vendored targets were read as UTF-8 data and passed to analyzeSource; target modules were not imported or executed.',
  provenance: {
    repository: manifest.repository,
    revision: manifest.revision,
    expectations_sha256: frozenSha,
    expectations_created_before_first_analyzer_run: expectations.created_before_first_analyzer_run,
    pre_implementation_commit: expectations.pre_implementation_commit,
    checkout_commit_at_run: checkoutCommit,
    analyzer_source_sha256: sha(analyzerSource),
    analyzer_distribution_sha256: sha(analyzerDistribution)
  },
  scope: {
    repository_count: 1,
    source_file_count: manifest.files.length,
    distinct_actual_tool_handlers: manifest.handler_count,
    source_rules: expectations.rules,
    corpus_limitation: expectations.corpus_scope
  },
  counts: {
    handlers: manifest.handler_count,
    recognized_registration_count: recognizedRegistrations,
    unrecognized_registration_count_by_file_count: registrationSlotsUnrecognizedByCount,
    registration_count_matches: fileStats.filter(f => f.registration_count_matches_frozen_expectation).length,
    coverage_incomplete_files: fileStats.filter(f => !f.coverage.complete).length,
    parse_failures: parseFailures,
    diagnostics: diagnosticCount,
    findings: allFindings.length
  },
  comparison_with_v1: {
    v1_recognized_registration_count: v1Report.counts.recognized_registration_count,
    v2_recognized_registration_count: recognizedRegistrations,
    v1_coverage_incomplete_files: v1Report.counts.coverage_incomplete_files,
    v2_coverage_incomplete_files: fileStats.filter(f => !f.coverage.complete).length,
    v1_findings: v1Report.counts.findings,
    v2_findings: allFindings.length
  },
  per_rule: perRule,
  handlers: handlerResults,
  files: fileStats,
  findings: allFindings
};

const reportLines = [
  '# External public-source evaluation v2 (1-level local factory support)',
  '',
  `Generated ${report.generated_at}.`,
  '',
  '## v1 vs v2 comparison',
  '',
  '| Metric | v1 (top-level only) | v2 (1-level local factory) |',
  '|---|---:|---:|',
  `| Recognized registrations (of ${report.counts.handlers}) | ${v1Report.counts.recognized_registration_count} | ${report.counts.recognized_registration_count} |`,
  `| Incomplete coverage files (of ${report.scope.source_file_count}) | ${v1Report.counts.coverage_incomplete_files} | ${report.counts.coverage_incomplete_files} |`,
  `| Findings | ${v1Report.counts.findings} | ${report.counts.findings} |`,
  `| Parse failures | ${v1Report.counts.parse_failures} | ${report.counts.parse_failures} |`,
  `| Coverage diagnostics | ${v1Report.counts.diagnostics} | ${report.counts.diagnostics} |`,
  '',
  `Pre-registered expectations SHA-256: \`${frozenSha}\` (committed before \`src/analyzer.ts\` changes at \`${expectations.pre_implementation_commit}\`).`,
  '',
  '| Rule | Supported positive | Supported negative | Unsupported | Unscored: coverage incomplete | Findings on scored handlers | False flags / negatives |',
  '|---|---:|---:|---:|---:|---:|---:|',
  ...Object.entries(perRule).map(([rule, stats]) => `| ${rule} | ${stats.supported_positive_handlers} | ${stats.supported_negative_handlers} | ${stats.manually_unsupported_handlers} | ${stats.unscored_due_to_incomplete_coverage} | ${stats.observed_findings_on_scored_supported_handlers} | ${stats.false_flagged_negative_controls === null ? 'n/a (0/0)' : `${stats.false_flagged_negative_controls} / ${stats.false_flag_denominator}`} |`),
  '',
  '## Per-file breakdown',
  '',
  '| File | Handlers | Recognized | Complete coverage | Diagnostics |',
  '|---|---:|---:|---|---:|',
  ...fileStats.map(f => `| \`${f.source}\` | ${f.handlers} | ${f.recognized_registration_count} | ${f.coverage.complete ? 'yes' : 'no'} | ${f.diagnostics.length} |`),
  '',
  '## Handler outcomes',
  '',
  '| Handler | Source line | Registration shape | Findings |',
  '|---|---:|---|---:|',
  ...handlerResults.map(h => `| [\`${h.name}\`](${h.upstream_line_url}) | ${h.registration_line} | ${h.registration_shape} | ${Object.values(h.actual_findings_by_rule).reduce((a,b)=>a+b,0)} |`)
];

const signature = value => ({
  handlers: value.counts.handlers,
  recognized_registration_count: value.counts.recognized_registration_count,
  unrecognized_registration_count_by_file_count: value.counts.unrecognized_registration_count_by_file_count,
  registration_count_matches: value.counts.registration_count_matches,
  coverage_incomplete_files: value.counts.coverage_incomplete_files,
  parse_failures: value.counts.parse_failures,
  diagnostics: value.counts.diagnostics,
  findings: value.counts.findings,
  files: value.files.map(f => ({ source: f.source, handlers: f.handlers, recognized: f.recognized_registration_count, diagnostics: f.diagnostics.length, complete: f.coverage.complete }))
});

const artifactsDir = path.join(here, 'artifacts', 'external-evaluation');
mkdirSync(artifactsDir, { recursive: true });
const generatedJsonPath = path.join(artifactsDir, 'report.json');
const generatedMarkdownPath = path.join(artifactsDir, 'EVALUATION-EXTERNAL-V2.md');
writeFileSync(generatedJsonPath, JSON.stringify(report, null, 2) + '\n');
writeFileSync(generatedMarkdownPath, reportLines.join('\n') + '\n');

if (record) {
  writeFileSync(path.join(here, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  writeFileSync(path.resolve(here, '../../docs/EVALUATION-EXTERNAL-V2.md'), reportLines.join('\n') + '\n');
} else {
  const reference = readJson(path.join(here, 'report.json'));
  if (JSON.stringify(signature(report)) !== JSON.stringify(signature(reference))) {
    throw new Error(`v2 evaluation counts differ from recorded reference. Review ${artifactsDir} before using --record.`);
  }
}

console.log(JSON.stringify({
  report: generatedJsonPath,
  record,
  handlers: report.counts.handlers,
  v1Recognized: v1Report.counts.recognized_registration_count,
  v2Recognized: recognizedRegistrations,
  v1IncompleteFiles: v1Report.counts.coverage_incomplete_files,
  v2IncompleteFiles: report.counts.coverage_incomplete_files,
  findings: allFindings.length,
  parseFailures
}, null, 2));
