import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { analyzeSource } from '../dist/analyzer.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const project = path.resolve(here, '..');
const record = process.argv.includes('--record');
if (process.argv.slice(2).some(arg => arg !== '--record')) throw new Error('Usage: node evaluation/run.mjs [--record]');
const readJson = (name) => JSON.parse(readFileSync(path.join(here, name), 'utf8'));
const sha = (buffer) => createHash('sha256').update(buffer).digest('hex');
const manifest = readJson('source-manifest.json');
const expectationsBytes = readFileSync(path.join(here, 'expectations.json'));
const expectations = JSON.parse(expectationsBytes);
const frozenLine = readFileSync(path.join(here, 'expectations.sha256'), 'utf8').trim();
const frozenSha = frozenLine.split(/\s+/)[0];
if (sha(expectationsBytes) !== frozenSha) throw new Error('Frozen expectations hash mismatch; refusing to run.');
if (!expectations.created_before_first_analyzer_run) throw new Error('Expectation provenance is not frozen.');
if (manifest.revision.length !== 40 || !/^[0-9a-f]{40}$/.test(manifest.revision)) throw new Error('Source revision must be an immutable 40-character commit.');
if (manifest.handler_count !== expectations.handlers.length || manifest.handler_count !== 24) throw new Error('Corpus handler count changed; review and refreeze explicitly.');
if (manifest.repository !== 'https://github.com/modelcontextprotocol/typescript-sdk') throw new Error('Unexpected upstream repository.');

const baseline = expectations.baseline_implementation;
const analyzerSource = readFileSync(path.join(project, 'src/analyzer.ts'));
const analyzerDistribution = readFileSync(path.join(project, 'dist/analyzer.js'));
if (sha(analyzerSource) !== baseline.analyzer_source_sha256) throw new Error('Analyzer source changed since expectations were frozen.');
if (sha(analyzerDistribution) !== baseline.analyzer_distribution_sha256) throw new Error('Analyzer distribution changed since expectations were frozen.');
const checkoutCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: project, encoding: 'utf8' }).trim();

for (const source of [...manifest.files, manifest.license_file]) {
  const bytes = readFileSync(path.join(here, source.path));
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
  const text = readFileSync(path.join(here, source.path), 'utf8');
  const result = analyzeSource(source.path, text);
  const handlers = expectedBySource.get(source.path) ?? [];
  const recognized = result.coverage.recognizedTools;
  if (recognized > handlers.length) throw new Error(`Analyzer recognized more registrations than manually reviewed in ${source.path}`);
  if (handlers.some(h => !h.source)) throw new Error(`Missing source mapping in ${source.path}`);
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
    manual_registration_shape: expected.expected_registration_status === 'supported'
      ? 'top-level McpServer registration (manual expectation)'
      : 'registration in local server factory (manual expectation)',
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
    false_flag_rate: negative.length ? falseFlags / negative.length : null,
    interpretation: positive.length ? 'Reference-example positive controls exist; static observations are not confirmed vulnerabilities.' : 'No scorable supported positive controls in this corpus; recall/miss rate is not measurable.'
  }];
}));

const report = {
  format_version: 2,
  generated_at: new Date().toISOString(),
  execution: 'Offline source-text analysis. Vendored targets were read as UTF-8 data and passed to analyzeSource; target modules were not imported or executed. No installation, network request, test, configuration scan, or credential scan is performed by this runner.',
  provenance: {
    repository: manifest.repository,
    revision: manifest.revision,
    license_basis: manifest.source_license_basis,
    license_file: manifest.license_file,
    source_files: manifest.files.map(f => ({ path: f.path, upstream_url: f.upstream_url, revision: f.revision, sha256: f.sha256, bytes: f.bytes })),
    expectations_sha256: frozenSha,
    expectations_created_before_first_analyzer_run: expectations.created_before_first_analyzer_run,
    baseline_implementation_commit: baseline.baseline_commit,
    checkout_commit_at_run: checkoutCommit,
    analyzer_source_sha256: sha(analyzerSource),
    analyzer_distribution_sha256: sha(analyzerDistribution)
  },
  scope: {
    repository_count: 1,
    source_file_count: manifest.files.length,
    distinct_actual_tool_handlers: manifest.handler_count,
    source_rules: expectations.rules,
    excluded_rules: { MG005: 'Inventory/schema rule; these source snippets do not form a descriptor inventory.' },
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
    findings: allFindings.length,
    positive_controls: expectations.handlers.filter(h => expectations.rules.some(r => h.expected_by_rule[r]?.status === 'supported-positive')).length,
    rule_handler_outcomes: manifest.handler_count * expectations.rules.length
  },
  per_rule: perRule,
  handlers: handlerResults,
  files: fileStats,
  findings: allFindings
};
const reportLines = [
  '# External public-source evaluation',
  '',
  `Generated ${report.generated_at}.`,
  '',
  `The offline runner reviewed ${report.counts.handlers} actual tool registrations from ${report.scope.source_file_count} source files in one official repository at commit \`${manifest.revision}\`. The analyzer reported ${report.counts.recognized_registration_count} recognized registrations in aggregate across files; the remaining ${report.counts.unrecognized_registration_count_by_file_count} are a count difference, not individually identified handlers. File-level recognized counts matched the frozen manual expectations in ${report.counts.registration_count_matches} of ${report.scope.source_file_count} files. The analyzer emitted ${report.counts.diagnostics} coverage diagnostics across ${report.counts.coverage_incomplete_files} files; there were ${report.counts.findings} findings and ${report.counts.parse_failures} parse failures.`,
  '',
  `Expectations were frozen before the first analyzer run (SHA-256 \`${frozenSha}\`). This is a single-repository reference-example coverage corpus, not an independent holdout or a representative accuracy estimate.`,
  '',
  'No supported positive controls were present, so recall and miss rate are not measurable. The corpus contains no confirmed vulnerabilities; any static finding is a pattern observation, not proof of exploitability.',
  '',
  '| Rule | Supported positive | Supported negative | Unsupported | Unscored: coverage incomplete | Unscored: mixed rule labels | Findings on scored handlers | Misses / positives | False flags / negatives |',
  '|---|---:|---:|---:|---:|---:|---:|---:|---:|',
  ...Object.entries(perRule).map(([rule, stats]) => `| ${rule} | ${stats.supported_positive_handlers} | ${stats.supported_negative_handlers} | ${stats.manually_unsupported_handlers} | ${stats.unscored_due_to_incomplete_coverage} | ${stats.unscored_due_to_unattributed_handler_identity} | ${stats.observed_findings_on_scored_supported_handlers} | ${stats.misses === null ? 'n/a (0/0)' : `${stats.misses} / ${stats.positive_denominator}`} | ${stats.false_flagged_negative_controls === null ? 'n/a (0/0)' : `${stats.false_flagged_negative_controls} / ${stats.false_flag_denominator}`} |`),
  '',
  'The two unscored columns describe overlapping reasons and must not be added together.',
  '',
  '## Handler outcomes',
  '',
  '| Handler | Source line | Manual registration shape | Findings mapped by tool name |',
  '|---|---:|---|---:|',
  ...handlerResults.map(h => `| [\`${h.name}\`](${h.upstream_line_url}) | ${h.registration_line} | ${h.manual_registration_shape} | ${Object.values(h.actual_findings_by_rule).reduce((a,b)=>a+b,0)} |`),
  '',
  '## Provenance and limits',
  '',
  'Reproduce from the repository root with `npm run evaluate`. The default run writes its timestamped report under ignored `evaluation/artifacts/external-evaluation/` and checks summary counts against the recorded `evaluation/report.json`; it does not modify committed evidence. Run `npm run evaluate -- --record` only when intentionally updating the recorded JSON and this document after reviewing a changed result. The vendored files are unmodified, checksum-verified copies of the cited upstream files. The upstream LICENSE is included in full because that repository documents an MIT-to-Apache-2.0 transition and retains older MIT grants where relicensing consent was not obtained. Each handler row links to its exact upstream line; findings retain analyzer output in the generated report JSON.',
  '',
  'The analyzer implementation is pinned by the pre-run commit and source/distribution checksums recorded above. The runner validates those checksums, vendored source checksums, and the frozen expectation hash before analysis. The analyzer exposes a recognized-registration count per file, not registration identities. The table lists manual source-registration shapes only; those labels are not independent analyzer classifications. Aggregate registration counts matched the manually frozen counts by file. All files had incomplete coverage, and the direct-registration file mixes rule-level expectations, so its one manual negative control is unscored. Per-rule unsupported counts follow manual expectations, not handler-by-handler analyzer identity. MG005 is not assessed because this source-only corpus contains no descriptor inventories.',
  '',
  'Targets are analyzed as text data. No target code is imported or executed; no dependencies are installed; no tests, network requests, credentials, third-party configuration, or external services are scanned.'
];

const signature = value => ({
  handlers: value.counts.handlers,
  recognized_registration_count: value.counts.recognized_registration_count ?? value.counts.recognized_handlers,
  unrecognized_registration_count_by_file_count: value.counts.unrecognized_registration_count_by_file_count ?? value.counts.unsupported_handlers,
  registration_count_matches: value.counts.registration_count_matches ?? value.files.filter(f => {
    const expectedCount = (expectedBySource.get(f.source) ?? []).filter(h => h.expected_registration_status === 'supported').length;
    return f.recognized_registration_count === undefined
      ? f.recognized_handlers === expectedCount
      : f.registration_count_matches_frozen_expectation;
  }).length,
  coverage_incomplete_files: value.counts.coverage_incomplete_files ?? value.files.filter(f => !f.coverage.complete).length,
  parse_failures: value.counts.parse_failures,
  diagnostics: value.counts.diagnostics,
  findings: value.counts.findings,
  positive_controls: value.counts.positive_controls,
  files: value.files.map(file => ({
    source: file.source,
    handlers: file.handlers,
    recognized: file.recognized_registration_count ?? file.recognized_handlers,
    diagnostics: file.diagnostics.length,
    complete: file.coverage.complete
  })),
  per_rule: Object.fromEntries(Object.entries(value.per_rule).map(([rule, stats]) => [rule, {
    positives: stats.supported_positive_handlers,
    negatives: stats.supported_negative_handlers,
    unsupported: stats.manually_unsupported_handlers,
    unscored_coverage: stats.expected_but_unscored_due_incomplete_coverage,
    unscored_identity: stats.expected_but_unscored_due_identity ?? stats.unscored_due_to_unattributed_handler_identity ?? 0
  }]))
});
const artifactsDir = path.join(here, 'artifacts', 'external-evaluation');
mkdirSync(artifactsDir, { recursive: true });
const generatedJsonPath = path.join(artifactsDir, 'report.json');
const generatedMarkdownPath = path.join(artifactsDir, 'EVALUATION-EXTERNAL.md');
writeFileSync(generatedJsonPath, JSON.stringify(report, null, 2) + '\n');
writeFileSync(generatedMarkdownPath, reportLines.join('\n') + '\n');

if (record) {
  writeFileSync(path.join(here, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  writeFileSync(path.resolve(here, '../docs/EVALUATION-EXTERNAL.md'), reportLines.join('\n') + '\n');
} else {
  const reference = readJson('report.json');
  if (JSON.stringify(signature(report)) !== JSON.stringify(signature(reference))) {
    throw new Error(`Evaluation counts differ from the recorded reference. Generated artifacts: ${artifactsDir}. Review changes before using --record.`);
  }
}

console.log(JSON.stringify({ report: generatedJsonPath, record, handlers: report.counts.handlers, recognizedRegistrationCount: recognizedRegistrations, unrecognizedRegistrationCountByFileCount: registrationSlotsUnrecognizedByCount, findings: allFindings.length, parseFailures, coverageIncompleteFiles: report.counts.coverage_incomplete_files }, null, 2));
