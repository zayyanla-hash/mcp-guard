import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeSource } from '../dist/analyzer.js';
import { analyzePythonSource } from '../dist/python-analyzer.js';
import { loadManifest } from './fetch.mjs';
import { generateLabelingSheet, resolveServerRoot } from './sheet.mjs';
import { parseCsv, RULES, scoreRows, verifyLabelsSha256 } from './score.mjs';
import { runGrepBaseline } from './baselines/grep.mjs';
import { runOpengrepBaseline } from './baselines/opengrep/run.mjs';
import { runEvasionSuite } from './evasion/run.mjs';
import { measurePerf } from './perf.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');

function collectSourceFiles(dir) {
  const out = [];
  const walk = (d) => {
    for (const entry of readdirSync(d).sort()) {
      if (['node_modules', '.git', 'dist', 'build', 'coverage'].includes(entry)) continue;
      const full = path.join(d, entry);
      const st = statSync(full);
      if (st.isDirectory()) walk(full);
      else if (/\.(ts|mts|js|mjs)$/i.test(entry) && !entry.endsWith('.d.ts') && !entry.endsWith('.min.js')) out.push(full);
    }
  };
  walk(dir);
  return out;
}

function fmtRate(v, ci) {
  if (v === null) return 'n/a';
  const pct = (v * 100).toFixed(1) + '%';
  if (!ci || ci.low === null) return pct;
  return `${pct} [${(ci.low * 100).toFixed(1)}%, ${(ci.high * 100).toFixed(1)}%]`;
}

export async function runBenchmark({
  split = 'dev',
  labelsPath,
  sha256Path,
  pyLabelsPath,
  pySha256Path,
  writeOutputs = true
} = {}) {
  if (!labelsPath) {
    throw new Error('No labels file given. Benchmark pending human labels; pass --labels <csv> and --sha256-file <path>.');
  }
  if (!sha256Path) {
    throw new Error('No SHA-256 file given. Pass --sha256-file <path>.');
  }
  if (split === 'test') {
    // External path verified below; test-split labels remain outside the repository.
  }
  const manifest = loadManifest(path.join(here, 'manifest.json'));
  const servers = manifest.servers.filter(s => split === 'all' || (s.split ?? 'dev') === split);
  const files = [];
  for (const server of servers) {
    const dir = resolveServerRoot(server);
    if (dir) files.push(...collectSourceFiles(dir));
  }

  // Generate blank labeling sheet artifact
  const sheet = generateLabelingSheet({ split });

  // Verify frozen labels SHA-256 before scoring
  const labelsSha256 = verifyLabelsSha256(labelsPath, readFileSync(sha256Path, 'utf8'));
  const labelRows = parseCsv(readFileSync(labelsPath, 'utf8'));

  // Run analyzer across files in the split and attach live predictions to label rows
  const analysisCache = new Map();
  for (const file of files) {
    const rel = path.relative(root, file).split(path.sep).join('/');
    analysisCache.set(rel, analyzeSource(rel, readFileSync(file, 'utf8')));
  }
  const scoredRows = labelRows.map(row => {
    const analysis = analysisCache.get(row.file) ?? analyzeSource(row.file, readFileSync(path.resolve(root, row.file), 'utf8'));
    const toolFindings = analysis.findings.filter(f => f.observed.includes(`Tool: ${row.handler_name}`));
    const out = {
      ...row,
      analyzer_complete: analysis.coverage.complete ? 'true' : 'false',
      analyzer_diagnostics: analysis.coverage.diagnostics.map(d => d.code).join(';')
    };
    for (const rule of RULES) {
      out[`${rule}_detected`] = toolFindings.some(f => f.ruleId === rule) ? '1' : '0';
    }
    return out;
  });

  const tsScores = scoreRows(scoredRows, RULES);

  // Separate Python MCP server slice (v1.1), scored only when human labels are provided
  let pySha256 = null;
  let pyScores = null;
  if (pyLabelsPath) {
    if (!pySha256Path) {
      throw new Error('No Python SHA-256 file given. Pass --py-sha256-file <path> alongside --py-labels <csv>.');
    }
    pySha256 = verifyLabelsSha256(pyLabelsPath, readFileSync(pySha256Path, 'utf8'));
    const pyRows = parseCsv(readFileSync(pyLabelsPath, 'utf8'));
    const pyAnalysisCache = new Map();
    for (const row of pyRows) {
      if (!pyAnalysisCache.has(row.file)) {
        pyAnalysisCache.set(row.file, await analyzePythonSource(row.file, readFileSync(path.resolve(root, row.file), 'utf8')));
      }
    }
    const pyScoredRows = pyRows.map(row => {
      const analysis = pyAnalysisCache.get(row.file);
      const toolFindings = analysis.findings.filter(f => f.observed.includes(`Tool: ${row.handler_name}`));
      const out = {
        ...row,
        analyzer_complete: analysis.coverage.complete ? 'true' : 'false',
        analyzer_diagnostics: analysis.coverage.diagnostics.map(d => d.code).join(';')
      };
      for (const rule of RULES) out[`${rule}_detected`] = toolFindings.some(f => f.ruleId === rule) ? '1' : '0';
      return out;
    });
    pyScores = scoreRows(pyScoredRows, RULES);
  }

  const grepBaseline = runGrepBaseline(files);
  const opengrepBaseline = runOpengrepBaseline(files);
  const evasion = runEvasionSuite();
  const perf = measurePerf(files);

  const summary = {
    generated_at: new Date().toISOString(),
    split,
    manifest_seed: manifest.seed,
    server_count: servers.length,
    file_count: files.length,
    labels_sha256: labelsSha256,
    python_labels_sha256: pySha256,
    sheet_path: path.relative(root, sheet.outFile),
    typescript: tsScores,
    python: pyScores,
    baselines: {
      grep: { total: grepBaseline.total, byRule: grepBaseline.byRule },
      opengrep: { status: opengrepBaseline.status, reason: opengrepBaseline.reason ?? null, total: opengrepBaseline.total ?? 0 }
    },
    evasion: evasion.summary,
    evasion_cases: evasion.cases,
    perf
  };

  const md = [
    '# Vambrace Benchmark Report',
    '',
    `Generated automatically by \`npm run bench\` (${summary.generated_at}). Never hand-edited.`,
    '',
    `- **Split:** \`${split}\` (${servers.length} servers, ${files.length} source files, seed \`${manifest.seed}\`)`,
    `- **Frozen labels SHA-256:** \`${labelsSha256}\``,
    `- **Handler coverage:** ${(tsScores.coverage * 100).toFixed(1)}% (${tsScores.covered_handlers}/${tsScores.total_handlers} handlers, 95% Wilson CI [${(tsScores.coverage_ci95.low * 100).toFixed(1)}%, ${(tsScores.coverage_ci95.high * 100).toFixed(1)}%])`,
    `- **Silent misses (positive handler with no finding and no incomplete diagnostic):** **${tsScores.total_silent_misses}**`,
    '',
    '## Per-rule accuracy (TypeScript analyzer)',
    '',
    '| Rule | TP | FP | FN | TN | Unsupported | Silent misses | Precision (95% Wilson CI) | Recall (95% Wilson CI) | F1 |',
    '|---|---:|---:|---:|---:|---:|---:|---|---|---:|',
    ...RULES.map(r => {
      const s = tsScores.per_rule[r];
      return `| ${r} | ${s.tp} | ${s.fp} | ${s.fn} | ${s.tn} | ${s.unsupported} | ${s.silent_misses} | ${fmtRate(s.precision, s.precision_ci95)} | ${fmtRate(s.recall, s.recall_ci95)} | ${s.f1 === null ? 'n/a' : s.f1.toFixed(4)} |`;
    }),
    '',
    '## Baselines',
    '',
    '| Baseline | Status | Total hits | Details |',
    '|---|---|---:|---|',
    `| Naive grep (\`bench/baselines/grep.mjs\`) | ok | ${grepBaseline.total} | ${RULES.slice(0, 4).map(r => `${r}:${grepBaseline.byRule[r] ?? 0}`).join(', ')} |`,
    `| Opengrep (\`bench/baselines/opengrep/\`) | ${opengrepBaseline.status} | ${opengrepBaseline.total ?? 0} | ${opengrepBaseline.reason ?? 'executed'} |`,
    '',
    '## Evasion resilience (TypeScript compiler API AST transforms)',
    '',
    `Tested ${evasion.total} transformed variants across MG001–MG004: **${evasion.summary.detected} detected**, **${evasion.summary.incomplete} flagged incomplete**, **${evasion.summary.silent_miss} silent misses**.`,
    '',
    '| Control | Transform | Outcome | Complete | Diagnostics |',
    '|---|---|---|---|---|',
    ...evasion.cases.map(c => `| ${c.control} | ${c.transform} | ${c.outcome} | ${c.complete ? 'yes' : 'no'} | ${c.diagnostics.join(', ') || 'none'} |`),
    '',
    '## Performance',
    '',
    `- **Samples:** ${perf.samples} (${perf.files} files)`,
    `- **Per-file latency:** p50 = ${perf.latency_ms.p50} ms, p95 = ${perf.latency_ms.p95} ms`,
    `- **Process RSS:** p50 = ${perf.rss_mb.p50} MiB, p95 = ${perf.rss_mb.p95} MiB`,
    '',
    '## Python slice (separate v1.1 evaluation)',
    '',
    ...(pyScores ? [
      `- **Frozen Python labels SHA-256:** \`${pySha256}\``,
      `- **Handler coverage:** ${(pyScores.coverage * 100).toFixed(1)}% (${pyScores.covered_handlers}/${pyScores.total_handlers} handlers, 95% Wilson CI [${(pyScores.coverage_ci95.low * 100).toFixed(1)}%, ${(pyScores.coverage_ci95.high * 100).toFixed(1)}%])`,
      `- **Silent misses:** **${pyScores.total_silent_misses}**`,
      '',
      '| Rule | TP | FP | FN | TN | Unsupported | Silent misses | Precision (95% Wilson CI) | Recall (95% Wilson CI) | F1 |',
      '|---|---:|---:|---:|---:|---:|---:|---|---|---:|',
      ...RULES.map(r => {
        const s = pyScores.per_rule[r];
        return `| ${r} | ${s.tp} | ${s.fp} | ${s.fn} | ${s.tn} | ${s.unsupported} | ${s.silent_misses} | ${fmtRate(s.precision, s.precision_ci95)} | ${fmtRate(s.recall, s.recall_ci95)} | ${s.f1 === null ? 'n/a' : s.f1.toFixed(4)} |`;
      })
    ] : ['Benchmark pending human labels.'])
  ];

  if (writeOutputs) {
    mkdirSync(path.join(here, 'artifacts'), { recursive: true });
    writeFileSync(path.join(here, 'artifacts', 'benchmark.json'), JSON.stringify(summary, null, 2) + '\n', 'utf8');
    writeFileSync(path.join(root, 'BENCHMARK.md'), md.join('\n') + '\n', 'utf8');
  }
  return summary;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const get = (flag) => {
    const idx = args.indexOf(flag);
    const val = idx !== -1 ? args[idx + 1] : undefined;
    return val && !val.startsWith('--') ? val : undefined;
  };
  const split = get('--split') ?? 'dev';
  const labelsPath = get('--labels');
  const sha256Path = get('--sha256-file');
  const pyLabelsPath = get('--py-labels');
  const pySha256Path = get('--py-sha256-file');
  try {
    const out = await runBenchmark({ split, labelsPath, sha256Path, pyLabelsPath, pySha256Path });
    console.log(JSON.stringify({
      split: out.split,
      servers: out.server_count,
      files: out.file_count,
      typescript: { coverage: out.typescript.coverage, silent_misses: out.typescript.total_silent_misses },
      python: out.python ? { coverage: out.python.coverage, silent_misses: out.python.total_silent_misses } : null,
      evasion: out.evasion,
      perf: out.perf
    }, null, 2));
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(2);
  }
}
