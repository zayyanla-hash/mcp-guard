import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { analyzeSource } from '../dist/analyzer.js';
import { loadManifest } from './fetch.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const cacheDir = path.join(here, '.cache');
const RULES = ['MG001', 'MG002', 'MG003', 'MG004', 'MG006'];

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

function extractToolNames(file, text) {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const tools = [];
  const visit = (n) => {
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === 'registerTool') {
      const arg0 = n.arguments[0];
      if (arg0 && ts.isStringLiteralLike(arg0)) {
        const line = sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;
        tools.push({ name: arg0.text, line });
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return tools;
}

export function resolveServerRoot(server) {
  const cached = server.subpath ? path.join(cacheDir, server.id, server.subpath) : path.join(cacheDir, server.id);
  try {
    if (statSync(cached).isDirectory()) return cached;
  } catch { /* use local fallback when cache has not been manually fetched */ }
  if (server.localFallback) {
    const local = path.resolve(root, server.localFallback);
    if (statSync(local).isDirectory()) return local;
  }
  return null;
}

function csvCell(v) {
  const s = String(v ?? '');
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function generateLabelingSheet({ split = 'dev', manifestFile = path.join(here, 'manifest.json'), outFile = path.join(here, 'artifacts', `labels-${split}-sheet.csv`) } = {}) {
  if (split !== 'dev' && split !== 'all') {
    throw new Error('Labeling sheet generation refuses test split inside repo; use --split dev.');
  }
  const manifest = loadManifest(manifestFile);
  const servers = manifest.servers.filter(s => split === 'all' || (s.split ?? 'dev') === split);
  const rows = [];
  const header = [
    'server_id', 'split', 'file', 'handler_name', 'line', 'analyzer_complete', 'analyzer_diagnostics',
    ...RULES.flatMap(r => [`${r}_detected`, `${r}_label`, `${r}_rationale`])
  ];
  for (const server of servers) {
    const dir = resolveServerRoot(server);
    if (!dir) continue;
    for (const file of collectSourceFiles(dir)) {
      const rel = path.relative(root, file).split(path.sep).join('/');
      const text = readFileSync(file, 'utf8');
      const result = analyzeSource(rel, text);
      const tools = extractToolNames(rel, text);
      const handlers = tools.length ? tools : [{ name: '<file-level>', line: 1 }];
      for (const h of handlers) {
        const toolFindings = result.findings.filter(f => f.observed.includes(`Tool: ${h.name}`));
        const diags = result.coverage.diagnostics.map(d => d.code).join(';');
        const ruleCols = RULES.flatMap(r => [toolFindings.some(f => f.ruleId === r) ? '1' : '0', '', '']);
        rows.push([server.id, server.split ?? 'dev', rel, h.name, h.line, result.coverage.complete ? 'true' : 'false', diags, ...ruleCols]);
      }
    }
  }
  mkdirSync(path.dirname(outFile), { recursive: true });
  const csv = [header.map(csvCell).join(','), ...rows.map(r => r.map(csvCell).join(','))].join('\n') + '\n';
  writeFileSync(outFile, csv, 'utf8');
  return { outFile, rowCount: rows.length };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const splitArg = process.argv.includes('--split') ? process.argv[process.argv.indexOf('--split') + 1] : 'dev';
  const outArg = process.argv.includes('--out') ? process.argv[process.argv.indexOf('--out') + 1] : undefined;
  console.log(JSON.stringify(generateLabelingSheet({ split: splitArg, outFile: outArg }), null, 2));
}
