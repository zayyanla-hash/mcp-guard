import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { analyzeSource } from '../dist/analyzer.js';
import { analyzePythonSource } from '../dist/python-analyzer.js';
import { loadManifest } from './fetch.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const cacheDir = path.join(here, '.cache');
const RULES = ['MG001', 'MG002', 'MG003', 'MG004', 'MG006'];
const HEADER = [
  'server_id', 'split', 'file', 'handler_name', 'line', 'analyzer_complete', 'analyzer_diagnostics',
  ...RULES.flatMap(r => [`${r}_detected`, `${r}_label`, `${r}_rationale`])
];

function collectFiles(dir, extPattern) {
  const out = [];
  const walk = (d) => {
    for (const entry of readdirSync(d).sort()) {
      if (['node_modules', '.git', 'dist', 'build', 'coverage', '__pycache__', '.venv', 'venv'].includes(entry)) continue;
      const full = path.join(d, entry);
      const st = statSync(full);
      if (st.isDirectory()) walk(full);
      else if (extPattern.test(entry) && !entry.endsWith('.d.ts') && !entry.endsWith('.min.js')) out.push(full);
    }
  };
  walk(dir);
  return out;
}

function extractTsToolNames(file, text) {
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

function extractPythonToolNames(text) {
  const lines = text.split(/\r?\n/);
  const tools = [];
  const seen = new Set();
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (/^@[A-Za-z_][A-Za-z0-9_]*\.tool\b/.test(trimmed)) {
      for (let j = i + 1; j < lines.length; j++) {
        const nextTrim = lines[j].trim();
        if (nextTrim.startsWith('@') || nextTrim === '' || nextTrim.startsWith('#')) continue;
        const m = nextTrim.match(/^(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/);
        if (m) {
          const key = `${m[1]}:${j + 1}`;
          if (!seen.has(key)) {
            seen.add(key);
            tools.push({ name: m[1], line: j + 1 });
          }
        }
        break;
      }
      continue;
    }
    const addMatch = trimmed.match(/^[A-Za-z_][A-Za-z0-9_]*\.add_tool\(\s*([A-Za-z_][A-Za-z0-9_]*)\b/);
    if (addMatch) {
      const key = `${addMatch[1]}:${i + 1}`;
      if (!seen.has(key)) {
        seen.add(key);
        tools.push({ name: addMatch[1], line: i + 1 });
      }
    }
  }
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

function appendHandlerRows(rows, server, split, rel, handlers, result) {
  const diags = result.coverage.diagnostics.map(d => d.code).join(';');
  const complete = result.coverage.complete ? 'true' : 'false';
  for (const h of handlers) {
    const toolFindings = result.findings.filter(f => f.observed.includes(`Tool: ${h.name}`));
    const ruleCols = RULES.flatMap(r => [toolFindings.some(f => f.ruleId === r) ? '1' : '0', '', '']);
    rows.push([server.id, server.split ?? split, rel, h.name, h.line, complete, diags, ...ruleCols]);
  }
}

function writeSheetCsv(outFile, rows) {
  mkdirSync(path.dirname(outFile), { recursive: true });
  const csv = [HEADER.map(csvCell).join(','), ...rows.map(r => r.map(csvCell).join(','))].join('\n') + '\n';
  writeFileSync(outFile, csv, 'utf8');
  return { outFile, rowCount: rows.length };
}

export function generateLabelingSheet({
  split = 'dev',
  manifestFile = path.join(here, 'manifest.json'),
  outFile = path.join(here, 'labels', 'todo', 'typescript-dev.csv')
} = {}) {
  if (split !== 'dev') {
    throw new Error('Labeling sheet generation refuses test split inside repo; use --split dev.');
  }
  const manifest = loadManifest(manifestFile);
  const servers = manifest.servers.filter(s => (s.split ?? 'dev') === split);
  const rows = [];
  for (const server of servers) {
    const dir = resolveServerRoot(server);
    if (!dir) continue;
    for (const file of collectFiles(dir, /\.(ts|mts|js|mjs)$/i)) {
      const rel = path.relative(root, file).split(path.sep).join('/');
      const text = readFileSync(file, 'utf8');
      const result = analyzeSource(rel, text);
      const tools = extractTsToolNames(rel, text);
      const handlers = tools.length ? tools : [{ name: '<file-level>', line: 1 }];
      appendHandlerRows(rows, server, split, rel, handlers, result);
    }
  }
  return writeSheetCsv(outFile, rows);
}

export async function generatePythonLabelingSheet({
  split = 'dev',
  manifestFile = path.join(here, 'python-manifest.json'),
  outFile = path.join(here, 'labels', 'todo', 'python-dev.csv')
} = {}) {
  if (split !== 'dev') {
    throw new Error('Labeling sheet generation refuses test split inside repo; use --split dev.');
  }
  const manifest = loadManifest(manifestFile);
  const servers = manifest.servers.filter(s => (s.split ?? 'dev') === split);
  const rows = [];
  for (const server of servers) {
    const dir = resolveServerRoot(server);
    if (!dir) continue;
    for (const file of collectFiles(dir, /\.py$/i)) {
      const rel = path.relative(root, file).split(path.sep).join('/');
      const text = readFileSync(file, 'utf8');
      const result = await analyzePythonSource(rel, text);
      const tools = extractPythonToolNames(text);
      const handlers = tools.length ? tools : [{ name: '<file-level>', line: 1 }];
      appendHandlerRows(rows, server, split, rel, handlers, result);
    }
  }
  return writeSheetCsv(outFile, rows);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const get = (flag) => {
    const idx = args.indexOf(flag);
    const val = idx !== -1 ? args[idx + 1] : undefined;
    return val && !val.startsWith('--') ? val : undefined;
  };
  const split = get('--split') ?? 'dev';
  const lang = get('--lang') ?? 'all';
  const out = get('--out');
  if (lang === 'ts') {
    console.log(JSON.stringify(generateLabelingSheet({ split, ...(out ? { outFile: out } : {}) }), null, 2));
  } else if (lang === 'py') {
    console.log(JSON.stringify(await generatePythonLabelingSheet({ split, ...(out ? { outFile: out } : {}) }), null, 2));
  } else if (lang === 'all') {
    const tsSheet = generateLabelingSheet({ split });
    const pySheet = await generatePythonLabelingSheet({ split });
    console.log(JSON.stringify({ typescript: tsSheet, python: pySheet }, null, 2));
  } else {
    console.error(`Error: unsupported --lang "${lang}". Use ts, py, or all.`);
    process.exit(2);
  }
}
