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
  'server_id', 'stratum', 'split', 'file', 'handler_name', 'line', 'analyzer_complete', 'analyzer_diagnostics',
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

export const UNENUMERATED_TOOL = '<tools-not-enumerated>';

function propName(p) {
  return p.name && (ts.isIdentifier(p.name) || ts.isStringLiteralLike(p.name)) ? p.name.text : undefined;
}

export function extractTsToolNames(file, text) {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const lineOf = (n) => sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;
  // Same-file `const NAME = 'literal'` bindings, so registerTool(TOOL_NAME, ...) still yields a row.
  const constStrings = new Map();
  const collectConsts = (n) => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer && ts.isStringLiteralLike(n.initializer)) {
      constStrings.set(n.name.text, n.initializer.text);
    }
    ts.forEachChild(n, collectConsts);
  };
  collectConsts(sf);
  const tools = [];
  const seen = new Set();
  const push = (name, line) => {
    const key = `${name}:${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    tools.push({ name, line });
  };
  const visit = (n) => {
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && ['registerTool', 'tool'].includes(n.expression.name.text)) {
      const arg0 = n.arguments[0];
      if (arg0 && ts.isStringLiteralLike(arg0)) push(arg0.text, lineOf(n));
      else if (arg0 && ts.isIdentifier(arg0) && constStrings.has(arg0.text)) push(constStrings.get(arg0.text), lineOf(n));
    }
    // Low-level servers (setRequestHandler(ListToolsRequestSchema, ...)) declare tools as
    // object literals with a literal `name` and an `inputSchema`.
    if (ts.isObjectLiteralExpression(n)) {
      const props = n.properties.filter(ts.isPropertyAssignment);
      const nameProp = props.find(p => propName(p) === 'name');
      const hasSchema = n.properties.some(p => propName(p) === 'inputSchema');
      if (nameProp && hasSchema && ts.isStringLiteralLike(nameProp.initializer)) push(nameProp.initializer.text, lineOf(n));
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return tools;
}

function parenDelta(line) {
  // Count ( ) outside string literals and comments; good enough for decorator argument lists.
  let d = 0;
  let quote = null;
  for (let k = 0; k < line.length; k++) {
    const c = line[k];
    if (quote) {
      if (c === '\\') k++;
      else if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === '#') break;
    else if (c === '(') d++;
    else if (c === ')') d--;
  }
  return d;
}

export function extractPythonToolNames(text) {
  const lines = text.split(/\r?\n/);
  const tools = [];
  const seen = new Set();
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (/^@[A-Za-z_][A-Za-z0-9_]*\.tool\b/.test(trimmed)) {
      // A decorator call may span several lines: `@mcp.tool(\n    name="x",\n)`.
      let depth = 0;
      for (let j = i; j < lines.length; j++) {
        const nextTrim = lines[j].trim();
        if (depth > 0 || (j > i && nextTrim.startsWith('@'))) {
          depth = Math.max(0, depth + parenDelta(nextTrim));
          continue;
        }
        if (j === i) {
          depth = Math.max(0, parenDelta(nextTrim));
          continue;
        }
        if (nextTrim === '' || nextTrim.startsWith('#')) continue;
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
    rows.push([server.id, server.stratum ?? 'unassigned', server.split ?? split, rel, h.name, h.line, complete, diags, ...ruleCols]);
  }
}

function appendUnenumeratedRow(rows, server, split, dir, reason) {
  // Keep every sampled server in the sheet. A server whose tools the extractor cannot list
  // gets one placeholder row, so it counts as uncovered instead of silently dropping out.
  const rel = dir ? path.relative(root, dir).split(path.sep).join('/') : `bench/.cache/${server.id}`;
  const ruleCols = RULES.flatMap(() => ['0', '', '']);
  rows.push([server.id, server.stratum ?? 'unassigned', server.split ?? split, rel, UNENUMERATED_TOOL, '', 'false', reason, ...ruleCols]);
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
    if (!dir) {
      appendUnenumeratedRow(rows, server, split, null, 'SOURCE_NOT_FETCHED');
      continue;
    }
    const before = rows.length;
    for (const file of collectFiles(dir, /\.(ts|mts|js|mjs)$/i)) {
      const rel = path.relative(root, file).split(path.sep).join('/');
      const text = readFileSync(file, 'utf8');
      const tools = extractTsToolNames(rel, text);
      if (!tools.length) continue;
      const result = analyzeSource(rel, text);
      appendHandlerRows(rows, server, split, rel, tools, result);
    }
    if (rows.length === before) appendUnenumeratedRow(rows, server, split, dir, 'TOOLS_NOT_ENUMERATED');
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
    if (!dir) {
      appendUnenumeratedRow(rows, server, split, null, 'SOURCE_NOT_FETCHED');
      continue;
    }
    const before = rows.length;
    for (const file of collectFiles(dir, /\.py$/i)) {
      const rel = path.relative(root, file).split(path.sep).join('/');
      const text = readFileSync(file, 'utf8');
      const tools = extractPythonToolNames(text);
      if (!tools.length) continue;
      const result = await analyzePythonSource(rel, text);
      appendHandlerRows(rows, server, split, rel, tools, result);
    }
    if (rows.length === before) appendUnenumeratedRow(rows, server, split, dir, 'TOOLS_NOT_ENUMERATED');
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
