import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const RULES = ['MG001', 'MG002', 'MG003', 'MG004', 'MG006'];
const Z_95 = 1.959963984540054;

export function wilsonInterval(successes, total, z = Z_95) {
  if (total <= 0) return { low: null, high: null };
  const p = successes / total;
  const z2 = z * z;
  const denom = 1 + z2 / total;
  const center = (p + z2 / (2 * total)) / denom;
  const half = (z * Math.sqrt((p * (1 - p) + z2 / (4 * total)) / total)) / denom;
  return {
    low: Math.max(0, Number((center - half).toFixed(4))),
    high: Math.min(1, Number((center + half).toFixed(4)))
  };
}

export function verifyLabelsSha256(labelsPath, expectedShaInput) {
  const bytes = readFileSync(labelsPath);
  const actual = createHash('sha256').update(bytes).digest('hex');
  const expected = expectedShaInput.trim().split(/\s+/)[0].toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expected)) {
    throw new Error(`Invalid expected SHA-256 format: ${expectedShaInput}`);
  }
  if (actual !== expected) {
    throw new Error(`Labels SHA-256 mismatch for ${labelsPath}: expected ${expected}, got ${actual}`);
  }
  return actual;
}

export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (ch === '"') inQuotes = false;
      else field += ch;
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(field); field = '';
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.some(cell => cell !== '')) rows.push(row);
      row = [];
    } else {
      field += ch;
    }
  }
  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  if (rows.length === 0) return [];
  const header = rows[0];
  return rows.slice(1).map(cells => Object.fromEntries(header.map((h, idx) => [h, cells[idx] ?? ''])));
}

/**
 * Score handler rows.
 * Each row has:
 * - analyzer_complete: 'true' | 'false' | boolean
 * - analyzer_diagnostics: semicolon-separated diagnostic codes or string
 * - <RULE>_label: 'positive' | 'negative' | 'unsupported'
 * - <RULE>_detected: '1' | '0' | 'true' | 'false'
 */
function computeRowStats(rows, rules = RULES) {
  const totalHandlers = rows.length;
  const coveredHandlers = rows.filter(r => {
    const diags = String(r.analyzer_diagnostics ?? '').trim();
    const unmapped = diags.includes('UNSUPPORTED_REGISTRATION') || diags.includes('UNRESOLVED_HANDLER') || diags.includes('UNRESOLVED_FACTORY');
    return !unmapped;
  }).length;
  const coverage = totalHandlers > 0 ? Number((coveredHandlers / totalHandlers).toFixed(4)) : 0;

  const perRule = {};
  let totalSilentMisses = 0;
  for (const rule of rules) {
    let tp = 0, fp = 0, fn = 0, tn = 0, unsupported = 0, silentMisses = 0;
    for (const row of rows) {
      const label = String(row[`${rule}_label`] ?? '').trim().toLowerCase();
      const detectedRaw = String(row[`${rule}_detected`] ?? '').trim().toLowerCase();
      const detected = detectedRaw === '1' || detectedRaw === 'true';
      const complete = row.analyzer_complete === true || String(row.analyzer_complete).trim().toLowerCase() === 'true';
      if (!label || label === 'unsupported') {
        unsupported++;
        continue;
      }
      if (label === 'positive') {
        if (detected) tp++;
        else {
          fn++;
          if (complete) silentMisses++;
        }
      } else if (label === 'negative') {
        if (detected) fp++;
        else tn++;
      } else {
        throw new Error(`Invalid label "${label}" for ${rule}; expected positive, negative, or unsupported.`);
      }
    }
    totalSilentMisses += silentMisses;
    const precDenom = tp + fp;
    const recDenom = tp + fn;
    const precision = precDenom > 0 ? Number((tp / precDenom).toFixed(4)) : null;
    const recall = recDenom > 0 ? Number((tp / recDenom).toFixed(4)) : null;
    const f1 = precision !== null && recall !== null && (precision + recall) > 0
      ? Number(((2 * precision * recall) / (precision + recall)).toFixed(4))
      : (precision === 0 || recall === 0 ? 0 : null);
    perRule[rule] = {
      tp, fp, fn, tn, unsupported,
      silent_misses: silentMisses,
      precision,
      precision_ci95: wilsonInterval(tp, precDenom),
      recall,
      recall_ci95: wilsonInterval(tp, recDenom),
      f1
    };
  }

  return {
    total_handlers: totalHandlers,
    covered_handlers: coveredHandlers,
    coverage,
    coverage_ci95: wilsonInterval(coveredHandlers, totalHandlers),
    total_silent_misses: totalSilentMisses,
    per_rule: perRule
  };
}

export function scoreRows(rows, rules = RULES) {
  const aggregate = computeRowStats(rows, rules);
  const strata = [...new Set(rows.map(r => String(r.stratum ?? '').trim() || 'unassigned'))];
  const byStratum = {};
  for (const stratum of strata) {
    byStratum[stratum] = computeRowStats(
      rows.filter(r => (String(r.stratum ?? '').trim() || 'unassigned') === stratum),
      rules
    );
  }
  return { ...aggregate, by_stratum: byStratum };
}

export function scoreFromFiles({ labelsPath, sha256Path, expectedSha } = {}) {
  if (!labelsPath) {
    throw new Error('No labels file given. Provide --labels <csv> (human-authored benchmark labels required).');
  }
  if (!expectedSha && !sha256Path) {
    throw new Error('No SHA-256 verification provided. Pass --sha256 <hex> or --sha256-file <path>.');
  }
  const hashSpec = expectedSha ?? readFileSync(sha256Path, 'utf8');
  const sha256 = verifyLabelsSha256(labelsPath, hashSpec);
  const rows = parseCsv(readFileSync(labelsPath, 'utf8'));
  return { labels_sha256: sha256, ...scoreRows(rows) };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const get = (flag) => {
    const idx = args.indexOf(flag);
    const val = idx !== -1 ? args[idx + 1] : undefined;
    return val && !val.startsWith('--') ? val : undefined;
  };
  const labelsPath = get('--labels');
  const sha256Path = get('--sha256-file');
  const expectedSha = get('--sha256');
  if (!labelsPath) {
    console.error('Error: no labels file given. Benchmark pending human labels; provide --labels <csv> and (--sha256 <hex> | --sha256-file <path>).');
    process.exit(2);
  }
  if (!sha256Path && !expectedSha) {
    console.error('Error: no SHA-256 verification given. Provide --sha256 <hex> or --sha256-file <path>.');
    process.exit(2);
  }
  try {
    console.log(JSON.stringify(scoreFromFiles({ labelsPath, sha256Path, expectedSha }), null, 2));
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(2);
  }
}
