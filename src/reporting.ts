import { cleanTerminal, redactText } from './shared.js';
import type { AuditResult, Coverage, Diagnostic, Finding, Location } from './types.js';

const MAX_BYTES = 1_048_576;
const MAX_DEPTH = 40;
const MAX_NODES = 50_000;
type Obj = Record<string, unknown>;
const isObject = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);
const string = (v: unknown): v is string => typeof v === 'string';
const sensitiveKey = (key: string) => {
  const normalized=key.replace(/[^a-z0-9]/gi,'').toLowerCase();
  return ['password','secret','token','apikey','authorization','privatekey','credential'].some(part=>normalized.includes(part));
};
function safeRedact(value: unknown): unknown {
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map(safeRedact);
  if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,sensitiveKey(k)?'[REDACTED]':safeRedact(v)]));
  return value;
}
function checkBounds(value: unknown): void {
  let nodes = 0;
  const visit = (v: unknown, depth: number): void => {
    if (++nodes > MAX_NODES) throw new Error(`Audit result exceeds the ${MAX_NODES} node limit.`);
    if (depth > MAX_DEPTH) throw new Error(`Audit result exceeds the ${MAX_DEPTH} level depth limit.`);
    if (Array.isArray(v)) for (const x of v) visit(x, depth + 1);
    else if (isObject(v)) for (const [k,x] of Object.entries(v)) {
      if (['__proto__','prototype','constructor'].includes(k)) throw new Error('Audit result contains an unsafe property name.');
      visit(x, depth + 1);
    }
    else if (typeof v === 'number' && !Number.isFinite(v)) throw new Error('Audit result contains a non-finite number.');
    else if (typeof v === 'undefined' || typeof v === 'function' || typeof v === 'symbol' || typeof v === 'bigint') throw new Error('Audit result contains a non-JSON value.');
  };
  visit(value,0);
  const raw = JSON.stringify(value);
  if (raw === undefined || new TextEncoder().encode(raw).length > MAX_BYTES) throw new Error(`Audit result exceeds the ${MAX_BYTES} byte limit or is not JSON-compatible.`);
}
function requiredStrings(o: Obj, fields: string[], where: string): void {
  for (const key of fields) if (!string(o[key])) throw new Error(`Malformed audit result: ${where}.${key} must be a string.`);
}
function arrayOfStrings(v: unknown, where: string): string[] {
  if (!Array.isArray(v) || v.some(x => !string(x))) throw new Error(`Malformed audit result: ${where} must be an array of strings.`);
  return v as string[];
}
function safeLocation(value: unknown): Location {
  if (!isObject(value)) throw new Error('Malformed audit result: finding location must be an object.');
  const out: Location = {};
  if (value.file !== undefined) { if (!string(value.file)) throw new Error('Malformed audit result: location.file must be a string.'); out.file = value.file; }
  if (value.pointer !== undefined) { if (!string(value.pointer)) throw new Error('Malformed audit result: location.pointer must be a string.'); out.pointer = value.pointer; }
  for (const key of ['line','column'] as const) if (value[key] !== undefined) {
    if (!Number.isSafeInteger(value[key]) || (value[key] as number) < 1) throw new Error(`Malformed audit result: location.${key} must be a positive integer.`);
    out[key] = value[key] as number;
  }
  if (Object.keys(out).length === 0) throw new Error('Malformed audit result: finding location must identify a file, pointer, line, or column.');
  return out;
}
function safeFinding(value: unknown): Finding {
  if (!isObject(value)) throw new Error('Malformed audit result: finding must be an object.');
  requiredStrings(value,['ruleId','ruleVersion','title','category','evidence','observed','why','remediation','fingerprint'],'finding');
  if (!['low','medium','high'].includes(String(value.severity))) throw new Error('Malformed audit result: finding.severity is invalid.');
  if (!['high','medium'].includes(String(value.confidence))) throw new Error('Malformed audit result: finding.confidence is invalid.');
  if (!['static-pattern','metadata-observation'].includes(String(value.evidenceType))) throw new Error('Malformed audit result: finding.evidenceType is invalid.');
  if (!Array.isArray(value.locations) || value.locations.length === 0) throw new Error('Malformed audit result: finding.locations must be a non-empty array.');
  if (!Array.isArray(value.assumptions) || value.assumptions.some(x => !string(x)) || !Array.isArray(value.limitations) || value.limitations.some(x => !string(x))) throw new Error('Malformed audit result: finding assumptions and limitations must be string arrays.');
  return {
    ruleId:value.ruleId as string, ruleVersion:value.ruleVersion as string, title:value.title as string, category:value.category as string,
    severity:value.severity as Finding['severity'], confidence:value.confidence as Finding['confidence'], evidenceType:value.evidenceType as Finding['evidenceType'],
    locations:value.locations.map(safeLocation), evidence:value.evidence as string, observed:value.observed as string, why:value.why as string,
    assumptions:value.assumptions as string[], remediation:value.remediation as string, limitations:value.limitations as string[], fingerprint:value.fingerprint as string
  };
}
function safeDiagnostic(value: unknown): Diagnostic {
  if (!isObject(value)) throw new Error('Malformed audit result: diagnostic must be an object.');
  requiredStrings(value,['code','message'],'diagnostic');
  const out: Diagnostic = {code:value.code as string,message:value.message as string};
  if (value.file !== undefined) { if (!string(value.file)) throw new Error('Malformed audit result: diagnostic.file must be a string.'); out.file=value.file; }
  if (value.pointer !== undefined) { if (!string(value.pointer)) throw new Error('Malformed audit result: diagnostic.pointer must be a string.'); out.pointer=value.pointer; }
  return out;
}
function safeCoverage(value: unknown, kind: AuditResult['kind']): Coverage {
  if (!isObject(value) || typeof value.complete !== 'boolean') throw new Error('Malformed audit result: coverage must include a boolean complete field.');
  for (const key of ['recognizedTools','unresolvedHandlers'] as const) if (!Number.isSafeInteger(value[key]) || (value[key] as number) < 0) throw new Error(`Malformed audit result: coverage.${key} must be a non-negative integer.`);
  if (!Array.isArray(value.diagnostics)) throw new Error('Malformed audit result: coverage.diagnostics must be an array.');
  const inspected = arrayOfStrings(value.inspected,'coverage.inspected');
  const excluded = arrayOfStrings(value.excluded,'coverage.excluded');
  const failed = arrayOfStrings(value.failed,'coverage.failed');
  const truncated = arrayOfStrings(value.truncated,'coverage.truncated');
  const diagnostics = value.diagnostics.map(safeDiagnostic);
  return {
    // A producer cannot claim complete coverage while analysis failed, a
    // handler remains unresolved, or a source scan found no supported tool.
    complete:value.complete && failed.length === 0 && truncated.length === 0 && diagnostics.length === 0
      && (value.unresolvedHandlers as number) === 0
      && !(kind === 'source' && (value.recognizedTools as number) === 0),
    inspected, excluded, failed, truncated,
    recognizedTools:value.recognizedTools as number, unresolvedHandlers:value.unresolvedHandlers as number,
    rulesApplied:arrayOfStrings(value.rulesApplied,'coverage.rulesApplied'), diagnostics
  };
}
function fixtureRoots(value: unknown, kind: AuditResult['kind']): string[] | undefined {
  if (value === undefined) return undefined;
  if (kind !== 'source' || !Array.isArray(value) || value.length === 0 || value.some(v =>
    !string(v) || !v || v.startsWith('/') || v.includes('\\') || v.split('/').some(part => !part || part === '.' || part === '..')
  )) throw new Error('Malformed audit result: declaredFixtureRoots must contain relative source directories.');
  return [...new Set(value as string[])].sort();
}
export function validateResult(value: unknown): AuditResult {
  checkBounds(value);
  if (!isObject(value) || value.schemaVersion !== 1 || !['source','inventory','diff'].includes(String(value.kind))) throw new Error('Malformed audit result: unsupported schemaVersion or kind.');
  requiredStrings(value,['target'],'result');
  if (!Array.isArray(value.findings)) throw new Error('Malformed audit result: findings must be an array.');
  const result: AuditResult = {
    schemaVersion:1,kind:value.kind as AuditResult['kind'],target:value.target as string,
    findings:value.findings.map(safeFinding),coverage:safeCoverage(value.coverage,value.kind as AuditResult['kind'])
  };
  const declaredRoots=fixtureRoots(value.declaredFixtureRoots,value.kind as AuditResult['kind']);
  if(declaredRoots)result.declaredFixtureRoots=declaredRoots;
  if (value.changes !== undefined) {
    if (!Array.isArray(value.changes)) throw new Error('Malformed audit result: changes must be an array.');
    result.changes = value.changes.map(change => {
      if (!isObject(change) || !string(change.kind)) throw new Error('Malformed audit result: change requires a kind string.');
      const out: NonNullable<AuditResult['changes']>[number] = {kind:change.kind};
      for (const key of ['tool','pointer'] as const) if (change[key] !== undefined) { if (!string(change[key])) throw new Error(`Malformed audit result: change.${key} must be a string.`); out[key]=change[key] as string; }
      if (Object.hasOwn(change,'before')) out.before=change.before;
      if (Object.hasOwn(change,'after')) out.after=change.after;
      return out;
    });
  }
  return safeRedact(result) as AuditResult;
}

function esc(value: string): string {
  return value.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
const safeText = (s: string) => esc(redactText(s));
function declaredFixture(finding: Finding, roots: string[] | undefined): string | undefined {
  if (!roots?.length || !finding.locations.length || finding.locations.some(location => !location.file)) return undefined;
  return roots.find(root => finding.locations.every(location => location.file?.startsWith(root + '/')));
}
function json(value: unknown): string { return safeText(JSON.stringify(safeRedact(value), null, 2) ?? String(value)); }
function locationText(location: Location): string {
  const source = location.file
    ? `${location.file}${location.line !== undefined ? `:${location.line}` : ''}${location.column !== undefined ? `:${location.column}` : ''}`
    : '';
  return [source, location.pointer].filter(Boolean).join(' ');
}
function coverageDetails(coverage: Coverage, text: (value: string) => string): string {
  const rows: Array<[string, string[]]> = [
    ['Rules applied', coverage.rulesApplied], ['Inspected', coverage.inspected], ['Excluded', coverage.excluded],
    ['Failed', coverage.failed], ['Truncated', coverage.truncated]
  ];
  return rows.map(([label, values]) => `<p><strong>${text(label)}:</strong> ${values.length ? values.map(text).join('; ') : 'None recorded.'}</p>`).join('');
}

export function renderHtml(input: AuditResult): string {
  const result = validateResult(input);
  const findings = result.findings.map(f => `<article class="finding"><div class="meta"><span class="severity ${f.severity}">${safeText(f.severity)}</span><span>${safeText(f.ruleId)}</span><span>${safeText(f.category)}</span><span>Confidence: ${safeText(f.confidence)}</span></div>${declaredFixture(f,result.declaredFixtureRoots) ? `<p class="muted">Operator-declared fixture path: ${safeText(declaredFixture(f,result.declaredFixtureRoots)!)}/. This does not dismiss the finding.</p>` : ''}<h2>${safeText(f.title)}</h2><p>${safeText(f.why)}</p><h3>Evidence</h3><pre>${safeText(f.evidence)}\nObserved: ${safeText(f.observed)}</pre><p><strong>Location:</strong> ${f.locations.map(l => safeText(locationText(l))).join(', ')}</p><p><strong>Assumptions:</strong> ${f.assumptions.length ? f.assumptions.map(safeText).join('; ') : 'None recorded.'}</p><p><strong>Remediation:</strong> ${safeText(f.remediation)}</p><p class="muted"><strong>Limitations:</strong> ${f.limitations.map(safeText).join('; ')}</p></article>`).join('\n');
  const changes = (result.changes ?? []).map(c => `<article class="change"><h2>${safeText(c.kind)}${c.tool ? ` · ${safeText(c.tool)}` : ''}</h2><p>${safeText(c.pointer ?? '')}</p>${c.before !== undefined ? `<h3>Before</h3><pre>${json(c.before)}</pre>` : ''}${c.after !== undefined ? `<h3>After</h3><pre>${json(c.after)}</pre>` : ''}</article>`).join('\n');
  const diagnostics = result.coverage.diagnostics.map(d => `<li><strong>${safeText(d.code)}:</strong> ${safeText(d.message)}${d.pointer ? ` <code>${safeText(d.pointer)}</code>` : ''}</li>`).join('');
  const summary = `<p class="coverage ${result.coverage.complete ? 'complete' : 'incomplete'}">Coverage: ${result.coverage.complete ? 'complete for declared checks' : 'incomplete'} · ${result.coverage.recognizedTools} recognized tools · ${result.coverage.unresolvedHandlers} unresolved handlers</p>`;
  const coverage = coverageDetails(result.coverage, safeText);
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MCP Guard report</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#17212b;background:#f7f9fb}h1{font-size:1.8rem}.muted{color:#586674}.coverage,.finding,.change{background:white;border:1px solid #d7e0e8;border-radius:8px;padding:1rem;margin:1rem 0}.coverage.complete{border-left:5px solid #24845a}.coverage.incomplete{border-left:5px solid #bd7915}.meta{display:flex;gap:1rem;align-items:center;color:#465766;font-size:.9rem}.severity{font-weight:700;text-transform:uppercase}.severity.high{color:#a52222}.severity.medium{color:#9c6410}.severity.low{color:#386b9a}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f7;padding:.8rem;border-radius:5px}code{overflow-wrap:anywhere}</style></head><body><h1>MCP Guard report</h1><p>${safeText(result.kind)} · ${safeText(result.target)}</p>${summary}${result.declaredFixtureRoots?.length ? `<p class="muted">Operator-declared fixture paths: ${result.declaredFixtureRoots.map(root=>safeText(root+'/')).join(', ')}. These paths are not verified as safe and findings remain actionable.</p>` : ''}<section><h2>Findings</h2>${findings || '<p>No findings recorded.</p>'}</section>${result.changes?.length ? `<section><h2>Changes</h2>${changes}</section>` : ''}<section><h2>Coverage details</h2>${coverage}</section><section><h2>Coverage diagnostics</h2>${diagnostics ? `<ul>${diagnostics}</ul>` : '<p>None.</p>'}</section></body></html>`;
}

export function renderTerminal(input: AuditResult): string {
  const result = validateResult(input);
  const lines = [`MCP Guard ${result.kind} report`, `Target: ${result.target}`, `Coverage: ${result.coverage.complete ? 'complete for declared checks' : 'incomplete'} (${result.coverage.recognizedTools} recognized tools; ${result.coverage.unresolvedHandlers} unresolved handlers)`, `Rules applied: ${result.coverage.rulesApplied.join(', ') || 'None recorded.'}`, `Inspected: ${result.coverage.inspected.join('; ') || 'None recorded.'}`, `Excluded: ${result.coverage.excluded.join('; ') || 'None recorded.'}`, `Failed: ${result.coverage.failed.join('; ') || 'None recorded.'}`, `Truncated: ${result.coverage.truncated.join('; ') || 'None recorded.'}`, ''];
  if (result.declaredFixtureRoots?.length) lines.push(`Operator-declared fixture paths: ${result.declaredFixtureRoots.map(root=>root+'/').join('; ')} (unverified; findings remain actionable)`, '');
  for (const f of result.findings) lines.push(`[${f.severity.toUpperCase()}] ${f.ruleId} ${f.title} (confidence: ${f.confidence})`, ...(declaredFixture(f,result.declaredFixtureRoots) ? [`  Context: operator-declared fixture path ${declaredFixture(f,result.declaredFixtureRoots)!}/; finding retained`] : []), `  Why: ${f.why}`, `  Evidence: ${f.evidence}`, `  Observed: ${f.observed}`, `  Location: ${f.locations.map(locationText).join(', ')}`, `  Assumptions: ${f.assumptions.join('; ') || 'None recorded.'}`, `  Remediation: ${f.remediation}`, '');
  for (const change of result.changes ?? []) lines.push(`[CHANGE] ${change.kind}${change.tool ? ` ${change.tool}` : ''}${change.pointer ? ` at ${change.pointer}` : ''}`, ...(change.before === undefined ? [] : [`  Before: ${JSON.stringify(change.before)}`]), ...(change.after === undefined ? [] : [`  After: ${JSON.stringify(change.after)}`]));
  if (result.coverage.diagnostics.length) { lines.push('Diagnostics:'); for (const d of result.coverage.diagnostics) lines.push(`  ${d.code}: ${d.message}${d.pointer ? ` (${d.pointer})` : ''}`); }
  return cleanTerminal(redactText(lines.join('\n')));
}
