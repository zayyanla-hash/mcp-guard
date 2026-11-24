import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { finding } from './shared.js';
import type { Diagnostic, Finding, Severity } from './types.js';

export type OptionalEngineName = 'cisco-yara' | 'promptguard';

export type ExecFileLike = (
  file: string,
  args: string[],
  options: { encoding: 'utf8'; timeout: number; stdio: ['ignore', 'pipe', 'pipe'] }
) => string;

export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal }
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export interface EngineRunOutput {
  findings: Finding[];
  diagnostics: Diagnostic[];
  incomplete: boolean;
}

function normalizeSeverity(raw: unknown): Severity {
  const s = String(raw ?? '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'high';
  if (s === 'low' || s === 'info') return 'low';
  return 'medium';
}

export async function runCiscoYaraEngine(
  inventoryPath: string,
  options: { execImpl?: ExecFileLike; binary?: string } = {}
): Promise<EngineRunOutput> {
  const execImpl = options.execImpl ?? ((file, args, opts) => execFileSync(file, args, opts));
  const binary = options.binary ?? 'mcp-scanner';
  let stdout = '';
  try {
    stdout = execImpl(binary, ['--analyzers', 'yara', '--raw', 'static', '--tools', path.resolve(inventoryPath)], {
      encoding: 'utf8',
      timeout: 30_000,
      stdio: ['ignore', 'pipe', 'pipe']
    });
  } catch (err: unknown) {
    const e = err as { code?: string; status?: number; stdout?: string | Buffer; message?: string };
    if (e.status === 1 && e.stdout) {
      stdout = typeof e.stdout === 'string' ? e.stdout : e.stdout.toString('utf8');
    } else if (e.code === 'ENOENT') {
      return {
        findings: [],
        diagnostics: [{ code: 'CISCO_YARA_UNAVAILABLE', file: inventoryPath, message: 'Cisco mcp-scanner binary not found on PATH; cisco-yara engine skipped.' }],
        incomplete: true
      };
    } else {
      return {
        findings: [],
        diagnostics: [{ code: 'CISCO_YARA_ERROR', file: inventoryPath, message: e.message ? String(e.message) : 'Cisco mcp-scanner failed.' }],
        incomplete: true
      };
    }
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return {
      findings: [],
      diagnostics: [{ code: 'CISCO_YARA_INVALID_OUTPUT', file: inventoryPath, message: 'Cisco mcp-scanner output was not valid JSON.' }],
      incomplete: true
    };
  }

  const rawFindings = Array.isArray(parsed)
    ? parsed
    : (parsed && typeof parsed === 'object' && Array.isArray((parsed as Record<string, unknown>).findings)
      ? (parsed as Record<string, unknown>).findings as unknown[]
      : []);

  const findings: Finding[] = [];
  for (const item of rawFindings) {
    if (!item || typeof item !== 'object') continue;
    const rec = item as Record<string, unknown>;
    const toolName = typeof rec.tool === 'string' ? rec.tool : (typeof rec.tool_name === 'string' ? rec.tool_name : undefined);
    const pointer = typeof rec.pointer === 'string' ? rec.pointer : '/tools';

    // Real `mcp-scanner --analyzers yara --raw static --tools` per-tool entry
    const findingsObj = rec.findings && typeof rec.findings === 'object' ? rec.findings as Record<string, unknown> : undefined;
    const yaraObj = findingsObj?.yara_analyzer && typeof findingsObj.yara_analyzer === 'object'
      ? findingsObj.yara_analyzer as Record<string, unknown>
      : undefined;
    if (yaraObj) {
      const total = Number(yaraObj.total_findings ?? 0);
      if (rec.is_safe === true || total <= 0) continue;
      const threats = Array.isArray(yaraObj.threat_names) ? yaraObj.threat_names.map(String) : ['yara_match'];
      const ruleName = threats.join(', ') || 'yara_match';
      const excerpt = String(rec.tool_description ?? yaraObj.threat_summary ?? ruleName);
      findings.push(finding({
        engine: 'cisco-yara',
        ruleId: 'MG007',
        title: `Cisco YARA match: ${ruleName}`,
        category: 'tool-poisoning',
        severity: normalizeSeverity(yaraObj.severity),
        confidence: 'medium',
        evidenceType: 'metadata-observation',
        locations: [{ file: inventoryPath, pointer }],
        evidence: excerpt.slice(0, 320),
        observed: `External cisco-yara matched ${ruleName}${toolName ? ` on tool "${toolName}"` : ''}.`,
        why: String(yaraObj.threat_summary ?? 'YARA signature matched suspicious instruction or payload metadata.'),
        assumptions: ['Cisco mcp-scanner ran offline in static YARA-only mode on inventory JSON.'],
        remediation: 'Review the flagged descriptor content and remove hidden directives or suspicious patterns.',
        limitations: ['External YARA engine match; verify signature context manually.']
      }));
      continue;
    }

    // Flat finding object format
    if (rec.is_safe === true) continue;
    const ruleName = String(rec.rule ?? rec.rule_name ?? rec.id ?? 'yara_match');
    const excerpt = String(rec.match ?? rec.evidence ?? rec.description ?? ruleName);
    findings.push(finding({
      engine: 'cisco-yara',
      ruleId: 'MG007',
      title: `Cisco YARA match: ${ruleName}`,
      category: 'tool-poisoning',
      severity: normalizeSeverity(rec.severity),
      confidence: 'medium',
      evidenceType: 'metadata-observation',
      locations: [{ file: inventoryPath, pointer }],
      evidence: excerpt.slice(0, 320),
      observed: `External cisco-yara matched ${ruleName}${toolName ? ` on tool "${toolName}"` : ''}.`,
      why: String(rec.reason ?? rec.message ?? 'YARA signature matched suspicious instruction or payload metadata.'),
      assumptions: ['Cisco mcp-scanner ran offline in static YARA-only mode on inventory JSON.'],
      remediation: 'Review the flagged descriptor content and remove hidden directives or suspicious patterns.',
      limitations: ['External YARA engine match; verify signature context manually.']
    }));
  }
  return { findings, diagnostics: [], incomplete: false };
}

export async function runPromptGuardEngine(
  inventory: Record<string, unknown>,
  inventoryPath: string,
  options: { endpoint?: string; fetchImpl?: FetchLike; threshold?: number } = {}
): Promise<EngineRunOutput> {
  const endpoint = options.endpoint ?? 'http://127.0.0.1:8787/classify';
  const threshold = options.threshold ?? 0.5;
  const fetchImpl: FetchLike = options.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);

  const tools = Array.isArray(inventory.tools) ? inventory.tools : [];
  const inputs: Array<{ pointer: string; tool?: string; text: string }> = [];
  if (typeof inventory.instructions === 'string' && inventory.instructions.trim()) {
    inputs.push({ pointer: '/instructions', text: inventory.instructions });
  }
  for (let i = 0; i < tools.length; i++) {
    const t = tools[i];
    if (t && typeof t === 'object' && typeof (t as Record<string, unknown>).description === 'string') {
      const rec = t as Record<string, unknown>;
      inputs.push({
        pointer: `/tools/${i}/description`,
        tool: typeof rec.name === 'string' ? rec.name : undefined,
        text: rec.description as string
      });
    }
  }
  if (inputs.length === 0) return { findings: [], diagnostics: [], incomplete: false };

  let response: { ok: boolean; status: number; json(): Promise<unknown> };
  try {
    response = await fetchImpl(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ items: inputs.map(x => ({ pointer: x.pointer, text: x.text })) }),
      signal: AbortSignal.timeout(10_000)
    });
  } catch (err) {
    return {
      findings: [],
      diagnostics: [{ code: 'PROMPTGUARD_UNAVAILABLE', file: inventoryPath, message: `Prompt Guard sidecar request failed: ${err instanceof Error ? err.message : String(err)}` }],
      incomplete: true
    };
  }

  if (!response.ok) {
    return {
      findings: [],
      diagnostics: [{ code: 'PROMPTGUARD_ERROR', file: inventoryPath, message: `Prompt Guard sidecar returned HTTP ${response.status}.` }],
      incomplete: true
    };
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return {
      findings: [],
      diagnostics: [{ code: 'PROMPTGUARD_INVALID_OUTPUT', file: inventoryPath, message: 'Prompt Guard sidecar response was not valid JSON.' }],
      incomplete: true
    };
  }

  const results = (body && typeof body === 'object' && Array.isArray((body as Record<string, unknown>).results))
    ? (body as Record<string, unknown>).results as Array<Record<string, unknown>>
    : [];

  const findings: Finding[] = [];
  for (let i = 0; i < results.length && i < inputs.length; i++) {
    const r = results[i]!;
    const item = inputs[i]!;
    const label = String(r.label ?? '').toUpperCase();
    const score = typeof r.score === 'number' ? r.score : 0;
    const isFlagged = r.malicious === true || (label === 'INJECTION' || label === 'MALICIOUS') && score >= threshold;
    if (!isFlagged) continue;
    findings.push(finding({
      engine: 'promptguard',
      ruleId: 'MG007',
      title: 'Prompt Guard 2 flagged potential prompt injection in tool metadata',
      category: 'tool-poisoning',
      severity: score >= 0.85 ? 'high' : 'medium',
      confidence: 'medium',
      evidenceType: 'metadata-observation',
      locations: [{ file: inventoryPath, pointer: item.pointer }],
      evidence: `score=${score.toFixed(3)} label=${label || 'INJECTION'} text=${JSON.stringify(item.text.slice(0, 200))}`,
      observed: `Local Prompt Guard 2 sidecar classified ${item.pointer}${item.tool ? ` (tool: ${item.tool})` : ''} as ${label || 'INJECTION'} (${score.toFixed(3)}).`,
      why: 'Classifier detected instruction-injection likelihood in metadata passed into model context.',
      assumptions: ['Local Prompt Guard 2 sidecar runs user-downloaded model weights locally.'],
      remediation: 'Inspect the flagged description and remove embedded directives or adversarial text.',
      limitations: ['Statistical classifier output; verify flagged spans manually.']
    }));
  }

  return { findings, diagnostics: [], incomplete: false };
}
