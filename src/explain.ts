import { Ajv } from 'ajv';
import { policyExit } from './policy.js';
import { validateResult } from './reporting.js';
import { redactText } from './shared.js';
import type { AuditResult, Finding, Severity } from './types.js';

export interface ExplainOptions {
  endpoint?: string;
  model?: string;
  threshold?: Severity;
  fetchImpl?: (
    url: string,
    init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal }
  ) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;
}

export interface ExplainEntry {
  fingerprint: string;
  priority: number;
  rationale: string;
  citedEvidence: string[];
  referencedFiles: string[];
  referencedLines: number[];
  referencedSymbols: string[];
}

export interface ExplainResponse {
  model: string;
  summary: string;
  explanations: ExplainEntry[];
}

export interface FaithfulnessRejection {
  fingerprint: string;
  reasons: string[];
}

export interface ExplainResult {
  advisoryOnly: true;
  exitCodeInvariant: true;
  policyExitCode: 0 | 1 | 3;
  model: string;
  endpoint: string;
  summary: string;
  accepted: ExplainEntry[];
  rejected: FaithfulnessRejection[];
  faithfulnessRate: number | null;
}

const EXPLAIN_JSON_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['model', 'summary', 'explanations'],
  properties: {
    model: { type: 'string', minLength: 1 },
    summary: { type: 'string' },
    explanations: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['fingerprint', 'priority', 'rationale', 'citedEvidence', 'referencedFiles', 'referencedLines', 'referencedSymbols'],
        properties: {
          fingerprint: { type: 'string', minLength: 1 },
          priority: { type: 'integer', minimum: 1 },
          rationale: { type: 'string', minLength: 1 },
          citedEvidence: { type: 'array', items: { type: 'string' } },
          referencedFiles: { type: 'array', items: { type: 'string' } },
          referencedLines: { type: 'array', items: { type: 'integer', minimum: 1 } },
          referencedSymbols: { type: 'array', items: { type: 'string' } }
        }
      }
    }
  }
};

const ajv = new Ajv({ allErrors: true, strict: false });
const validateExplainSchema = ajv.compile<ExplainResponse>(EXPLAIN_JSON_SCHEMA);

function verifyEntryFaithfulness(entry: ExplainEntry, byFp: Map<string, Finding>): string[] {
  const reasons: string[] = [];
  const finding = byFp.get(entry.fingerprint);
  if (!finding) {
    reasons.push(`Unknown finding fingerprint "${entry.fingerprint}".`);
    return reasons;
  }

  const allowedFiles = new Set(finding.locations.map(l => l.file).filter((x): x is string => Boolean(x)));
  const allowedBasenames = new Set([...allowedFiles].map(f => f.split('/').pop()!));
  const allowedLines = new Set(finding.locations.map(l => l.line).filter((x): x is number => typeof x === 'number'));
  const evidenceCorpus = `${finding.evidence}\n${finding.observed}\n${finding.title}\n${finding.locations.map(l => l.pointer ?? '').join('\n')}`;

  for (const file of entry.referencedFiles) {
    if (!allowedFiles.has(file) && !allowedBasenames.has(file)) {
      reasons.push(`Referenced file "${file}" is absent from cited finding locations.`);
    }
  }

  for (const line of entry.referencedLines) {
    if (!allowedLines.has(line)) {
      reasons.push(`Referenced line ${line} is absent from cited finding locations.`);
    }
  }

  for (const sym of entry.referencedSymbols) {
    if (sym && !evidenceCorpus.includes(sym)) {
      reasons.push(`Referenced symbol "${sym}" is absent from cited finding evidence.`);
    }
  }

  // Also check explicit file/line mentions embedded in rationale prose
  const fileMentions = entry.rationale.match(/\b[A-Za-z0-9_.-]+\.(?:ts|mts|js|mjs|py|json)\b/g) ?? [];
  for (const fm of fileMentions) {
    if (!allowedFiles.has(fm) && !allowedBasenames.has(fm)) {
      reasons.push(`Prose mentions file "${fm}" absent from cited finding.`);
    }
  }

  const lineMentions = [...entry.rationale.matchAll(/\bline\s+([0-9]+)\b/gi)].map(m => Number(m[1]));
  for (const lm of lineMentions) {
    if (!allowedLines.has(lm)) {
      reasons.push(`Prose mentions line ${lm} absent from cited finding.`);
    }
  }

  return reasons;
}

export async function explainScanResult(rawScan: unknown, options: ExplainOptions = {}): Promise<ExplainResult> {
  const scan = validateResult(rawScan);
  const threshold = options.threshold ?? 'medium';
  const invariantExit = policyExit(scan, threshold);
  const endpoint = options.endpoint ?? 'http://127.0.0.1:11434/v1/chat/completions';
  const model = options.model ?? 'foundation-sec-8b';

  if (scan.findings.length === 0) {
    return {
      advisoryOnly: true,
      exitCodeInvariant: true,
      policyExitCode: invariantExit,
      model,
      endpoint,
      summary: 'No findings to explain; policy exit code unchanged.',
      accepted: [],
      rejected: [],
      faithfulnessRate: null
    };
  }

  const fetchImpl = options.fetchImpl ?? (globalThis.fetch as unknown as NonNullable<ExplainOptions['fetchImpl']>);
  const redactedFindings = scan.findings.map(f => ({
    fingerprint: f.fingerprint,
    ruleId: f.ruleId,
    severity: f.severity,
    title: f.title,
    locations: f.locations,
    evidence: redactText(f.evidence),
    observed: redactText(f.observed)
  }));

  const prompt = [
    'You are an advisory security triage assistant. Rank and explain only the provided Vambrace findings.',
    'Respond with strict JSON matching keys: model, summary, explanations[].',
    'Each explanation MUST cite an exact fingerprint, referencedFiles, referencedLines, and referencedSymbols present in that finding.',
    JSON.stringify({ target: scan.target, findings: redactedFindings })
  ].join('\n');

  const response = await fetchImpl(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      model,
      temperature: 0,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: 'Return strict JSON only. Never invent files, lines, or symbols not present in the finding.' },
        { role: 'user', content: prompt }
      ]
    }),
    signal: AbortSignal.timeout(30_000)
  });

  if (!response.ok) {
    throw new Error(`Explain endpoint returned HTTP ${response.status}`);
  }
  const rawBody = (await response.json()) as Record<string, unknown>;
  let candidate: unknown = rawBody;
  if (Array.isArray(rawBody.choices) && rawBody.choices[0] && typeof rawBody.choices[0] === 'object') {
    const choice = rawBody.choices[0] as Record<string, unknown>;
    const msg = choice.message as Record<string, unknown> | undefined;
    if (msg && typeof msg.content === 'string') {
      candidate = JSON.parse(msg.content);
    }
  }

  if (!validateExplainSchema(candidate)) {
    throw new Error(`Explain response failed JSON schema validation: ${ajv.errorsText(validateExplainSchema.errors)}`);
  }
  const validated = candidate as ExplainResponse;

  const byFp = new Map<string, Finding>(scan.findings.map(f => [f.fingerprint, f]));
  const accepted: ExplainEntry[] = [];
  const rejected: FaithfulnessRejection[] = [];

  for (const entry of validated.explanations) {
    const reasons = verifyEntryFaithfulness(entry, byFp);
    if (reasons.length === 0) accepted.push(entry);
    else rejected.push({ fingerprint: entry.fingerprint, reasons });
  }

  accepted.sort((a, b) => a.priority - b.priority);
  const total = accepted.length + rejected.length;
  return {
    advisoryOnly: true,
    exitCodeInvariant: true,
    policyExitCode: invariantExit,
    model: validated.model || model,
    endpoint,
    summary: redactText(validated.summary),
    accepted,
    rejected,
    faithfulnessRate: total > 0 ? Number((accepted.length / total).toFixed(4)) : null
  };
}
