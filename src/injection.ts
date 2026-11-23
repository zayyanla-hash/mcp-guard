import { cleanTerminal, finding } from './shared.js';
import type { Finding } from './types.js';

type Obj = Record<string, unknown>;
const isObject = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);

interface InjectionPattern {
  kind: string;
  severity: Finding['severity'];
  regex: RegExp;
  title: string;
  why: string;
  remediation: string;
}

const PATTERNS: InjectionPattern[] = [
  {
    kind: 'model-directive',
    severity: 'high',
    regex: /\b(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?|disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions?|override\s+(?:system|developer|user)\s+(?:instructions?|prompt)|you\s+must\s+(?:always|never)|do\s+not\s+(?:tell|inform|mention\s+to)\s+the\s+user|before\s+(?:calling|using|running)\s+(?:any\s+)?(?:other\s+)?tool|instead\s+of\s+telling\s+the\s+user|secretly\s+(?:read|send|exfiltrate|append|pass))\b|<\/?(?:IMPORTANT|INSTRUCTIONS|SYSTEM|SECRET)\b[^>]*>/gi,
    title: 'Model-directed directive in tool metadata',
    why: 'Embedded imperatives or instruction tags inside tool descriptions can steer an LLM into unintended actions.',
    remediation: 'Remove imperative prompt-steering instructions and hidden instruction tags from tool descriptions.'
  },
  {
    kind: 'hidden-unicode',
    severity: 'high',
    regex: /[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]+/g,
    title: 'Hidden zero-width or bidirectional Unicode in tool metadata',
    why: 'Invisible zero-width or bidi override characters can conceal instructions from human reviewers while remaining visible to models.',
    remediation: 'Strip invisible zero-width and bidirectional formatting characters from tool descriptions and instructions.'
  },
  {
    kind: 'ansi-escape',
    severity: 'high',
    regex: /\x1b\[[0-9;?]*[A-Za-z]|\x9b[0-9;?]*[A-Za-z]/g,
    title: 'ANSI escape sequence in tool metadata',
    why: 'ANSI control sequences in tool descriptors can spoof terminal output or conceal instructions.',
    remediation: 'Remove ANSI escape sequences from tool descriptions and instructions.'
  },
  {
    kind: 'html-comment',
    severity: 'medium',
    regex: /<!--[\s\S]*?-->/g,
    title: 'Hidden HTML comment in tool metadata',
    why: 'HTML comments may be hidden in rendered markdown UIs while still fed into LLM context windows.',
    remediation: 'Remove HTML comments from MCP tool descriptions and server instructions.'
  },
  {
    kind: 'sensitive-path',
    severity: 'high',
    regex: /(?:~\/\.ssh(?:\/[^\s"'`)]*)?|\/\.ssh\/[^\s"'`)]*|\/etc\/(?:passwd|shadow|sudoers)\b|(?<![A-Za-z0-9_])\.env(?:\.[A-Za-z0-9_-]+)?\b|~\/\.aws\/credentials\b|~\/\.kube\/config\b|\bid_(?:rsa|ed25519)\b)/gi,
    title: 'Sensitive credential path referenced in tool metadata',
    why: 'Mentioning sensitive credential files such as ~/.ssh or .env in tool metadata is a common tool-poisoning exfiltration cue.',
    remediation: 'Remove references to local secret files from tool descriptions and validate necessity.'
  },
  {
    kind: 'exfiltration-url',
    severity: 'medium',
    regex: /https?:\/\/[^\s"'<>)\]]+/gi,
    title: 'External URL referenced in tool metadata',
    why: 'URLs embedded in tool descriptions can act as exfiltration endpoints or covert instructions.',
    remediation: 'Move documentation links to explicit metadata fields or verify that embedded URLs are strictly benign.'
  }
];

function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function visibleSpan(raw: string): string {
  const escaped = raw.replace(/[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]/g, c =>
    `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`
  );
  return cleanTerminal(escaped);
}

export function scanDescriptionText(
  text: string,
  pointer: string,
  currentTool: string | undefined,
  allToolNames: string[],
  targetFile?: string
): Finding[] {
  const findings: Finding[] = [];
  const loc = targetFile ? [{ file: targetFile, pointer }] : [{ pointer }];

  for (const pat of PATTERNS) {
    pat.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pat.regex.exec(text)) !== null) {
      const start = m.index;
      const end = m.index + m[0].length;
      const span = visibleSpan(m[0]);
      findings.push(finding({
        engine: 'vambrace-inventory',
        ruleId: 'MG007',
        title: pat.title,
        category: 'tool-poisoning',
        severity: pat.severity,
        confidence: 'high',
        evidenceType: 'metadata-observation',
        locations: loc,
        evidence: `offset=${start}:${end} span=${JSON.stringify(span)}`,
        observed: `Detected ${pat.kind} at offset ${start}..${end} in ${pointer}${currentTool ? ` (tool: ${currentTool})` : ''}.`,
        why: pat.why,
        assumptions: ['Tool descriptions and server instructions are passed into model context.'],
        remediation: pat.remediation,
        limitations: ['Deterministic pattern checks may miss novel natural-language phrasing without known markers.']
      }));
      if (m[0].length === 0) pat.regex.lastIndex++;
    }
  }

  for (const other of allToolNames) {
    if (!other || other === currentTool || other.length < 3) continue;
    const escaped = escapeRegex(other);
    const hasIdentifierShape = /[_-]|[a-z][A-Z]/.test(other);
    const re = hasIdentifierShape
      ? new RegExp(`(?<![A-Za-z0-9_-])${escaped}(?![A-Za-z0-9_-])`, 'g')
      : new RegExp(`\`${escaped}\`|\\b(?:call|invoke|run|trigger|execute|chain|via|to|instead\\s+of)\\s+${escaped}\\b|\\b${escaped}\\(\\)`, 'gi');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const start = m.index;
      const end = m.index + m[0].length;
      findings.push(finding({
        engine: 'vambrace-inventory',
        ruleId: 'MG007',
        title: 'Cross-tool reference in tool metadata',
        category: 'tool-poisoning',
        severity: 'high',
        confidence: 'high',
        evidenceType: 'metadata-observation',
        locations: loc,
        evidence: `offset=${start}:${end} span=${JSON.stringify(visibleSpan(m[0]))}`,
        observed: `Detected cross-tool reference to "${other}" at offset ${start}..${end} in ${pointer}.`,
        why: 'Descriptions referencing other tools can hijack cross-tool invocation or exfiltrate data across tools.',
        assumptions: ['Each tool description should describe only its own behavior.'],
        remediation: `Remove cross-tool invocation cues referencing "${other}" from ${pointer}.`,
        limitations: ['Identifies explicit tool-name mentions and invocation cues.']
      }));
      if (m[0].length === 0) re.lastIndex++;
    }
  }

  return findings;
}

export function auditDescriptions(inventory: Obj, targetFile?: string): Finding[] {
  const findings: Finding[] = [];
  const tools = Array.isArray(inventory.tools) ? inventory.tools : [];
  const allNames = tools
    .filter(isObject)
    .map(t => (typeof t.name === 'string' ? t.name : ''))
    .filter(Boolean);

  if (typeof inventory.instructions === 'string') {
    findings.push(...scanDescriptionText(inventory.instructions, '/instructions', undefined, allNames, targetFile));
  }
  if (isObject(inventory.serverInfo) && typeof inventory.serverInfo.instructions === 'string') {
    findings.push(...scanDescriptionText(inventory.serverInfo.instructions, '/serverInfo/instructions', undefined, allNames, targetFile));
  }

  for (let i = 0; i < tools.length; i++) {
    const tool = tools[i];
    if (!isObject(tool) || typeof tool.description !== 'string') continue;
    const name = typeof tool.name === 'string' ? tool.name : undefined;
    findings.push(...scanDescriptionText(tool.description, `/tools/${i}/description`, name, allNames, targetFile));
  }
  return findings;
}
