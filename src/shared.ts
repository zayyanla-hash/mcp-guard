import { createHash } from 'node:crypto';
import type { Coverage, Finding } from './types.js';
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical((value as Record<string, unknown>)[k])).join(',') + '}';
}
export const hash = (value: unknown) => createHash('sha256').update(canonical(value)).digest('hex');
export function redactText(value: string): string {
  return value.replace(/\b(?:FAKE_[A-Z0-9_]*(?:SECRET|TOKEN|KEY|CANARY)[A-Z0-9_]*|CANARY_[A-Z0-9_]+)\b/g, '[REDACTED]')
    .replace(/((?:api[_-]?key|password|secret|token)\s*[:=]\s*["'`])[^"'`\r\n]+/gi, '$1[REDACTED]')
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|sk-[A-Za-z0-9_-]{16,})\b/g, '[REDACTED]');
}
export function redact(value: unknown, depth = 0): unknown {
  if (depth > 64) return '[DEPTH LIMIT]';
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map(v => redact(v, depth + 1));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v]) => [k, /^(?:password|secret|token|api[_-]?key|authorization)$/i.test(k) ? '[REDACTED]' : redact(v, depth + 1)]));
  return value;
}
export const cleanTerminal = (text: string) => text.replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4,'0'));
export function coverage(rules: string[]): Coverage { return {complete:true,inspected:[],excluded:[],failed:[],truncated:[],recognizedTools:0,unresolvedHandlers:0,rulesApplied:rules,diagnostics:[]}; }
export function finding(input: Omit<Finding, 'fingerprint' | 'ruleVersion'>): Finding {
  const safe = {...input, evidence: redactText(input.evidence), ruleVersion:'1.1.0'};
  return {...safe, fingerprint: hash({ruleId:safe.ruleId,locations:safe.locations,observed:safe.observed})};
}
