import { Ajv } from 'ajv';
import { constants, promises as fs, readFileSync } from 'node:fs';
import path from 'node:path';
import { hash } from './shared.js';
import type { AuditResult, Finding, Severity } from './types.js';

export interface VambracePolicy {
  schemaVersion: 1;
  threshold?: Severity;
  allowedTools: string[];
  pinnedDescriptors?: Record<string, string>;
  deniedCapabilities?: string[];
}

const MAX_POLICY_BYTES = 262_144;
const UNSAFE_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const schema = JSON.parse(readFileSync(new URL('../schemas/policy.schema.json', import.meta.url), 'utf8'));
const ajv = new Ajv({ allErrors: true, strict: false });
const validateSchema = ajv.compile<VambracePolicy>(schema);

function parseScalar(raw: string): unknown {
  const s = raw.trim();
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (s === 'null' || s === '~') return null;
  if (/^-?[0-9]+$/.test(s)) return Number(s);
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  if (s.startsWith('[') && s.endsWith(']')) {
    const inner = s.slice(1, -1).trim();
    if (!inner) return [];
    return inner.split(',').map(part => parseScalar(part));
  }
  return s;
}

function stripComment(line: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === '#' && !inSingle && !inDouble) return line.slice(0, i);
  }
  return line;
}

/** Parse a bounded, prototype-safe JSON or YAML policy document. */
export function parsePolicyText(text: string): unknown {
  const trimmed = text.trim();
  if (!trimmed) throw new Error('Policy file is empty.');
  if (trimmed.startsWith('{')) return JSON.parse(trimmed);

  const lines = trimmed.split(/\r?\n/).map(stripComment).filter(l => l.trim().length > 0);
  const root: Record<string, unknown> = Object.create(null);
  let currentKey: string | null = null;
  let currentMode: 'array' | 'map' | null = null;

  for (const rawLine of lines) {
    const indent = rawLine.search(/\S/);
    const content = rawLine.trim();

    if (indent === 0) {
      const colon = content.indexOf(':');
      if (colon === -1) throw new Error(`Invalid YAML policy line: ${content}`);
      const key = content.slice(0, colon).trim().replace(/^["']|["']$/g, '');
      if (UNSAFE_KEYS.has(key)) throw new Error(`Unsafe policy key: ${key}`);
      const rest = content.slice(colon + 1).trim();
      if (rest === '') {
        currentKey = key;
        currentMode = null;
      } else {
        root[key] = parseScalar(rest);
        currentKey = null;
        currentMode = null;
      }
      continue;
    }

    if (!currentKey) throw new Error(`Unexpected indented YAML line: ${content}`);
    if (content.startsWith('- ')) {
      if (currentMode === null) {
        currentMode = 'array';
        root[currentKey] = [];
      } else if (currentMode !== 'array') {
        throw new Error(`Mixed array and map items under "${currentKey}".`);
      }
      (root[currentKey] as unknown[]).push(parseScalar(content.slice(2)));
    } else {
      const colon = content.indexOf(':');
      if (colon === -1) throw new Error(`Invalid nested YAML line: ${content}`);
      if (currentMode === null) {
        currentMode = 'map';
        root[currentKey] = Object.create(null);
      } else if (currentMode !== 'map') {
        throw new Error(`Mixed map and array items under "${currentKey}".`);
      }
      const subKey = content.slice(0, colon).trim().replace(/^["']|["']$/g, '');
      if (UNSAFE_KEYS.has(subKey)) throw new Error(`Unsafe policy key: ${subKey}`);
      const subVal = content.slice(colon + 1).trim();
      (root[currentKey] as Record<string, unknown>)[subKey] = parseScalar(subVal);
    }
  }
  return JSON.parse(JSON.stringify(root));
}

export function validatePolicyObject(obj: unknown): VambracePolicy {
  if (!validateSchema(obj)) {
    throw new Error(`Invalid policy file: ${ajv.errorsText(validateSchema.errors)}`);
  }
  return obj as VambracePolicy;
}

export async function loadPolicyFile(policyPath: string): Promise<VambracePolicy> {
  const stat = await fs.lstat(policyPath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error('Policy path must be a regular non-symlink file.');
  }
  const fd = await fs.open(policyPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await fd.stat();
    if (opened.size > MAX_POLICY_BYTES) throw new Error(`Policy file exceeds ${MAX_POLICY_BYTES} bytes.`);
    const text = await fd.readFile('utf8');
    return validatePolicyObject(parsePolicyText(text));
  } finally {
    await fd.close();
  }
}

export function toolDescriptorHash(tool: Record<string, unknown>): string {
  const projected = {
    name: tool.name,
    ...(tool.description !== undefined ? { description: tool.description } : {}),
    ...(tool.inputSchema !== undefined ? { inputSchema: tool.inputSchema } : {}),
    ...(tool.outputSchema !== undefined ? { outputSchema: tool.outputSchema } : {}),
    ...(tool.annotations !== undefined ? { annotations: tool.annotations } : {})
  };
  return hash(projected);
}

const CAPABILITY_RULES: Record<string, string[]> = {
  shell: ['MG001', 'MG012'],
  filesystem: ['MG002', 'MG011'],
  network: ['MG003', 'MG010'],
  secrets: ['MG004', 'MG008'],
  poisoning: ['MG007'],
  contradiction: ['MG006'],
  supply_chain: ['MG009', 'OSV']
};

export function findingMatchesDeniedCapability(f: Finding, deniedCapabilities: string[] = []): boolean {
  for (const cap of deniedCapabilities) {
    const norm = cap.toLowerCase();
    if (f.ruleId.toLowerCase() === norm) return true;
    const mapped = CAPABILITY_RULES[norm];
    if (mapped?.includes(f.ruleId)) return true;
  }
  return false;
}

export function evaluatePolicyAgainstResult(
  result: AuditResult,
  policy: VambracePolicy,
  explicitThreshold?: Severity
): 0 | 1 | 3 {
  if (!result.coverage.complete) return 3;
  if (result.kind === 'diff' && result.changes?.length) return 1;
  const threshold = explicitThreshold ?? policy.threshold ?? 'medium';
  const levels: Record<Severity, number> = { low: 0, medium: 1, high: 2 };
  if (result.findings.some(f => levels[f.severity] >= levels[threshold])) return 1;
  if (result.findings.some(f => findingMatchesDeniedCapability(f, policy.deniedCapabilities))) return 1;
  return 0;
}

export function checkInventoryAgainstPolicy(inventory: unknown, policy: VambracePolicy): {
  approved: string[];
  blocked: Array<{ name: string; reason: string; actualHash?: string; expectedHash?: string }>;
} {
  const tools = (inventory && typeof inventory === 'object' && Array.isArray((inventory as Record<string, unknown>).tools))
    ? (inventory as Record<string, unknown>).tools as Array<Record<string, unknown>>
    : [];
  const allowedSet = new Set(policy.allowedTools);
  const pinned = policy.pinnedDescriptors;
  const approved: string[] = [];
  const blocked: Array<{ name: string; reason: string; actualHash?: string; expectedHash?: string }> = [];

  for (const tool of tools) {
    if (!tool || typeof tool.name !== 'string') continue;
    const name = tool.name;
    const actualHash = toolDescriptorHash(tool);
    if (!allowedSet.has(name)) {
      blocked.push({ name, reason: 'not-in-allowedTools', actualHash });
      continue;
    }
    if (pinned) {
      const expectedHash = pinned[name];
      if (!expectedHash) {
        blocked.push({ name, reason: 'missing-pinned-hash', actualHash });
        continue;
      }
      if (expectedHash !== actualHash) {
        blocked.push({ name, reason: 'descriptor-hash-mismatch', actualHash, expectedHash });
        continue;
      }
    }
    approved.push(name);
  }
  approved.sort();
  blocked.sort((a, b) => a.name.localeCompare(b.name));
  return { approved, blocked };
}
