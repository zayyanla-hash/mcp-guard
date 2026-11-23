import { auditInventory } from './inventory.js';
import { checkInventoryAgainstPolicy, toolDescriptorHash, type VambracePolicy } from './policy-file.js';

export type CompileTarget = 'agentgateway' | 'mcp-context-protector';

export interface CompiledGatewayOutput {
  target: CompileTarget;
  approvedTools: string[];
  blockedTools: Array<{ name: string; reason: string; actualHash?: string; expectedHash?: string }>;
  content: string;
}

function extractInventoryPayload(snapshotOrInventory: unknown): Record<string, unknown> {
  if (!snapshotOrInventory || typeof snapshotOrInventory !== 'object' || Array.isArray(snapshotOrInventory)) {
    throw new Error('Snapshot or inventory input must be a JSON object.');
  }
  const obj = snapshotOrInventory as Record<string, unknown>;
  if (obj.kind === 'inventory-snapshot' && obj.payload && typeof obj.payload === 'object') {
    return obj.payload as Record<string, unknown>;
  }
  return obj;
}

export function compilePolicyConfig(
  policy: VambracePolicy,
  snapshotOrInventory: unknown,
  target: CompileTarget,
  options: { listenerPort?: number; backendHost?: string } = {}
): CompiledGatewayOutput {
  const payload = extractInventoryPayload(snapshotOrInventory);
  const audited = auditInventory(payload);
  if (!audited.coverage.complete || audited.findings.length > 0) {
    const firstIssue = audited.findings[0]?.observed ?? audited.coverage.diagnostics[0]?.message ?? 'inventory failed audit';
    throw new Error(`Refusing to compile policy from invalid or poisoned inventory: ${firstIssue}`);
  }

  const { approved, blocked } = checkInventoryAgainstPolicy(payload, policy);
  const port = options.listenerPort ?? 3000;
  const backendHost = options.backendHost ?? 'fixture-server:3001';

  if (target === 'agentgateway') {
    const celList = approved.map(t => JSON.stringify(t)).join(', ');
    const celExpr = approved.length > 0
      ? `mcp.tool.name in [${celList}]`
      : 'false';
    const yaml = [
      '# Generated deterministically by vambrace policy compile --target agentgateway',
      'binds:',
      `  - port: ${port}`,
      '    listeners:',
      '      - routes:',
      '          - policies:',
      '              mcpAuthorization:',
      '                rules:',
      `                  - ${JSON.stringify(celExpr)}`,
      '            backends:',
      '              - mcp:',
      '                  targets:',
      '                    - name: vambrace-protected-mcp',
      '                      mcp:',
      `                        host: ${backendHost}`,
      ''
    ].join('\n');
    return { target, approvedTools: approved, blockedTools: blocked, content: yaml };
  }

  // mcp-context-protector pin export (stretch goal)
  const tools = Array.isArray(payload.tools) ? payload.tools as Array<Record<string, unknown>> : [];
  const approvedSet = new Set(approved);
  const pins: Record<string, unknown> = {};
  for (const tool of [...tools].sort((a, b) => String(a.name ?? '').localeCompare(String(b.name ?? '')))) {
    if (!tool || typeof tool.name !== 'string' || !approvedSet.has(tool.name)) continue;
    pins[tool.name] = {
      sha256: toolDescriptorHash(tool),
      description: tool.description ?? '',
      inputSchema: tool.inputSchema ?? {}
    };
  }
  const pinDoc = {
    schemaVersion: 1,
    format: 'mcp-context-protector-pins',
    approvedTools: approved,
    blockedTools: blocked.map(b => ({ name: b.name, reason: b.reason })),
    pins
  };
  return { target, approvedTools: approved, blockedTools: blocked, content: JSON.stringify(pinDoc, null, 2) + '\n' };
}
