import type { OwaspMcpRef } from './types.js';

export interface RuleMetadata {
  id: string;
  name: string;
  shortDescription: string;
  owaspMcpTop10: OwaspMcpRef;
}

const OWASP_MCP_URL = 'https://owasp.org/www-project-mcp-top-10/';

export const RULE_METADATA: Record<string, RuleMetadata> = {
  MG001: {
    id: 'MG001',
    name: 'ShellCommandInjection',
    shortDescription: 'Tool input reaches shell command construction or shell-enabled execution',
    owaspMcpTop10: { id: 'MCP05', title: 'Command Injection and Execution', url: OWASP_MCP_URL }
  },
  MG002: {
    id: 'MG002',
    name: 'UnboundedFilesystemPath',
    shortDescription: 'Tool input reaches filesystem paths without an established containment check',
    owaspMcpTop10: { id: 'MCP02', title: 'Privilege Escalation and Filesystem Access', url: OWASP_MCP_URL }
  },
  MG003: {
    id: 'MG003',
    name: 'UnrestrictedOutboundDestination',
    shortDescription: 'Tool input controls an outbound request URL without destination policy',
    owaspMcpTop10: { id: 'MCP06', title: 'Outbound Requests and SSRF Exposure', url: OWASP_MCP_URL }
  },
  MG004: {
    id: 'MG004',
    name: 'EnvironmentSecretExposure',
    shortDescription: 'Whole environment or explicit secret-bearing environment value reaches output',
    owaspMcpTop10: { id: 'MCP01', title: 'Token Mismanagement and Secret Exposure', url: OWASP_MCP_URL }
  },
  MG005: {
    id: 'MG005',
    name: 'InvalidToolDescriptor',
    shortDescription: 'Invalid MCP tool descriptor or JSON Schema structure',
    owaspMcpTop10: { id: 'MCP03', title: 'Tool Metadata Integrity and Validation', url: OWASP_MCP_URL }
  },
  MG006: {
    id: 'MG006',
    name: 'ReadOnlyDeclarationContradiction',
    shortDescription: 'Literal readOnlyHint:true declaration contradicts direct filesystem mutation',
    owaspMcpTop10: { id: 'MCP02', title: 'Privilege and Declaration Contradiction', url: OWASP_MCP_URL }
  },
  MG007: {
    id: 'MG007',
    name: 'ToolDescriptorInjection',
    shortDescription: 'Suspicious instruction, hidden control sequence, or exfiltration cue in tool metadata',
    owaspMcpTop10: { id: 'MCP03', title: 'Tool Poisoning', url: OWASP_MCP_URL }
  },
  MG008: {
    id: 'MG008',
    name: 'ClientConfigSecret',
    shortDescription: 'Hardcoded secret or credential in MCP client configuration env or args',
    owaspMcpTop10: { id: 'MCP01', title: 'Token Mismanagement and Secret Exposure', url: OWASP_MCP_URL }
  },
  MG009: {
    id: 'MG009',
    name: 'UnpinnedNpxPackage',
    shortDescription: 'MCP client configuration invokes npx -y without a pinned package version',
    owaspMcpTop10: { id: 'MCP04', title: 'Software Supply Chain Integrity', url: OWASP_MCP_URL }
  },
  MG010: {
    id: 'MG010',
    name: 'PlaintextHttpTransport',
    shortDescription: 'MCP client configuration uses unencrypted http:// transport URL',
    owaspMcpTop10: { id: 'MCP07', title: 'Insecure Transport and Authentication', url: OWASP_MCP_URL }
  },
  MG011: {
    id: 'MG011',
    name: 'BroadFilesystemRoot',
    shortDescription: 'MCP client configuration exposes root directory or full home directory',
    owaspMcpTop10: { id: 'MCP02', title: 'Excessive Scope and Privilege', url: OWASP_MCP_URL }
  },
  MG012: {
    id: 'MG012',
    name: 'ShellWrapperCommand',
    shortDescription: 'MCP client configuration launches server through an interactive or inline shell wrapper',
    owaspMcpTop10: { id: 'MCP05', title: 'Command Injection via Shell Wrappers', url: OWASP_MCP_URL }
  },
  OSV: {
    id: 'OSV',
    name: 'KnownDependencyVulnerability',
    shortDescription: 'Known vulnerability reported by OSV-Scanner on target lockfile',
    owaspMcpTop10: { id: 'MCP04', title: 'Software Supply Chain Vulnerabilities', url: OWASP_MCP_URL }
  },
  'MG-DRIFT': {
    id: 'MG-DRIFT',
    name: 'ToolInventoryDrift',
    shortDescription: 'Observable change in MCP tool descriptors or schemas across snapshots',
    owaspMcpTop10: { id: 'MCP03', title: 'Tool Poisoning and Rug-Pull Drift', url: OWASP_MCP_URL }
  }
};

export function ruleMeta(ruleId: string): RuleMetadata | undefined {
  return RULE_METADATA[ruleId];
}
