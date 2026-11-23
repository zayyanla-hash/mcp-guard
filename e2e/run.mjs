import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compilePolicyConfig } from '../dist/policy-compile.js';
import { toolDescriptorHash } from '../dist/policy-file.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const artifacts = path.join(here, 'artifacts');
mkdirSync(artifacts, { recursive: true });

const approvedTool = {
  name: 'lookup',
  description: 'Look up a record by ID.',
  inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] }
};
const searchTool = {
  name: 'search',
  description: 'Search records.',
  inputSchema: { type: 'object', properties: { query: { type: 'string' } } }
};

const baselineInventory = {
  protocolVersion: '2026-07-28',
  tools: [approvedTool, searchTool]
};
const driftedInventory = {
  protocolVersion: '2026-07-28',
  tools: [
    { ...approvedTool, description: 'Look up a record by ID (unexpectedly modified descriptor).' },
    searchTool
  ]
};

const policy = {
  schemaVersion: 1,
  threshold: 'medium',
  allowedTools: ['lookup'],
  pinnedDescriptors: {
    lookup: toolDescriptorHash(approvedTool)
  },
  deniedCapabilities: ['shell', 'poisoning']
};

const initialCompiled = compilePolicyConfig(policy, baselineInventory, 'agentgateway');
const driftedCompiled = compilePolicyConfig(policy, driftedInventory, 'agentgateway');

writeFileSync(path.join(artifacts, 'agentgateway.yaml'), initialCompiled.content);
writeFileSync(path.join(artifacts, 'agentgateway.drifted.yaml'), driftedCompiled.content);

if (!initialCompiled.approvedTools.includes('lookup')) {
  throw new Error('Expected lookup to be approved initially.');
}
if (driftedCompiled.approvedTools.length !== 0 || driftedCompiled.blockedTools.every(b => b.reason !== 'descriptor-hash-mismatch')) {
  throw new Error('Expected drifted lookup tool to be dropped from compiled allowlist.');
}

if (process.argv.includes('--live')) {
  execFileSync('docker', ['compose', '-f', path.join(here, 'docker-compose.yml'), 'up', '--abort-on-container-exit'], { stdio: 'inherit' });
}

console.log(JSON.stringify({
  initialApproved: initialCompiled.approvedTools,
  driftedApproved: driftedCompiled.approvedTools,
  driftedBlocked: driftedCompiled.blockedTools
}, null, 2));
