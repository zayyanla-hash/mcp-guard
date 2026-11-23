import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { compilePolicyConfig } from '../dist/policy-compile.js';
import { loadPolicyFile, parsePolicyText, toolDescriptorHash } from '../dist/policy-file.js';

const lookupTool = {
  name: 'lookup',
  description: 'Look up a record by ID.',
  inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] }
};
const searchTool = {
  name: 'search',
  description: 'Search records.',
  inputSchema: { type: 'object', properties: { query: { type: 'string' } } }
};

test('vambrace.policy.yaml parser validates schema and rejects unsafe keys', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'vambrace-policy-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const h = toolDescriptorHash(lookupTool);
  const policyYaml = [
    'schemaVersion: 1',
    'threshold: medium',
    'allowedTools:',
    '  - lookup',
    'pinnedDescriptors:',
    `  lookup: ${h}`,
    'deniedCapabilities:',
    '  - shell',
    '  - poisoning',
    ''
  ].join('\n');
  const policyPath = path.join(dir, 'vambrace.policy.yaml');
  await writeFile(policyPath, policyYaml);
  const loaded = await loadPolicyFile(policyPath);
  assert.equal(loaded.schemaVersion, 1);
  assert.deepEqual(loaded.allowedTools, ['lookup']);
  assert.equal(loaded.pinnedDescriptors.lookup, h);
  assert.throws(() => parsePolicyText('__proto__:\n  polluted: true'), /Unsafe policy key/);
});

test('policy compile produces deterministic agentgateway config and blocks drifted tools', () => {
  const h = toolDescriptorHash(lookupTool);
  const policy = {
    schemaVersion: 1,
    threshold: 'medium',
    allowedTools: ['lookup'],
    pinnedDescriptors: { lookup: h },
    deniedCapabilities: ['shell']
  };
  const inv = { protocolVersion: '2026-07-28', tools: [searchTool, lookupTool] };
  const first = compilePolicyConfig(policy, inv, 'agentgateway');
  const second = compilePolicyConfig(policy, inv, 'agentgateway');
  assert.equal(first.content, second.content);
  assert.deepEqual(first.approvedTools, ['lookup']);
  assert.equal(first.blockedTools[0].name, 'search');
  assert.equal(first.blockedTools[0].reason, 'not-in-allowedTools');
  assert.equal(first.content, [
    '# Generated deterministically by vambrace policy compile --target agentgateway',
    'binds:',
    '  - port: 3000',
    '    listeners:',
    '      - routes:',
    '          - policies:',
    '              mcpAuthorization:',
    '                rules:',
    '                  - "mcp.tool.name in [\\"lookup\\"]"',
    '            backends:',
    '              - mcp:',
    '                  targets:',
    '                    - name: vambrace-protected-mcp',
    '                      mcp:',
    '                        host: fixture-server:3001',
    ''
  ].join('\n'));

  const driftedInv = {
    protocolVersion: '2026-07-28',
    tools: [{ ...lookupTool, description: 'Look up a record with changed schema/text' }, searchTool]
  };
  const drifted = compilePolicyConfig(policy, driftedInv, 'agentgateway');
  assert.deepEqual(drifted.approvedTools, []);
  assert.ok(drifted.blockedTools.some(b => b.name === 'lookup' && b.reason === 'descriptor-hash-mismatch'));
  assert.match(drifted.content, /- "false"/);

  const pins = compilePolicyConfig(policy, inv, 'mcp-context-protector');
  const parsedPins = JSON.parse(pins.content);
  assert.equal(parsedPins.format, 'mcp-context-protector-pins');
  assert.equal(parsedPins.pins.lookup.sha256, h);
});

test('CLI policy compile and --policy gate enforce policy file across audit and gateway compile', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'vambrace-policy-cli-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const h = toolDescriptorHash(lookupTool);
  const policyPath = path.join(dir, 'vambrace.policy.yaml');
  const invPath = path.join(dir, 'inv.json');
  const outPath = path.join(dir, 'agentgateway.yaml');
  await writeFile(policyPath, `schemaVersion: 1\nthreshold: high\nallowedTools:\n  - lookup\npinnedDescriptors:\n  lookup: ${h}\ndeniedCapabilities:\n  - filesystem\n`);
  await writeFile(invPath, JSON.stringify({ protocolVersion: '2026-07-28', tools: [lookupTool] }));

  const compiled = spawnSync(process.execPath, ['dist/cli.js', 'policy', 'compile', '--policy', policyPath, '--snapshot', invPath, '--target', 'agentgateway', '--out', outPath], { encoding: 'utf8', timeout: 15000 });
  assert.equal(compiled.status, 0, compiled.stderr);
  assert.match(await readFile(outPath, 'utf8'), /mcp\.tool\.name in/);

  // Threshold is high in policy, but deniedCapabilities includes filesystem (MG002 is medium), so audit must still exit 1!
  const auditGate = spawnSync(process.execPath, ['dist/cli.js', 'audit', 'fixtures/vulnerable', '--policy', policyPath], { encoding: 'utf8', timeout: 15000 });
  assert.equal(auditGate.status, 1);
});
