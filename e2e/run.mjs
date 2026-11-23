import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { diffSnapshots, snapshotInventory } from '../dist/inventory.js';
import { compilePolicyConfig } from '../dist/policy-compile.js';
import { toolDescriptorHash } from '../dist/policy-file.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const artifacts = path.join(here, 'artifacts');
const composeFile = path.join(here, 'docker-compose.yml');
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
    { ...approvedTool, description: 'Look up a record by ID (revised description).' },
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

function compose(args, extraEnv = {}) {
  return execFileSync('docker', ['compose', '-f', composeFile, ...args], {
    encoding: 'utf8',
    env: { ...process.env, ...extraEnv }
  });
}

async function discoverLiveInventory(url = 'http://127.0.0.1:3001/mcp') {
  let lastErr;
  for (let i = 0; i < 30; i++) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      const tools = json?.result?.tools;
      if (!Array.isArray(tools)) throw new Error('tools/list returned no tools array');
      return { protocolVersion: '2026-07-28', tools };
    } catch (err) {
      lastErr = err;
      await new Promise(r => setTimeout(r, 200));
    }
  }
  throw lastErr;
}

function runClientPhase(label, driftMode, expectLookup) {
  compose(['up', '-d', '--force-recreate', 'agentgateway'], { DRIFT_MODE: driftMode });
  const clientOut = compose(['run', '--rm', '--no-deps', '-T', '-e', `EXPECT_LOOKUP=${expectLookup}`, 'test-client'], {
    DRIFT_MODE: driftMode,
    EXPECT_LOOKUP: expectLookup
  });
  const gwLogs = compose(['logs', '--no-color', 'agentgateway'], { DRIFT_MODE: driftMode });
  return { label, expectLookup, clientResult: JSON.parse(clientOut), gatewayLogs: gwLogs };
}

if (process.argv.includes('--live')) {
  try {
    compose(['down', '--remove-orphans']);

    // Phase 1: Baseline discovery, approve lookup, compile, verify lookup allowed and search blocked
    compose(['up', '-d', '--force-recreate', 'fixture-server'], { DRIFT_MODE: '0' });
    const phase1Inv = await discoverLiveInventory();
    const phase1Snap = snapshotInventory(phase1Inv);
    writeFileSync(path.join(artifacts, 'snapshot-baseline.json'), JSON.stringify(phase1Snap, null, 2));
    const lookupPhase1 = phase1Inv.tools.find(t => t.name === 'lookup');
    const phase1Policy = {
      ...policy,
      pinnedDescriptors: { lookup: toolDescriptorHash(lookupPhase1) }
    };
    const phase1Compiled = compilePolicyConfig(phase1Policy, phase1Snap, 'agentgateway');
    if (!phase1Compiled.approvedTools.includes('lookup')) {
      throw new Error('Phase 1 expected lookup to be approved.');
    }
    writeFileSync(path.join(artifacts, 'agentgateway.yaml'), phase1Compiled.content);
    const phase1Run = runClientPhase('phase1-baseline-approved', '0', 'allow');

    // Phase 2: Change lookup description, re-discover, snapshot, recompile with old pin -> descriptor-hash-mismatch -> blocked
    compose(['up', '-d', '--force-recreate', 'fixture-server'], { DRIFT_MODE: '1' });
    const phase2Inv = await discoverLiveInventory();
    const phase2Snap = snapshotInventory(phase2Inv);
    writeFileSync(path.join(artifacts, 'snapshot-drifted.json'), JSON.stringify(phase2Snap, null, 2));
    const driftDiff = diffSnapshots(phase1Snap, phase2Snap);
    if (!driftDiff.changes?.length) {
      throw new Error('Phase 2 expected diffSnapshots to detect descriptor change.');
    }
    const phase2Compiled = compilePolicyConfig(phase1Policy, phase2Snap, 'agentgateway');
    const mismatchEntry = phase2Compiled.blockedTools.find(b => b.name === 'lookup' && b.reason === 'descriptor-hash-mismatch');
    if (phase2Compiled.approvedTools.length !== 0 || !mismatchEntry) {
      throw new Error('Phase 2 expected lookup to be blocked with descriptor-hash-mismatch.');
    }
    writeFileSync(path.join(artifacts, 'agentgateway.yaml'), phase2Compiled.content);
    const phase2Run = runClientPhase('phase2-drifted-blocked', '1', 'block');

    // Phase 3: Approve new drifted snapshot, recompile -> lookup allowed again
    const lookupPhase3 = phase2Inv.tools.find(t => t.name === 'lookup');
    const phase3Policy = {
      ...phase1Policy,
      pinnedDescriptors: { lookup: toolDescriptorHash(lookupPhase3) }
    };
    const phase3Compiled = compilePolicyConfig(phase3Policy, phase2Snap, 'agentgateway');
    if (!phase3Compiled.approvedTools.includes('lookup')) {
      throw new Error('Phase 3 expected lookup to be re-approved.');
    }
    writeFileSync(path.join(artifacts, 'agentgateway.yaml'), phase3Compiled.content);
    const phase3Run = runClientPhase('phase3-reapproved-allowed', '1', 'allow');

    console.log(JSON.stringify({
      phase1: { approvedTools: phase1Compiled.approvedTools, snapshotHash: phase1Snap.hash, clientResult: phase1Run.clientResult },
      phase2: { driftObserved: (driftDiff.changes?.length ?? 0) > 0, changes: driftDiff.changes, approvedTools: phase2Compiled.approvedTools, blockedTools: phase2Compiled.blockedTools, snapshotHash: phase2Snap.hash, clientResult: phase2Run.clientResult },
      phase3: { approvedTools: phase3Compiled.approvedTools, clientResult: phase3Run.clientResult }
    }, null, 2));
    for (const r of [phase1Run, phase2Run, phase3Run]) {
      console.log(`=== GATEWAY LOGS (${r.label}) ===`);
      console.log(r.gatewayLogs.trimEnd());
    }
  } finally {
    try {
      compose(['down', '--remove-orphans']);
    } catch { /* best-effort teardown */ }
  }
} else {
  console.log(JSON.stringify({
    initialApproved: initialCompiled.approvedTools,
    driftedApproved: driftedCompiled.approvedTools,
    driftedBlocked: driftedCompiled.blockedTools
  }, null, 2));
}
