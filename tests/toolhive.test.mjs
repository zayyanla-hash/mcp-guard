import test from 'node:test';
import assert from 'node:assert/strict';
import { IsolationBlocked } from '../dist/isolation.js';
import { verifyToolHiveEnvironment, discoverWithToolHive } from '../dist/toolhive.js';
import { discoverFixture } from '../dist/discovery.js';

test('ToolHive fails closed with IsolationBlocked when thv or container runtime is missing', async () => {
  assert.throws(() => verifyToolHiveEnvironment(() => { throw new Error('ENOENT'); }), IsolationBlocked);
  assert.throws(
    () => verifyToolHiveEnvironment((bin) => (bin === 'thv' ? 'v0.1.0' : (() => { throw new Error('daemon down'); })())),
    IsolationBlocked
  );
  await assert.rejects(discoverWithToolHive({ approved: false }), IsolationBlocked);
  await assert.rejects(discoverFixture({ approved: true, backend: 'toolhive', signal: AbortSignal.abort() }), IsolationBlocked);
});

test('ToolHive discovery acquires read-only tools/list inventory when verified', async () => {
  const env = verifyToolHiveEnvironment((bin) => (bin === 'thv' ? 'v0.1.0' : '27.0.0'));
  assert.equal(env.runtime, 'docker');

  const result = await discoverWithToolHive({
    approved: true,
    execImpl: (bin) => (bin === 'thv' ? 'v0.1.0' : '27.0.0'),
    listToolsFn: async () => ({
      serverInfo: { name: 'toolhive-reviewed', version: '1.0.0' },
      tools: [{ name: 'lookup', description: 'Lookup record', inputSchema: { type: 'object' } }],
      pageCount: 1
    })
  });
  assert.equal(result.inventory.metadata.isolation, 'toolhive-network-isolated-container');
  assert.equal(result.inventory.metadata.toolCalls, 0);
  assert.equal(result.inventory.metadata.resourceReads, 0);
  assert.equal(result.inventory.tools.length, 1);
});
