import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { auditInventory, snapshotInventory, diffSnapshots } from '../dist/inventory.js';
import { policyExit } from '../dist/policy.js';

const load = (name) => JSON.parse(readFileSync(new URL(`../fixtures/descriptions/${name}`, import.meta.url), 'utf8'));

test('MG007 flags poisoned directives, hidden unicode, ANSI escapes, HTML comments, sensitive paths, URLs, and cross-tool refs with exact offsets', () => {
  const res = auditInventory(load('poisoned.json'));
  assert.equal(res.coverage.complete, true);
  assert.equal(policyExit(res), 1);
  const mg007 = res.findings.filter(f => f.ruleId === 'MG007');
  assert.ok(mg007.length >= 7, `expected >= 7 MG007 findings, got ${mg007.length}`);
  assert.ok(mg007.every(f => f.engine === 'vambrace-inventory'));
  assert.ok(mg007.every(f => /offset=\d+:\d+ span=/.test(f.evidence)));
  assert.ok(mg007.some(f => f.locations[0].pointer === '/instructions'));
  assert.ok(mg007.some(f => f.locations[0].pointer === '/tools/0/description'));
  assert.ok(mg007.some(f => f.observed.includes('hidden-unicode')));
  assert.ok(mg007.some(f => f.observed.includes('ansi-escape')));
  assert.ok(mg007.some(f => f.observed.includes('html-comment')));
  assert.ok(mg007.some(f => f.observed.includes('sensitive-path')));
  assert.ok(mg007.some(f => f.observed.includes('exfiltration-url')));
  assert.ok(mg007.some(f => f.observed.includes('cross-tool reference')));
});

test('MG007 stays quiet on benign descriptions and server instructions', () => {
  const res = auditInventory(load('benign.json'));
  assert.equal(res.coverage.complete, true);
  assert.deepEqual(res.findings, []);
  assert.equal(policyExit(res), 0);
});

test('diffSnapshots --ignore-order compares tools order-insensitively', () => {
  const a = snapshotInventory({ tools: [{ name: 'alpha', inputSchema: {} }, { name: 'beta', inputSchema: {} }] });
  const b = snapshotInventory({ tools: [{ name: 'beta', inputSchema: {} }, { name: 'alpha', inputSchema: {} }] });
  assert.ok(diffSnapshots(a, b).changes.some(c => c.kind === 'tool-order-changed'));
  assert.ok(!diffSnapshots(a, b, { ignoreOrder: true }).changes.some(c => c.kind === 'tool-order-changed'));
});
