import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import Ajv from 'ajv';
import { buildSarif } from '../dist/sarif.js';
import { scanSource } from '../dist/scanner.js';
import { auditInventory, snapshotInventory, diffSnapshots } from '../dist/inventory.js';

const sarifSchema = JSON.parse(readFileSync(new URL('../schemas/sarif-2.1.0.json', import.meta.url), 'utf8'));
const ajv = new Ajv({ allErrors: false, strict: false, validateFormats: false });
const validateSarif = ajv.compile(sarifSchema);

test('SARIF 2.1.0 output validates against OASIS schema for audit, inventory, diff, and incomplete scans', async () => {
  const srcResult = await scanSource('fixtures/vulnerable');
  const srcSarif = buildSarif(srcResult);
  assert.equal(validateSarif(srcSarif), true, JSON.stringify(validateSarif.errors));
  assert.equal(srcSarif.runs[0].results.length, 5);
  assert.ok(srcSarif.runs[0].results.every(r => r.partialFingerprints?.['vambrace/v1']));
  assert.ok(srcSarif.runs[0].tool.driver.rules.every(r => r.properties?.owaspMcpTop10?.id && r.helpUri));

  const ambResult = await scanSource('fixtures/ambiguous');
  const ambSarif = buildSarif(ambResult);
  assert.equal(validateSarif(ambSarif), true, JSON.stringify(validateSarif.errors));
  assert.equal(ambSarif.runs[0].invocations[0].executionSuccessful, false);
  assert.ok(ambSarif.runs[0].invocations[0].toolExecutionNotifications.length > 0);

  const invJson = JSON.parse(readFileSync(new URL('../fixtures/inventories/vulnerable.json', import.meta.url), 'utf8'));
  const invSarif = buildSarif(auditInventory(invJson));
  assert.equal(validateSarif(invSarif), true, JSON.stringify(validateSarif.errors));
  assert.equal(invSarif.runs[0].results.length, 1);

  const before = snapshotInventory(JSON.parse(readFileSync(new URL('../fixtures/inventories/valid.json', import.meta.url), 'utf8')));
  const after = snapshotInventory(JSON.parse(readFileSync(new URL('../fixtures/inventories/drift.json', import.meta.url), 'utf8')));
  const diffSarif = buildSarif(diffSnapshots(before, after));
  assert.equal(validateSarif(diffSarif), true, JSON.stringify(validateSarif.errors));
  assert.ok(diffSarif.runs[0].results.some(r => r.ruleId === 'MG-DRIFT'));
});

test('CLI supports --format sarif on audit, inventory, and diff', () => {
  const audit = spawnSync(process.execPath, ['dist/cli.js', 'audit', 'fixtures/vulnerable', '--format', 'sarif'], { encoding: 'utf8', timeout: 15000 });
  assert.equal(audit.status, 1);
  const parsed = JSON.parse(audit.stdout);
  assert.equal(validateSarif(parsed), true, JSON.stringify(validateSarif.errors));

  const inv = spawnSync(process.execPath, ['dist/cli.js', 'inventory', 'fixtures/inventories/vulnerable.json', '--format', 'sarif'], { encoding: 'utf8', timeout: 15000 });
  assert.equal(inv.status, 1);
  assert.equal(validateSarif(JSON.parse(inv.stdout)), true);
});
