import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { auditClientConfig } from '../dist/config-audit.js';
import { policyExit } from '../dist/policy.js';

const load = (name) => JSON.parse(readFileSync(new URL(`../fixtures/configs/${name}`, import.meta.url), 'utf8'));

for (const rule of ['MG008', 'MG009', 'MG010', 'MG011', 'MG012']) {
  const lower = rule.toLowerCase();
  test(`${rule} positive and negative config fixtures`, () => {
    const pos = auditClientConfig(load(`${lower}-positive.json`), `${lower}-positive.json`);
    assert.equal(pos.coverage.complete, true);
    assert.ok(pos.findings.some(f => f.ruleId === rule), `expected ${rule} finding`);
    assert.ok(pos.findings.every(f => f.engine === 'vambrace-config'));
    assert.equal(policyExit(pos), 1);

    const neg = auditClientConfig(load(`${lower}-negative.json`), `${lower}-negative.json`);
    assert.equal(neg.coverage.complete, true);
    assert.equal(neg.findings.length, 0, `expected zero findings on ${lower}-negative.json`);
    assert.equal(policyExit(neg), 0);
  });
}

test('MG008 redacts canary secret values and CLI config command works offline', () => {
  const pos = auditClientConfig(load('mg008-positive.json'), 'mg008-positive.json');
  const serialized = JSON.stringify(pos);
  assert.ok(!serialized.includes('FAKE_CANARY_TOKEN_VALUE'));
  assert.ok(!serialized.includes('FAKE_GITHUB_CANARY_SECRET'));

  const cli = spawnSync(process.execPath, ['dist/cli.js', 'config', 'fixtures/configs/mg012-positive.json', '--format', 'json'], { encoding: 'utf8', timeout: 15000 });
  assert.equal(cli.status, 1);
  assert.equal(JSON.parse(cli.stdout).findings[0].ruleId, 'MG012');

  const cleanCli = spawnSync(process.execPath, ['dist/cli.js', 'config', 'fixtures/configs/mg012-negative.json'], { encoding: 'utf8', timeout: 15000 });
  assert.equal(cleanCli.status, 0);
});
