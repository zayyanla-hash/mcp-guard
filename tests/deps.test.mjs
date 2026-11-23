import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { scanDepsLockfile } from '../dist/deps.js';
import { policyExit } from '../dist/policy.js';

test('deps refuses network lookup without --allow-network and returns exit 3', async () => {
  const res = await scanDepsLockfile('npm-shrinkwrap.json');
  assert.equal(res.coverage.complete, false);
  assert.equal(policyExit(res), 3);
  assert.ok(res.coverage.diagnostics.some(d => d.code === 'NETWORK_OPT_IN_REQUIRED'));

  const cli = spawnSync(process.execPath, ['dist/cli.js', 'deps', 'npm-shrinkwrap.json', '--format', 'json'], { encoding: 'utf8', timeout: 15000 });
  assert.equal(cli.status, 3);
  assert.ok(JSON.parse(cli.stdout).coverage.diagnostics.some(d => d.code === 'NETWORK_OPT_IN_REQUIRED'));
});

test('deps normalizes mocked osv-scanner output with engine osv-scanner', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'vambrace-deps-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const lockfile = path.join(dir, 'package-lock.json');
  await writeFile(lockfile, '{"lockfileVersion":3,"packages":{}}');

  const sampleOsv = JSON.stringify({
    results: [
      {
        packages: [
          {
            package: { name: 'example-pkg', version: '1.2.3', ecosystem: 'npm' },
            vulnerabilities: [
              {
                id: 'GHSA-0000-0000-0001',
                summary: 'Prototype pollution in example-pkg',
                database_specific: { severity: 'HIGH' }
              }
            ]
          }
        ]
      }
    ]
  });

  const res = await scanDepsLockfile(lockfile, {
    allowNetwork: true,
    execImpl: () => {
      const err = new Error('exit 1');
      err.status = 1;
      err.stdout = sampleOsv;
      throw err;
    }
  });
  assert.equal(res.coverage.complete, true);
  assert.equal(res.findings.length, 1);
  assert.equal(res.findings[0].engine, 'osv-scanner');
  assert.equal(res.findings[0].ruleId, 'OSV');
  assert.equal(res.findings[0].severity, 'high');
  assert.equal(policyExit(res), 1);
});

test('deps fails closed when osv-scanner binary is missing', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'vambrace-deps-missing-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const lockfile = path.join(dir, 'package-lock.json');
  await writeFile(lockfile, '{}');

  const res = await scanDepsLockfile(lockfile, {
    allowNetwork: true,
    execImpl: () => {
      const err = new Error('not found');
      err.code = 'ENOENT';
      throw err;
    }
  });
  assert.equal(res.coverage.complete, false);
  assert.equal(policyExit(res), 3);
  assert.ok(res.coverage.diagnostics.some(d => d.code === 'OSV_SCANNER_UNAVAILABLE'));
});
