import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { explainScanResult } from '../dist/explain.js';
import { scanSource } from '../dist/scanner.js';
import { policyExit } from '../dist/policy.js';

test('explain validates schema, checks faithfulness, rejects hallucinated references, and preserves exit codes', async () => {
  const vuln = await scanSource('fixtures/vulnerable');
  const expectedExit = policyExit(vuln, 'medium');
  assert.equal(expectedExit, 1);
  const f0 = vuln.findings[0];
  const f1 = vuln.findings[1];

  const explained = await explainScanResult(vuln, {
    model: 'foundation-sec-8b',
    threshold: 'medium',
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        choices: [{
          message: {
            content: JSON.stringify({
              model: 'foundation-sec-8b',
              summary: 'Prioritized findings.',
              explanations: [
                {
                  fingerprint: f0.fingerprint,
                  priority: 1,
                  rationale: `Shell sink at ${f0.locations[0].file} line ${f0.locations[0].line}.`,
                  citedEvidence: [f0.evidence],
                  referencedFiles: [f0.locations[0].file],
                  referencedLines: [f0.locations[0].line],
                  referencedSymbols: ['exec']
                },
                {
                  fingerprint: f1.fingerprint,
                  priority: 2,
                  rationale: 'Hallucinated nonexistent.ts line 999.',
                  citedEvidence: [f1.evidence],
                  referencedFiles: ['nonexistent.ts'],
                  referencedLines: [999],
                  referencedSymbols: ['inventedFunction']
                }
              ]
            })
          }
        }]
      })
    })
  });

  assert.equal(explained.advisoryOnly, true);
  assert.equal(explained.exitCodeInvariant, true);
  assert.equal(explained.policyExitCode, expectedExit);
  assert.equal(explained.accepted.length, 1);
  assert.equal(explained.rejected.length, 1);
  assert.equal(explained.faithfulnessRate, 0.5);
  assert.ok(explained.rejected[0].reasons.some(r => r.includes('nonexistent.ts')));
});

test('explain preserves exit 0 and exit 3 identically without model calls when no findings', async () => {
  const clean = await scanSource('fixtures/corrected');
  const ambig = await scanSource('fixtures/ambiguous');
  const cleanExplained = await explainScanResult(clean, { threshold: 'medium' });
  assert.equal(cleanExplained.policyExitCode, policyExit(clean, 'medium'));
  assert.equal(cleanExplained.policyExitCode, 0);

  const ambigExplained = await explainScanResult(ambig, {
    threshold: 'medium',
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        model: 'foundation-sec-8b',
        summary: 'Incomplete scan with findings.',
        explanations: []
      })
    })
  });
  assert.equal(ambigExplained.policyExitCode, policyExit(ambig, 'medium'));
  assert.equal(ambigExplained.policyExitCode, 3);
});

test('explain rejects invalid JSON schema responses and CLI explain preserves exit 0 on clean scan', async t => {
  const vuln = await scanSource('fixtures/vulnerable');
  await assert.rejects(
    explainScanResult(vuln, {
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        json: async () => ({ bad: true })
      })
    }),
    /schema validation/
  );

  const dir = await mkdtemp(path.join(tmpdir(), 'vambrace-explain-cli-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const cleanPath = path.join(dir, 'clean.json');
  const clean = await scanSource('fixtures/corrected');
  await writeFile(cleanPath, JSON.stringify(clean));
  const res = spawnSync(process.execPath, ['dist/cli.js', 'explain', cleanPath, '--model', 'foundation-sec-8b'], { encoding: 'utf8', timeout: 15000 });
  assert.equal(res.status, 0);
  assert.equal(JSON.parse(res.stdout).policyExitCode, 0);
});
