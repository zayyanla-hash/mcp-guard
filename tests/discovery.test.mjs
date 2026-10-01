import test from 'node:test';
import assert from 'node:assert/strict';
import {IsolationBlocked} from '../dist/isolation.js';
import { discoverFixture, discoverFixtureTestMode } from '../dist/discovery.js';
import { auditInventory } from '../dist/inventory.js';

test('discovery is disabled before launching unless explicitly approved', async () => {
  await assert.rejects(discoverFixture(), /Discovery is disabled/);
});

test('approved reviewed fixture returns a pinned read-only tools inventory', async () => {
  if(process.platform!=='darwin'){await assert.rejects(discoverFixture({approved:true}),IsolationBlocked);return;}
  const result = await discoverFixture({ approved: true });
  assert.equal(result.inventory.protocolVersion, '2026-07-28');
  assert.equal(result.inventory.acquisitionContext.transport, 'stdio');
  assert.equal(result.inventory.acquisitionContext.authorization, 'none');
  assert.equal(result.inventory.acquisitionContext.source, 'reviewed built-in project fixture');
  assert.equal(result.inventory.tools.length, 1);
  assert.equal(result.inventory.tools[0].name, 'lookup');
  assert.deepEqual(result.diagnostics, []);
  const audit = auditInventory(result.inventory);
  assert.equal(audit.coverage.complete, true);
  assert.deepEqual(audit.findings, []);
});

test('startup timeout, repeated cursor, server request, version mismatch, and large frame fail closed', async t => {
  if(process.platform!=='darwin'){await assert.rejects(discoverFixtureTestMode('timeout'),IsolationBlocked);return;}
  const cases = [
    ['timeout', /timed out|timeout|exceed/i],
    ['cursor-loop', /repeated.*cursor/i],
    ['server-request', /unsolicited server request/i],
    ['protocol-mismatch', /negotiat|protocol/i],
    ['large-response', /buffer|byte|size|exceed/i],
  ];
  for (const [mode, expected] of cases) {
    await t.test(mode, async () => {
      await assert.rejects(discoverFixtureTestMode(mode), expected);
    });
  }
});

test('CLI approval produces snapshot-ready recorded inventory without accepting arbitrary targets',async()=>{
 const {spawnSync}=await import('node:child_process');const {mkdtemp,readFile,rm}=await import('node:fs/promises');const {tmpdir}=await import('node:os');const path=await import('node:path');
 const temp=await mkdtemp(path.join(tmpdir(),'guard-discovery-cli-'));const inventory=path.join(temp,'tools.json');
 try{
  const run=(...args)=>spawnSync(process.execPath,['dist/cli.js',...args],{encoding:'utf8',timeout:10000});
  const acquired=run('discover','--fixture','reviewed','--approve-execution','--format','json','--inventory-out',inventory);
  if(process.platform!=='darwin'){assert.equal(acquired.status,3);return;}
  assert.equal(acquired.status,0,acquired.stderr);assert.match(acquired.stderr,/Approved executable\/arguments:/);
  assert.equal(JSON.parse(acquired.stdout).coverage.complete,true);
  const value=JSON.parse(await readFile(inventory,'utf8'));assert.equal(value.protocolVersion,'2026-07-28');assert.equal(value.tools[0].name,'lookup');
  assert.equal(run('snapshot',inventory,'--out',path.join(temp,'snapshot.json')).status,0);
  assert.equal(run('discover','--fixture','arbitrary','--approve-execution').status,3);
  assert.equal(run('discover','--fixture','reviewed','--format','json').status,3);
 }finally{await rm(temp,{recursive:true,force:true});}
});
