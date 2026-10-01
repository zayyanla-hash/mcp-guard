import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, mkdir, symlink } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
const cli=path.resolve('dist/cli.js');
const run=(...args)=>spawnSync(process.execPath,[cli,...args],{encoding:'utf8',timeout:15000});
test('help and version identify the working CLI',()=>{
 const help=run('--help');assert.equal(help.status,0);assert.match(help.stdout,/audit <directory>/);assert.match(help.stdout,/never executes targets/);
 const version=run('--version');assert.equal(version.status,0);assert.equal(version.stdout.trim(),'0.1.0');
});
test('invalid commands and flags fail with exit 2',()=>{
 for(const args of [['bogus'],['audit'],['audit','fixtures/corrected','--policy','anything'],['audit','fixtures/corrected','--threshold','safe'],['snapshot','fixtures/inventories/valid.json']]){
 const result=run(...args);assert.equal(result.status,2);assert.match(result.stderr,/Error:/);}
});
test('source finding, corrected control and incomplete coverage have distinct exits',()=>{
 const risky=run('audit','fixtures/vulnerable','--format','json');assert.equal(risky.status,1);const scan=JSON.parse(risky.stdout);assert.equal(scan.findings.length,5);assert.equal(scan.coverage.complete,true);assert.ok(scan.findings.every(f=>f.locations[0].line>0));
 assert.equal(run('audit','fixtures/corrected').status,0);
 assert.equal(run('audit','fixtures/ambiguous').status,3);
 assert.equal(run('discover').status,3);
});
test('outputs cannot mutate target or overwrite a baseline',async()=>{
 const temp=await mkdtemp(path.join(os.tmpdir(),'guard-cli-'));
 try{
 assert.equal(run('audit','fixtures/corrected','--out','fixtures/corrected/forbidden.json').status,2);
 const baseline=path.join(temp,'baseline.json');assert.equal(run('snapshot','fixtures/inventories/valid.json','--out',baseline).status,0);
 const initial=await readFile(baseline,'utf8');assert.equal(run('snapshot','fixtures/inventories/drift.json','--out',baseline).status,2);assert.equal(await readFile(baseline,'utf8'),initial);
 const next=path.join(temp,'next.json');assert.equal(run('snapshot','fixtures/inventories/drift.json','--out',next).status,0);
 const diff=run('diff',baseline,next,'--format','json');assert.ok([1,3].includes(diff.status));assert.ok(JSON.parse(diff.stdout).changes.some(c=>c.kind==='tool-description-changed'));
 const scan=path.join(temp,'scan.json');assert.equal(run('audit','fixtures/vulnerable','--format','json','--out',scan).status,1);
 const html=path.join(temp,'report.html');assert.equal(run('report',scan,'--out',html).status,0);assert.match(await readFile(html,'utf8'),/MG001/);
 const link=path.join(temp,'link.json');await symlink(baseline,link);assert.equal(run('inventory',link).status,2);
 }finally{await rm(temp,{recursive:true,force:true});}
});
test('JSON and empty source errors never produce a successful clean result',async()=>{
 const temp=await mkdtemp(path.join(os.tmpdir(),'guard-empty-'));
 try{await mkdir(path.join(temp,'empty'));assert.equal(run('audit',path.join(temp,'empty')).status,3);assert.equal(run('inventory','missing.json').status,2);assert.equal(run('inventory','fixtures/inventories/unsupported.json').status,3);}finally{await rm(temp,{recursive:true,force:true});}
});
