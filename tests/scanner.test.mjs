import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,symlink,rm,readFile,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {scanSource,LIMITS} from '../dist/scanner.js';
import {policyExit} from '../dist/policy.js';
import {containedExistingPath} from '../fixtures/behavior/containment.mjs';
const positive=await readFile(new URL('../fixtures/vulnerable/server.ts',import.meta.url),'utf8');
async function temporary(t){const dir=await mkdtemp(path.join(tmpdir(),'mcp-guard-test-'));t.after(()=>rm(dir,{recursive:true,force:true}));return dir;}
test('seeded vulnerable/corrected scans reproduce five source-rule outcomes',async()=>{
 const bad=await scanSource('fixtures/vulnerable'),good=await scanSource('fixtures/corrected');
 assert.deepEqual(bad.findings.map(x=>x.ruleId),['MG001','MG002','MG003','MG004','MG006']);assert.equal(bad.coverage.complete,true);assert.equal(policyExit(bad),1);
 assert.equal(good.findings.length,0);assert.equal(good.coverage.complete,true);assert.equal(policyExit(good),0);
});
test('ambiguous source has findings and incomplete coverage',async()=>{const r=await scanSource('fixtures/ambiguous');assert.equal(policyExit(r),3);assert.equal(r.coverage.unresolvedHandlers,1);assert.ok(r.findings.some(x=>x.ruleId==='MG002'));});
test('static audit never executes target code or package scripts',async t=>{
 const dir=await temporary(t),marker=path.join(dir,'executed');
 await writeFile(path.join(dir,'server.ts'),positive+`\nrequire('node:fs').writeFileSync(${JSON.stringify(marker)},'oops');`);
 await writeFile(path.join(dir,'package.json'),JSON.stringify({scripts:{preinstall:`touch ${marker}`}}));
 const r=await scanSource(dir);assert.ok(r.findings.length);await assert.rejects(readFile(marker));
});
test('symlink targets outside root are excluded and incomplete',async t=>{
 const dir=await temporary(t);await mkdir(path.join(dir,'root'));await writeFile(path.join(dir,'outside.ts'),positive);await symlink('../outside.ts',path.join(dir,'root','escape.ts'));
 const r=await scanSource(path.join(dir,'root'));assert.deepEqual(r.coverage.inspected,[]);assert.ok(r.coverage.excluded.includes('escape.ts'));assert.equal(policyExit(r),3);
});
test('symlink audit root rejected',async t=>{const dir=await temporary(t);await mkdir(path.join(dir,'root'));await symlink('root',path.join(dir,'alias'));await assert.rejects(scanSource(path.join(dir,'alias')),/not a symlink/);});
test('parse failure is incomplete even when findings exist elsewhere',async t=>{const dir=await temporary(t);await writeFile(path.join(dir,'a.ts'),positive);await writeFile(path.join(dir,'bad.ts'),'function {');const r=await scanSource(dir);assert.equal(policyExit(r),3);assert.ok(r.coverage.failed.includes('bad.ts'));});
test('no tools or no supported files never exits clean',async t=>{const dir=await temporary(t);assert.equal(policyExit(await scanSource(dir)),3);await writeFile(path.join(dir,'ordinary.ts'),'export const x=1;');assert.equal(policyExit(await scanSource(dir)),3);});
test('bounded file bytes remain visible',async t=>{const dir=await temporary(t);await writeFile(path.join(dir,'a.ts'),positive);const r=await scanSource(dir,{...LIMITS,fileBytes:64});assert.equal(policyExit(r),3);assert.deepEqual(r.coverage.truncated,['a.ts']);});
test('invalid encoding is a failed assessment',async t=>{const dir=await temporary(t);await writeFile(path.join(dir,'bad.js'),Buffer.from([0xff,0xfe]));const r=await scanSource(dir);assert.equal(policyExit(r),3);assert.ok(r.coverage.diagnostics.some(x=>x.code==='INVALID_ENCODING'));});
test('deterministic scans and dependency exclusion',async t=>{const dir=await temporary(t);await writeFile(path.join(dir,'a.ts'),positive);await mkdir(path.join(dir,'node_modules'));await writeFile(path.join(dir,'node_modules','bad.ts'),'function {');const a=await scanSource(dir),b=await scanSource(dir);assert.deepEqual(a,b);assert.ok(a.coverage.excluded.includes('node_modules/'));});
test('unsupported languages, time and entry budgets remain incomplete',async t=>{const dir=await temporary(t);await writeFile(path.join(dir,'tool.py'),'print("data")');assert.equal(policyExit(await scanSource(dir)),3);assert.equal(policyExit(await scanSource(dir,{...LIMITS,milliseconds:0})),3);assert.equal(policyExit(await scanSource(dir,{...LIMITS,entries:0})),3);});
test('explicit target suppression file cannot disable finding',async t=>{const dir=await temporary(t);await writeFile(path.join(dir,'a.ts'),positive);await writeFile(path.join(dir,'.mcp-guard.json'),'{"disabledRules":["MG001","MG002","MG003","MG004","MG006"]}');assert.ok((await scanSource(dir)).findings.some(x=>x.ruleId==='MG001'));});
test('reviewed containment fixture rejects traversal, absolute, prefix confusion and symlink escapes',async t=>{
 const dir=await temporary(t),root=path.join(dir,'root');await mkdir(root);await mkdir(path.join(dir,'root-other'));await writeFile(path.join(root,'ok'),'sample');await writeFile(path.join(dir,'root-other','secret'),'FAKE_SECRET_CANARY');await symlink('../root-other/secret',path.join(root,'link'));
 assert.equal(await containedExistingPath(root,'ok'),await realpath(path.join(root,'ok')));
 for(const input of ['../root-other/secret',path.join(dir,'root-other','secret'),'link'])await assert.rejects(containedExistingPath(root,input));
});

test('excluded minified executable source remains visibly unassessed',async t=>{
 const dir=await temporary(t);
 await writeFile(path.join(dir,'server.ts'),await readFile('fixtures/corrected/server.ts','utf8'));
 await writeFile(path.join(dir,'hidden.min.js'),positive);
 const result=await scanSource(dir);assert.equal(policyExit(result),3);
 assert.ok(result.coverage.excluded.includes('hidden.min.js'));
 assert.ok(result.coverage.diagnostics.some(d=>d.code==='GENERATED_SOURCE_EXCLUDED'));
});

test('excluded deployment directories cannot produce a silently complete result',async t=>{
 const dir=await temporary(t);await mkdir(path.join(dir,'dist'));
 await writeFile(path.join(dir,'server.ts'),await readFile('fixtures/corrected/server.ts','utf8'));
 await writeFile(path.join(dir,'dist/server.js'),positive);
 const result=await scanSource(dir);assert.equal(policyExit(result),3);assert.ok(result.coverage.excluded.includes('dist/'));
});
