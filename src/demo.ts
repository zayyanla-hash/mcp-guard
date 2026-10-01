import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanSource } from './scanner.js';
import { auditInventory, snapshotInventory, diffSnapshots } from './inventory.js';
import { renderHtml, validateResult } from './reporting.js';
import { policyExit } from './policy.js';
import { canonical } from './shared.js';
const root=fileURLToPath(new URL('../',import.meta.url));
async function main():Promise<void>{
  const args=process.argv.slice(2);
  if(args.length&&!(args.length===2&&args[0]==='--out'))throw new Error('Usage: demo [--out NEW-directory]');
  const output=path.resolve(args[1]??'demo-output');
  const parent=await fs.realpath(path.dirname(output));
  const canonicalOutput=path.join(parent,path.basename(output));
  const fixtureRoot=await fs.realpath(path.join(root,'fixtures'));
  if(path.relative(fixtureRoot,canonicalOutput)===''||!path.relative(fixtureRoot,canonicalOutput).startsWith('..'))throw new Error('Demo output must be outside fixtures');
  await fs.mkdir(canonicalOutput,{recursive:false});
  const save=async(name:string,value:unknown)=>fs.writeFile(path.join(canonicalOutput,name),canonical(value)+'\n',{flag:'wx',mode:0o600});
  const read=async(name:string)=>JSON.parse(await fs.readFile(path.join(root,'fixtures','inventories',name),'utf8'));
  const vulnerable=validateResult(await scanSource(path.join(root,'fixtures/vulnerable')));
  const corrected=validateResult(await scanSource(path.join(root,'fixtures/corrected')));
  vulnerable.target='Project-owned seeded fixture: vulnerable';corrected.target='Project-owned seeded fixture: corrected';
  const actual=[...new Set(vulnerable.findings.map(f=>f.ruleId))].sort().join(',');
  if(actual!=='MG001,MG002,MG003,MG004,MG006'||!vulnerable.coverage.complete||corrected.findings.length||!corrected.coverage.complete)throw new Error('Paired source fixtures did not reproduce expected outcomes');
  const inventory=validateResult(auditInventory(await read('vulnerable.json')));
  const correctedInventory=validateResult(auditInventory(await read('corrected.json')));
  inventory.target='Project-owned seeded fixture: invalid descriptor';correctedInventory.target='Project-owned seeded fixture: corrected descriptor';
  if(!inventory.findings.some(f=>f.ruleId==='MG005')||correctedInventory.findings.length||!correctedInventory.coverage.complete)throw new Error('Inventory fixture outcomes did not reproduce');
  const before=snapshotInventory(await read('valid.json')),after=snapshotInventory(await read('drift.json'));
  const drift=validateResult(diffSnapshots(before,after));drift.target='Project-owned seeded fixture: descriptor drift';
  if(!drift.changes?.some(c=>c.kind==='tool-description-changed'))throw new Error('Description drift was not detected');
  const outcomes={vulnerable:policyExit(vulnerable),corrected:policyExit(corrected),inventory:policyExit(inventory),correctedInventory:policyExit(correctedInventory),drift:policyExit(drift)};
  if(outcomes.vulnerable!==1||outcomes.corrected!==0)throw new Error('Source CI outcomes differ from contract');
  for(const [name,result]of Object.entries({vulnerable,corrected,inventory,correctedInventory,drift})){
    await save(name+'.json',result);await fs.writeFile(path.join(canonicalOutput,name+'.html'),renderHtml(result),{flag:'wx',mode:0o600});
  }
  await save('before.snapshot.json',before);await save('after.snapshot.json',after);
  await save('summary.json',{evidenceCategory:'Project-owned seeded fixture',sourceRules:actual.split(','),findingsBefore:vulnerable.findings.length,findingsAfter:corrected.findings.length,descriptorDefects:inventory.findings.length,driftChanges:drift.changes?.length,outcomes,limitations:'Seeded results are not real-world detection rates. Targets were parsed, never executed.'});
  console.log('Offline demo PASS. Recorded evidence: '+output);console.log(JSON.stringify(outcomes));
}
main().catch(error=>{console.error(error instanceof Error?error.message:String(error));process.exitCode=2;});
