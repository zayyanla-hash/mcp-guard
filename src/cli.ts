#!/usr/bin/env node
import { promises as fs, constants } from 'node:fs';
import path from 'node:path';
import { Worker } from 'node:worker_threads';
import { inside } from './scanner.js';
import { renderTerminal, validateResult } from './reporting.js';
import { canonical, cleanTerminal, redactText } from './shared.js';
import { scanSourceBounded } from './bounded-scan.js';
import { VERSION } from './version.js';
import { fileURLToPath } from 'node:url';
import { discoverFixture, DiscoveryIncomplete } from './discovery.js';
import { IsolationBlocked,describeFixtureLaunch } from './isolation.js';
import { policyExit } from './policy.js';
import type { AuditResult, Severity } from './types.js';

const cancellation=new AbortController();
process.once('SIGINT',()=>cancellation.abort());
process.once('SIGTERM',()=>cancellation.abort());
const HELP=`MCP Guard ${VERSION} — bounded offline MCP audits
Usage: mcp-guard <command> [arguments] [options]
  audit <directory>                  Static source audit; never executes targets
  inventory <tools.json>             Validate offline inventory
  snapshot <tools.json> --out <file>  Create a new inventory baseline
  diff <before.json> <after.json>     Explain inventory drift
  report <scan.json> --out <file>     Render self-contained HTML
  discover --fixture reviewed --approve-execution
                                    Isolated reviewed local fixture (macOS only)
Options:
  --format terminal|json             Audit/inventory/diff output (default terminal)
  --out <file>                       Write a NEW artifact; never overwrite
  --inventory-out <file>             Discovery: preserve snapshot-ready inventory
  --fixture-root <relative-directory> Audit: label operator-declared fixture paths
  --threshold low|medium|high         Finding policy threshold (default medium)
  --help                            Show help
  --version                         Show version
Exits: 0 complete below threshold; 1 findings/drift; 2 invalid input/error;
       3 required coverage incomplete or discovery blocked.
No findings does not establish safety. See docs/LIMITATIONS.md.
`;
async function readJson(file:string):Promise<unknown> {
  const stat=await fs.lstat(file);
  if(!stat.isFile()||stat.isSymbolicLink())throw new Error('JSON input must be a regular file, not a symlink');
  const fd=await fs.open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
  try {
    const opened=await fd.stat();
    if(opened.ino!==stat.ino||opened.dev!==stat.dev||opened.size>1048576)throw new Error('JSON input changed or exceeds the 1 MiB limit');
    const buffer=Buffer.alloc(1048577);let length=0;
    while(length<buffer.length){const read=await fd.read(buffer,length,buffer.length-length,null);if(!read.bytesRead)break;length+=read.bytesRead;}
    if(length>1048576)throw new Error('JSON input exceeds the 1 MiB limit');
    return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(buffer.subarray(0,length)));
  } finally {await fd.close();}
}
async function writeNew(file:string,text:string,target?:string):Promise<void> {
  const destination=path.resolve(file);
  const parent=await fs.realpath(path.dirname(destination));
  if(target&&inside(await fs.realpath(target),path.join(parent,path.basename(destination))))throw new Error('Output must be outside the audited source root');
  await fs.writeFile(path.join(parent,path.basename(destination)),text,{flag:'wx',mode:0o600});
}
async function artifact(operation:string,inputs:unknown[]):Promise<unknown> {
  return new Promise((resolve,reject)=>{
    const worker=new Worker(new URL('./artifact-worker.js',import.meta.url),{workerData:{operation,inputs},resourceLimits:{maxOldGenerationSizeMb:256}});
    const timer=setTimeout(()=>{void worker.terminate();reject(new Error('Artifact processing exceeded 5 seconds'));},5000);
    worker.once('message',(message:{result?:unknown;error?:string})=>{clearTimeout(timer);void worker.terminate();if(message.error)reject(new Error(message.error));else resolve(message.result);});
    worker.once('error',error=>{clearTimeout(timer);reject(error);});
    worker.once('exit',code=>{if(code!==0){clearTimeout(timer);reject(new Error('Artifact worker failed'));}});
  });
}
async function main(argv:string[]):Promise<number> {
  if(argv.length===1&&argv[0]==='--version'){console.log(VERSION);return 0;}
  if(!argv.length||(argv.length===1&&argv[0]==='--help')){console.log(HELP);return 0;}
  const command=argv.shift()!;
  if(!['audit','inventory','snapshot','diff','report','discover'].includes(command))throw new Error('Unknown command: '+command);
  if(argv.length===1&&argv[0]==='--help'){console.log(HELP);return 0;}
  const positions:string[]=[],options=new Map<string,string>();
  for(let i=0;i<argv.length;i++){
    const value=argv[i]!;
    if(value.startsWith('--')){
      if(!['--out','--format','--threshold','--fixture','--approve-execution','--inventory-out','--fixture-root'].includes(value)||options.has(value))throw new Error('Unknown or repeated option: '+value);
      if(value==='--approve-execution'){options.set(value,'true');continue;}
      const next=argv[++i];if(!next||next.startsWith('--'))throw new Error('Missing value for '+value);options.set(value,next);
    }else if(value.startsWith('-'))throw new Error('Unknown option: '+value);else positions.push(value);
  }
  if(positions.length!==(command==='diff'?2:command==='discover'?0:1))throw new Error('Incorrect number of arguments for '+command);
  const format=options.get('--format')??'terminal',threshold=options.get('--threshold')??'medium',out=options.get('--out');
  if(!['terminal','json'].includes(format))throw new Error('Invalid output format');
  if(!['low','medium','high'].includes(threshold))throw new Error('Invalid severity threshold');
  if(command!=='discover'&&(options.has('--fixture')||options.has('--approve-execution')||options.has('--inventory-out')))throw new Error('Discovery options only apply to discover');
  if(command!=='audit'&&options.has('--fixture-root'))throw new Error('--fixture-root only applies to audit');
  if(['snapshot','report'].includes(command)){
    if(!out)throw new Error(command+' requires --out');
    if(options.has('--format')||options.has('--threshold'))throw new Error('Format/threshold options are not supported for '+command);
  }
  if(command==='snapshot'){
    const snapshot=await artifact('snapshot',[await readJson(positions[0]!)]);
    await writeNew(out!,canonical(snapshot)+'\n');console.log('Snapshot written: '+cleanTerminal(redactText(out!)));return 0;
  }
  if(command==='report'){
    const html=await artifact('report',[await readJson(positions[0]!)]);
    await writeNew(out!,String(html));console.log('Report written: '+cleanTerminal(redactText(out!)));return 0;
  }
  let result:AuditResult;
  if(command==='discover'){
    if(options.get('--fixture')!=='reviewed'||!options.has('--approve-execution')){console.error('BLOCKED: use --fixture reviewed --approve-execution to explicitly authorize the isolated project-owned fixture.');return 3;}
    const approvedFixture=fileURLToPath(new URL('../fixtures/discovery/reviewed.mjs',import.meta.url));
    console.error('Approved executable/arguments: '+cleanTerminal(redactText(JSON.stringify(await describeFixtureLaunch(approvedFixture)))));
    const acquired=await discoverFixture({approved:true,signal:cancellation.signal});
    result=await artifact('inventory',[acquired.inventory]) as AuditResult;
    result.target='Project-owned reviewed fixture: isolated SDK discovery';
    if(options.has('--inventory-out')){const checked=await artifact('snapshot',[acquired.inventory]) as {payload:unknown};await writeNew(options.get('--inventory-out')!,canonical(checked.payload)+'\n',fileURLToPath(new URL('../fixtures',import.meta.url)));}
  }
  else if(command==='audit'){
    let declaredRoot:string|undefined;
    if(options.has('--fixture-root')){
      const relative=options.get('--fixture-root')!;
      if(path.isAbsolute(relative)||relative.includes('\\')||relative.split('/').some(part=>!part||part==='.'||part==='..'))throw new Error('--fixture-root must be a relative directory within the audited root');
      const auditRoot=await fs.realpath(positions[0]!);
      const selected=path.resolve(auditRoot,relative),stat=await fs.lstat(selected);
      if(!stat.isDirectory()||stat.isSymbolicLink())throw new Error('--fixture-root must identify a real directory');
      const real=await fs.realpath(selected);
      if(!inside(auditRoot,real))throw new Error('--fixture-root escapes the audited root');
      declaredRoot=path.relative(auditRoot,real).split(path.sep).join('/');
    }
    result=await scanSourceBounded(positions[0]!,undefined,cancellation.signal);
    if(declaredRoot)result.declaredFixtureRoots=[declaredRoot];
  }
  else if(command==='inventory')result=await artifact('inventory',[await readJson(positions[0]!)]) as AuditResult;
  else result=await artifact('diff',[await readJson(positions[0]!),await readJson(positions[1]!)]) as AuditResult;
  result=validateResult(result);
  const rendered=format==='json'?JSON.stringify(result,null,2)+'\n':renderTerminal(result)+'\n';
  if(out)await writeNew(out,rendered,command==='audit'?positions[0]:undefined);else process.stdout.write(rendered);
  return policyExit(result,threshold as Severity);
}
main(process.argv.slice(2)).then(code=>{process.exitCode=code;}).catch(error=>{console.error('Error: '+cleanTerminal(redactText(error instanceof Error?error.message:String(error))));process.exitCode=error instanceof IsolationBlocked||error instanceof DiscoveryIncomplete?3:2;});
