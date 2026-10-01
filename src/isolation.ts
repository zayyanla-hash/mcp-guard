import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import type { Readable, Writable } from 'node:stream';
const ROOT=fileURLToPath(new URL('../',import.meta.url));
export class IsolationBlocked extends Error {readonly code='ISOLATION_BLOCKED';}
export interface LaunchOptions {signal?:AbortSignal;maxBytes?:number;timeoutMs?:number}
export interface IsolatedChild {pid?:number;stdin:Writable;stdout:Readable;stderr:Readable;exit:Promise<{code:number|null;signal:NodeJS.Signals|null}>;terminate():Promise<void>}
const environment=():NodeJS.ProcessEnv=>({PATH:'/usr/bin:/bin',LANG:'C',TZ:'UTC',NODE_NO_WARNINGS:'1'});
function profile(root:string,node:string):string {
  const deniedReads=[root,'/System','/usr/lib','/Library/Apple'].map(p=>`(require-not (subpath ${JSON.stringify(p)}))`).join(' ');
  // REGULAR-FILE is essential: inherited stdio pipes must remain usable.
  // This backend is deliberately restricted to reviewed project fixtures.
  return `(version 1)(allow default)(deny network*)(deny process-fork)(deny process-exec (require-not (literal ${JSON.stringify(node)})))(deny file-read-data (require-all (vnode-type REGULAR-FILE) ${deniedReads} (require-not (literal ${JSON.stringify(node)}))))(deny file-write* (require-not (literal "/dev/null")))`;
}
async function launch(script:string,args:string[],options:LaunchOptions):Promise<IsolatedChild>{
  if(process.platform!=='darwin')throw new IsolationBlocked('Isolated discovery currently requires verified macOS sandbox-exec; no unrestricted fallback.');
  if(options.signal?.aborted)throw new IsolationBlocked('Discovery cancelled before startup.');
  await fs.access('/usr/bin/sandbox-exec');
  const root=await fs.realpath(ROOT),node=await fs.realpath(process.execPath);
  const child=spawn('/usr/bin/sandbox-exec',['-p',profile(root,node),node,'--max-old-space-size=128',script,...args],{cwd:root,env:environment(),stdio:['pipe','pipe','pipe'],detached:true});
  let bytes=0;let stopped=false;
  const kill=()=>{if(stopped)return;stopped=true;if(child.pid){try{process.kill(-child.pid,'SIGKILL');}catch{child.kill('SIGKILL');}}};
  const deadline=setTimeout(kill,options.timeoutMs??10000);
  const bound=(chunk:Buffer)=>{bytes+=chunk.length;if(bytes>(options.maxBytes??1048576))kill();};
  child.stdout.on('data',bound);child.stderr.on('data',bound);
  const abort=()=>kill();options.signal?.addEventListener('abort',abort,{once:true});
  const exit=new Promise<{code:number|null;signal:NodeJS.Signals|null}>((resolve,reject)=>{
    const clean=()=>{clearTimeout(deadline);options.signal?.removeEventListener('abort',abort);};
    child.once('error',error=>{clean();reject(error);});
    child.once('exit',(code,signal)=>{clean();resolve({code,signal});});
  });
  // Avoid an unhandled rejection if startup fails before a transport attaches.
  void exit.catch(()=>{});
  return {pid:child.pid,stdin:child.stdin,stdout:child.stdout,stderr:child.stderr,exit,terminate:async()=>{kill();await exit.catch(()=>{});}};
}
export async function verifyIsolation():Promise<{backend:string;verified:boolean;controls:Record<string,boolean>}> {
  if(process.platform!=='darwin')throw new IsolationBlocked('No verified isolation backend on this platform.');
  const probe=fileURLToPath(new URL('./isolation-probe.js',import.meta.url));
  const scratch=await fs.mkdtemp(path.join(os.tmpdir(),'mcp-guard-isolation-'));
  const canary=path.join(scratch,'fake-canary.txt');
  await fs.writeFile(canary,'FAKE_PRIVATE_CANARY_SCOPE_ONLY',{mode:0o600});
  let child:IsolatedChild|undefined;
  try {
    child=await launch(probe,[canary],{timeoutMs:5000,maxBytes:8192});
    let output='';child.stdout.on('data',chunk=>{output+=String(chunk);});
    const result=await child.exit;
    if(result.code!==0)throw new IsolationBlocked('OS isolation probe failed; no fixture was started.');
    const controls=JSON.parse(output) as Record<string,boolean>;
    if(!['read','write','spawn','network','environment'].every(key=>controls[key]===true)||await fs.readFile(canary,'utf8')!=='FAKE_PRIVATE_CANARY_SCOPE_ONLY')throw new IsolationBlocked('OS isolation controls were not established.');
    return {backend:'macos-seatbelt-reviewed-fixture',verified:true,controls};
  }catch(error){if(error instanceof IsolationBlocked)throw error;throw new IsolationBlocked('Isolation verification failed: '+(error instanceof Error?error.message:String(error)));}
  finally{await child?.terminate();await fs.rm(scratch,{recursive:true,force:true});}
}
export async function describeFixtureLaunch(fixturePath:string):Promise<{executable:string;args:string[]}>{
  const root=await fs.realpath(ROOT),node=await fs.realpath(process.execPath);
  return {executable:'/usr/bin/sandbox-exec',args:['-p',profile(root,node),node,'--max-old-space-size=128',await fs.realpath(fixturePath)]};
}
export async function launchFixture(fixturePath:string,options:LaunchOptions={}):Promise<IsolatedChild>{
  const fixtures=await fs.realpath(path.join(ROOT,'fixtures/discovery'));
  const stat=await fs.lstat(fixturePath),real=await fs.realpath(fixturePath);
  if(!['reviewed.mjs','timeout.mjs','cursor-loop.mjs','server-request.mjs','protocol-mismatch.mjs','large-response.mjs'].includes(path.basename(real)))throw new IsolationBlocked('Fixture is not on the execution allowlist');
  if(!stat.isFile()||stat.isSymbolicLink()||path.dirname(real)!==fixtures)throw new IsolationBlocked('Only built-in reviewed fixture files may execute.');
  await verifyIsolation();
  return launch(real,[],options);
}
