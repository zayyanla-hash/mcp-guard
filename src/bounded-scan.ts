import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { LIMITS } from './scanner.js';
import { SOURCE_RULES } from './analyzer.js';
import { coverage } from './shared.js';
import type { AuditResult } from './types.js';
export function scanSourceBounded(root:string,limits=LIMITS,signal?:AbortSignal):Promise<AuditResult>{
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,['--max-old-space-size=256',fileURLToPath(new URL('./scan-worker.js',import.meta.url))],{stdio:['ignore','ignore','ignore','ipc'],env:{PATH:'/usr/bin:/bin',LANG:'C',TZ:'UTC'}});
    let done=false;
    const clean=()=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);};
    const stop=(code:string)=>{
      if(done)return;done=true;clean();child.kill('SIGKILL');
      const cov=coverage(SOURCE_RULES);cov.complete=false;cov.truncated=['.'];cov.diagnostics=[{code,message:'Whole-source scan was terminated; no clean assessment is available.'}];
      resolve({schemaVersion:1,kind:'source',target:'Interrupted source audit',findings:[],coverage:cov});
    };
    const abort=()=>stop('SCAN_CANCELLED');
    const timer=setTimeout(()=>stop('SCAN_TIMEOUT'),Math.min(30000,Math.max(1,limits.milliseconds)));
    child.once('message',(message:{result?:AuditResult;error?:string})=>{if(done)return;done=true;clean();child.kill();if(message.result)resolve(message.result);else reject(new Error(message.error??'Scan child failed'));});
    child.once('error',error=>{if(done)return;done=true;clean();reject(error);});
    child.once('exit',()=>{if(!done)stop('SCAN_CHILD_EXIT');});
    signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
    child.send({root,limits},error=>{if(error&&!done){done=true;clean();child.kill();reject(error);}});
  });
}
