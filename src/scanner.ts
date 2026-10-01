import { promises as fs, constants } from 'node:fs';
import path from 'node:path';
import { Worker } from 'node:worker_threads';
import { coverage, redact } from './shared.js';
import { SOURCE_RULES } from './analyzer.js';
import type { AuditResult } from './types.js';
export const LIMITS={files:2000,entries:4000,bytes:20*1024*1024,fileBytes:1024*1024,depth:20,milliseconds:30000,fileMilliseconds:2000};
const excluded=new Set(['node_modules','.git','.svn','.hg','dist','build','coverage','.next','vendor','__pycache__']);
const supported=new Set(['.js','.mjs','.ts','.mts']);
const unsupported=new Set(['.cjs','.cts','.jsx','.tsx','.py','.go','.rs','.java','.rb','.php','.c','.cpp']);
export function inside(root:string,candidate:string):boolean {const rel=path.relative(root,candidate);return rel===''||(!rel.startsWith('..'+path.sep)&&rel!=='..'&&!path.isAbsolute(rel));}
async function analyze(file:string,text:string,milliseconds:number):Promise<AuditResult>{
  return new Promise((resolve,reject)=>{
    const worker=new Worker(new URL('./analysis-worker.js',import.meta.url),{workerData:{file,text},resourceLimits:{maxOldGenerationSizeMb:256}});
    const timer=setTimeout(()=>{void worker.terminate();reject(new Error('ANALYSIS_TIMEOUT'));},milliseconds);
    worker.once('message',(message:{result?:AuditResult;error?:string})=>{clearTimeout(timer);void worker.terminate();if(message.result)resolve(message.result);else reject(new Error(message.error??'ANALYSIS_FAILED'));});
    worker.once('error',error=>{clearTimeout(timer);reject(error);});
    worker.once('exit',code=>{clearTimeout(timer);if(code!==0)reject(new Error('ANALYSIS_WORKER_EXIT_'+code));});
  });
}
export async function scanSource(input:string,limits=LIMITS):Promise<AuditResult>{
  const requested=path.resolve(input),stat=await fs.lstat(requested);
  if(!stat.isDirectory()||stat.isSymbolicLink())throw new Error('Audit root must be a real directory, not a symlink');
  const root=await fs.realpath(requested),cov=coverage(SOURCE_RULES);
  const out:AuditResult={schemaVersion:1,kind:'source',target:path.basename(root),findings:[],coverage:cov};
  const deadline=Date.now()+limits.milliseconds;let entries=0,totalBytes=0,files=0,stop=false;
  const incomplete=(code:string,file:string,message:string)=>{cov.complete=false;cov.diagnostics.push({code,file,message});};
  const walk=async(dir:string,depth:number):Promise<void>=>{
    if(stop)return;
    const relative=path.relative(root,dir)||'.';
    if(depth>limits.depth){cov.truncated.push(relative);incomplete('DEPTH_LIMIT',relative,'Maximum source-walk depth reached');return;}
    if(Date.now()>=deadline){stop=true;cov.truncated.push(relative);incomplete('TIME_LIMIT',relative,'Source-audit deadline reached');return;}
    const names:string[]=[];
    try{
      const handle=await fs.opendir(dir);
      for await(const entry of handle){if(++entries>limits.entries){stop=true;cov.truncated.push(relative);incomplete('ENTRY_LIMIT',relative,'Directory entry budget reached');break;}names.push(entry.name);}
    }catch{cov.failed.push(relative);incomplete('UNREADABLE_DIRECTORY',relative,'Directory could not be read');return;}
    names.sort();
    for(const name of names){
      if(stop)break;
      if(Date.now()>=deadline){stop=true;cov.truncated.push(relative);incomplete('TIME_LIMIT',relative,'Source-audit deadline reached');break;}
      const full=path.join(dir,name),rel=path.relative(root,full).split(path.sep).join('/');
      try{
        const info=await fs.lstat(full);
        if(info.isSymbolicLink()){cov.excluded.push(rel);incomplete('SYMLINK_SKIPPED',rel,'Symlink was not followed; its content was not assessed');continue;}
        if(info.isDirectory()){if(excluded.has(name)){cov.excluded.push(rel+'/');if(['dist','build','vendor','.next'].includes(name))incomplete('GENERATED_DIRECTORY_EXCLUDED',rel,'Executable generated/vendor directory was not assessed');continue;}await walk(full,depth+1);continue;}
        if(!info.isFile()){cov.excluded.push(rel);continue;}
        const ext=path.extname(name);
        if(!supported.has(ext)||name.endsWith('.d.ts')||name.endsWith('.min.js')){cov.excluded.push(rel);if(name.endsWith('.min.js'))incomplete('GENERATED_SOURCE_EXCLUDED',rel,'Executable generated source was excluded and not assessed');if(unsupported.has(ext))incomplete('UNSUPPORTED_LANGUAGE',rel,'File language/module format is outside the supported source subset');continue;}
        if(++files>limits.files){stop=true;cov.truncated.push(rel);incomplete('FILE_LIMIT',rel,'Maximum supported files reached');break;}
        if(info.size>limits.fileBytes||totalBytes+info.size>limits.bytes){cov.truncated.push(rel);incomplete('BYTE_LIMIT',rel,'Source byte budget exceeded');continue;}
        const real=await fs.realpath(full);if(!inside(root,real)){cov.failed.push(rel);incomplete('ROOT_ESCAPE',rel,'Path resolved outside the selected root');continue;}
        const descriptor=await fs.open(full,constants.O_RDONLY|constants.O_NOFOLLOW);
        let bytes:Buffer;
        try{
          const opened=await descriptor.stat();if(!opened.isFile()||opened.size>limits.fileBytes||opened.ino!==info.ino||opened.dev!==info.dev)throw new Error('File changed while opening');
          // Read at most the declared byte budget, even if a file grows after stat.
          const buffer=Buffer.alloc(Math.min(limits.fileBytes+1,opened.size+1));let offset=0;
          while(offset<buffer.length){const read=await descriptor.read(buffer,offset,buffer.length-offset,offset);if(!read.bytesRead)break;offset+=read.bytesRead;}
          if(offset>opened.size||offset>limits.fileBytes)throw new Error('File changed or exceeded byte limit');
          bytes=buffer.subarray(0,offset);
          if(!inside(root,await fs.realpath(full)))throw new Error('Path changed outside selected root');
        }finally{await descriptor.close();}
        totalBytes+=bytes.length;
        let text:string;try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{cov.failed.push(rel);incomplete('INVALID_ENCODING',rel,'Source is not valid UTF-8');continue;}
        const result=await analyze(rel,text,Math.max(1,Math.min(limits.fileMilliseconds,deadline-Date.now())));
        cov.inspected.push(...result.coverage.inspected);cov.failed.push(...result.coverage.failed);
        cov.recognizedTools+=result.coverage.recognizedTools;cov.unresolvedHandlers+=result.coverage.unresolvedHandlers;
        cov.complete&&=result.coverage.complete;cov.diagnostics.push(...result.coverage.diagnostics);out.findings.push(...result.findings);
      }catch(error){cov.failed.push(rel);incomplete('FILE_OR_ANALYZER_FAILURE',rel,error instanceof Error?error.message:'File read/analyzer failed');}
    }
  };await walk(root,0);
  if(!cov.inspected.length)incomplete('NO_SUPPORTED_FILES','.', 'No supported source files were assessed');
  if(!cov.recognizedTools)incomplete('NO_RECOGNIZED_TOOLS','.', 'No supported tool registrations were found');
  for(const key of ['inspected','excluded','failed','truncated'] as const)cov[key]=[...new Set(cov[key])].sort();
  out.findings.sort((a,b)=>(a.locations[0]?.file??'').localeCompare(b.locations[0]?.file??'')||a.ruleId.localeCompare(b.ruleId)||(a.locations.at(-1)?.line??0)-(b.locations.at(-1)?.line??0));
  return redact(out) as AuditResult;
}
