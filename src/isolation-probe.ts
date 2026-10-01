import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import net from 'node:net';
const canary=process.argv[2]!;
const denied=(error:unknown)=>['EPERM','EACCES'].includes((error as NodeJS.ErrnoException).code??'');
const result={read:false,write:false,spawn:false,network:false,environment:process.env.MCP_GUARD_FAKE_SECRET===undefined};
try{readFileSync(canary);}catch(error){result.read=denied(error);}
try{writeFileSync(canary,'MUTATED');}catch(error){result.write=denied(error);}
const child=spawnSync(process.execPath,['--version']);result.spawn=!!child.error&&denied(child.error);
const server=net.createServer();
const finish=()=>{console.log(JSON.stringify(result));process.exitCode=Object.values(result).every(Boolean)?0:1;};
server.once('error',error=>{result.network=denied(error);finish();});
server.listen(0,'127.0.0.1',()=>server.close(finish));
