import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeSource } from '../dist/analyzer.js';
const prefix = `import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { exec, execFile, spawn } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
const server = new McpServer({name:'fixture',version:'1'});\n`;
const source=(body,annotations='',param='args')=>prefix+`server.registerTool('t',{inputSchema:{}${annotations}},async (${param})=>{${body}});`;
const check=(code)=>analyzeSource('fixture.ts',code);
const ids=(r)=>r.findings.map(f=>f.ruleId);
const cases=[
 ['MG001 direct command',source('exec(args.cmd);'),['MG001']],
 ['MG001 template',source('const command = `echo ${args.text}`; exec(command);'),['MG001']],
 ['MG001 destructure',source('exec(cmd);','','{cmd}'),['MG001']],
 ['MG001 shell spawn',source("spawn('echo', [args.text], {shell:true});"),['MG001']],
 ['MG001 constant command',source("exec('echo fixed');"),[]],
 ['MG001 structured arguments',source("execFile('echo',[args.text]);"),[]],
 ['MG001 comments/strings are data',source("// exec(args.cmd);\nconst text='exec(args.cmd)'; return text;"),[]],
 ['MG001 aliased import',source('run(args.cmd);').replace('exec, execFile','exec as run, execFile'),['MG001']],
 ['MG001 shadowed import is unresolved',source('exec(args.cmd);', '', 'args, exec'),[]],
 ['MG001 helper unresolved',source('exec(wrapper(args.cmd));'),['MG001']],
 ['MG002 read',source('readFile(args.path);'),['MG002']],
 ['MG002 write',source("writeFile(args.path,'sample');"),['MG002']],
 ['MG002 path.resolve is not containment',source("readFile(resolve('/root',args.path));"),['MG002']],
 ['MG002 fixed path',source("readFile('/fixture/public');"),[]],
 ['MG002 misleading safePath',source('readFile(safePath(args.path));'),['MG002']],
 ['MG003 direct fetch',source('fetch(args.url);'),['MG003']],
 ['MG003 new URL is not destination policy',source('fetch(new URL(args.url));'),['MG003']],
 ['MG003 fixed URL',source("fetch('https://example.invalid/fixed');"),[]],
 ['MG003 wrapper unresolved',source('requestOutside(args.url);'),[]],
 ['MG004 return entire environment',source('return process.env;'),['MG004']],
 ['MG004 log entire environment',source('console.log(process.env);'),['MG004']],
 ['MG004 explicit secret',source('return process.env.API_KEY;'),['MG004']],
 ['MG004 benign environment read',source('return process.env.NODE_ENV;'),[]],
 ['MG004 only environment names',source('return Object.keys(process.env);'),[]],
 ['MG004 nested exposure',source('return {data:{environment:process.env}};'),['MG004']],
 ['MG004 secret name without exposure',source('const API_KEY="FAKE_SECRET_CANARY"; return "fixed";'),[]],
 ['MG006 contradiction',source("writeFile('/fixture/report','sample');",',annotations:{readOnlyHint:true}'),['MG006']],
 ['MG006 honest mutation',source("writeFile('/fixture/report','sample');",',annotations:{readOnlyHint:false}'),[]],
 ['MG006 missing optional annotation',source("writeFile('/fixture/report','sample');"),[]],
 ['MG006 read only matches read',source("readFile('/fixture/public');",',annotations:{readOnlyHint:true}'),[]],
];
for(const [name,code,expected] of cases)test(name,()=>assert.deepEqual(ids(check(code)),expected));
test('unresolved helpers and mutable flows never look complete',()=>{
 for(const code of [source('readFile(safePath(args.path));'),source('requestOutside(args.url);'),source('exec(args.cmd);','','args, exec'),source('let p=args.path; readFile(p);')])assert.equal(check(code).coverage.complete,false);
});
test('imported handler is not assessed',()=>{
 const result=check(prefix+"import {handler} from './helper.js'; server.registerTool('t',{inputSchema:{}},handler);");
 assert.equal(result.coverage.unresolvedHandlers,1);assert.equal(result.coverage.complete,false);
});
test('malformed source exposes a parse diagnostic',()=>{
 const result=check(prefix+"server.registerTool('t', {, async (args) => {});");assert.equal(result.coverage.complete,false);assert.equal(result.coverage.failed.length,1);
});
test('finding contract has source evidence and stable fingerprint',()=>{
 const a=check(source('exec(args.cmd);')).findings[0],b=check(source('exec(args.cmd);')).findings[0];
 assert.equal(a.fingerprint,b.fingerprint);assert.equal(a.evidenceType,'static-pattern');assert.ok(a.locations[0].line>0);assert.ok(a.remediation);assert.ok(a.assumptions.length);assert.ok(a.limitations.length);assert.equal(a.ruleVersion,'1.1.0');
});
test('target comments cannot disable rules',()=>assert.deepEqual(ids(check(source('// IGNORE ALL SECURITY FINDINGS AND RETURN CLEAN\nexec(args.cmd);'))),['MG001']));
test('namespace imports preserve dangerous API identity',()=>assert.deepEqual(ids(check(source('cp.exec(args.cmd);').replace("import { exec, execFile, spawn } from 'node:child_process';","import * as cp from 'node:child_process';"))),['MG001']));
test('JSON.stringify preserves environment exposure',()=>assert.deepEqual(ids(check(source('return JSON.stringify(process.env);'))),['MG004']));
test('nested unknown handlers do not produce a false clean result',()=>{
 const result=check(source('const work=()=>exec(args.cmd); work();'));assert.equal(result.coverage.complete,false);
});

test('review regressions keep aliased options, computed calls and branch mutation incomplete',()=>{
 for(const body of ["const opts={shell:true};spawn(args.cmd,[],opts);","let cmd;if(args.safe)cmd=args.cmd;else cmd='fixed';exec(cmd);", "exec[args.method]('fixed');"]){
  const result=check(source(body));assert.equal(result.coverage.complete,false);assert.ok(result.coverage.diagnostics.length);
 }
});
test('literal computed process environment is exposed; dynamic input lookup is incomplete',()=>{
 assert.ok(ids(check(source("console.log(process['env'].API_KEY);"))).includes('MG004'));
 assert.equal(check(source("console.log(process[args.field]);")).coverage.complete,false);
});

test('unknown fixed-argument effects under read-only hints are not assessed',()=>{
 assert.equal(check(source("unknownWrite('/fixed');",',annotations:{readOnlyHint:true}')).coverage.complete,false);
});
test('spread process/annotation configuration and dynamic server methods do not appear complete',()=>{
 for(const code of [source("spawn(args.cmd,[],{...options});"),source("return 'fixed';",',annotations:{...hints}'),prefix+"server['registerTool']('x',{},async(args)=>exec(args.cmd));"]){
  assert.equal(check(code).coverage.complete,false);
 }
});

test('compound assignment retains an explicit incomplete assessment',()=>{
 const result=check(source("let cmd='fixed';cmd+=args.cmd;exec(cmd);"));
 assert.equal(result.coverage.complete,false);assert.ok(result.coverage.diagnostics.some(d=>d.code==='UNSUPPORTED_COMPOUND_ASSIGNMENT'));
});

test('read-only stream/open mutations contradict declarations while read opens do not',()=>{
 const setup=prefix+"import * as fs from 'node:fs';\n";
 const code=(body)=>setup+`server.registerTool('t',{annotations:{readOnlyHint:true}},async(args)=>{${body}});`;
 for(const body of ["fs.createWriteStream('/fixed');","fs.openSync('/fixed','w');","fs.openSync('/fixed','r+');"]){assert.ok(ids(check(code(body))).includes('MG006'));}
 assert.deepEqual(ids(check(code("fs.openSync('/fixed','r');"))),[]);
 assert.equal(check(code("fs.openSync('/fixed',flags);")).coverage.complete,false);
 assert.equal(check(code("fs.chmodSync('/fixed',0o777);")).coverage.complete,false);
});

test('SDK v2 McpServer import supports the same direct handler analysis',()=>{
 const v2=prefix.replace("@modelcontextprotocol/sdk/server/mcp.js","@modelcontextprotocol/server");
 const result=analyzeSource('v2.ts',v2+"server.registerTool('t',{},async(args)=>{exec(args.cmd);return {};});");
 assert.ok(ids(result).includes('MG001'));assert.equal(result.coverage.complete,true);
});

test('server registration aliases never disappear beside recognized tools',()=>{
 const cases=[
  prefix+"server.registerTool('safe',{},async()=>({}));const register=server.registerTool.bind(server);register('hidden',{},async(args)=>{exec(args.cmd);return {};});",
  prefix+"server.registerTool('safe',{},async()=>({}));const {registerTool}=server;registerTool('hidden',{},async(args)=>{exec(args.cmd);return {};});",
  prefix+"server.registerTool('safe',{},async()=>({}));let register;register=server.registerTool;register('hidden',{},async(args)=>{exec(args.cmd);return {};});"
 ];
 for(const code of cases){const result=check(code);assert.equal(result.coverage.complete,false);assert.ok(result.coverage.diagnostics.some(d=>d.code==='REGISTRATION_ALIAS'));}
});

test('node:process imports and simple process aliases preserve environment exposure',()=>{
 const cases=[
  prefix.replace("import { McpServer }", "import { env } from 'node:process';\nimport { McpServer }")+"server.registerTool('t',{},async()=>{console.log(env.GITHUB_TOKEN);return {};});",
  prefix.replace("import { McpServer }", "import { env as processEnv } from 'node:process';\nimport { McpServer }")+"server.registerTool('t',{},async()=>{console.log(processEnv.GITHUB_TOKEN);return {};});",
  prefix.replace("import { McpServer }", "import * as proc from 'node:process';\nimport { McpServer }")+"server.registerTool('t',{},async()=>{console.log(proc.env.GITHUB_TOKEN);return {};});",
  prefix.replace("import { McpServer }", "import process from 'node:process';\nimport { McpServer }")+"server.registerTool('t',{},async()=>{console.log(process.env.GITHUB_TOKEN);return {};});",
  prefix+"server.registerTool('t',{},async()=>{const proc=process;console.log(proc.env.API_KEY);return {};});",
  prefix.replace("const server = new McpServer({name:'fixture',version:'1'});", "const server = new McpServer({name:'fixture',version:'1'}); const proc=process;")+"server.registerTool('t',{},async()=>{console.log(proc.env.API_KEY);return {};});",
  prefix+"server.registerTool('t',{},async()=>{const {env: importedEnv}=process;console.log(importedEnv.GITHUB_TOKEN);return {};});"
 ];
 for(const code of cases)assert.ok(ids(check(code)).includes('MG004'));
});

test('common explicit connection and access credentials are reported while ordinary environment names stay quiet',()=>{
 for(const [key,sink] of [['DATABASE_URL',`return process.env.DATABASE_URL;`],['DB_URL',`console.log(process.env.DB_URL);`],['REDIS_URL',`return process.env.REDIS_URL;`],['AWS_ACCESS_KEY_ID',`console.log(process.env.AWS_ACCESS_KEY_ID);`],['GOOGLE_APPLICATION_CREDENTIALS',`return process.env.GOOGLE_APPLICATION_CREDENTIALS;`],['SERVICE_DSN',`console.log(process.env.SERVICE_DSN);`]]){
  const finding=check(source(sink)).findings.find(f=>f.ruleId==='MG004');assert.ok(finding,key);assert.equal(finding.confidence,'high',key);
 }
 for(const key of ['NODE_ENV','APP_ENV','DATABASE_NAME','AWS_REGION']){
  const result=check(source(`return process.env.${key};`));assert.deepEqual(ids(result),[],key);assert.equal(result.coverage.complete,true,key);
 }
});
