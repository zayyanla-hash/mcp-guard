import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyIsolation,launchFixture,IsolationBlocked} from '../dist/isolation.js';
test('OS backend either verifies all denial controls or blocks explicitly',async()=>{
 if(process.platform==='darwin'){
  process.env.MCP_GUARD_FAKE_SECRET='FAKE_SECRET_CANARY_ENV';
  const result=await verifyIsolation();delete process.env.MCP_GUARD_FAKE_SECRET;assert.equal(result.verified,true);
  assert.deepEqual(result.controls,{read:true,write:true,spawn:true,network:true,environment:true});
 }else await assert.rejects(verifyIsolation(),IsolationBlocked);
});
test('launcher refuses arbitrary project code before execution',async()=>{
 await assert.rejects(launchFixture('fixtures/vulnerable/server.ts'),IsolationBlocked);
});

test('timeout and cancellation remove only the launched child',async()=>{
 if(process.platform!=='darwin'){await assert.rejects(launchFixture('fixtures/discovery/timeout.mjs'),IsolationBlocked);return;}
 for(const cancel of [false,true]){
  const controller=new AbortController();const child=await launchFixture('fixtures/discovery/timeout.mjs',{timeoutMs:150,signal:controller.signal});
  if(cancel)controller.abort();const exit=await child.exit;assert.equal(exit.signal,'SIGKILL');
  assert.throws(()=>process.kill(child.pid,0),{code:'ESRCH'});
 }
});
