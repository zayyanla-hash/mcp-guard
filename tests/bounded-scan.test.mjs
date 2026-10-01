import test from 'node:test';
import assert from 'node:assert/strict';
import {scanSourceBounded} from '../dist/bounded-scan.js';
import {LIMITS} from '../dist/scanner.js';
import {policyExit} from '../dist/policy.js';
test('parent watchdog terminates whole traversal and reports incomplete',async()=>{
 const start=Date.now();const scan=await scanSourceBounded('fixtures/vulnerable',{...LIMITS,milliseconds:1});
 assert.equal(policyExit(scan),3);assert.ok(scan.coverage.diagnostics.some(d=>d.code==='SCAN_TIMEOUT'));assert.ok(Date.now()-start<3000);
});
test('cancellation never becomes a clean scan',async()=>{
 const signal=AbortSignal.abort();const scan=await scanSourceBounded('fixtures/vulnerable',LIMITS,signal);
 assert.equal(policyExit(scan),3);assert.ok(scan.coverage.diagnostics.some(d=>d.code==='SCAN_CANCELLED'));
});
test('complete bounded source scan preserves actual evidence',async()=>{
 const scan=await scanSourceBounded('fixtures/vulnerable');assert.equal(policyExit(scan),1);assert.equal(scan.findings.length,5);assert.ok(scan.findings.every(f=>f.locations[0].line>0));
});
