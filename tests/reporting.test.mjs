import test from 'node:test';
import assert from 'node:assert/strict';
import { renderHtml, renderTerminal, validateResult } from '../dist/reporting.js';

const result = (extra={}) => ({
  schemaVersion:1,kind:'inventory',target:'demo <inventory>',findings:[{
    ruleId:'MG005',ruleVersion:'1.0.0',title:'Unsafe <name>',category:'descriptor-invalid',severity:'medium',confidence:'high',evidenceType:'metadata-observation',
    locations:[{pointer:'/tools/0/name'}],evidence:'FAKE_SECRET_CANARY_123',observed:'bad <script>alert(1)</script>',why:'Check this & that.',assumptions:[],remediation:'Fix & rescan.',limitations:['Offline only.'],fingerprint:'abc'
  }],
  coverage:{complete:false,inspected:['inventory'],excluded:[],failed:[],truncated:[],recognizedTools:1,unresolvedHandlers:0,rulesApplied:['MG005'],diagnostics:[{code:'MG005_TEST',message:'<img src=x onerror=alert(1)>'}]},
  ...extra
});

test('validateResult accepts the full report contract and preserves safe fields', () => {
  const r=validateResult(result()); assert.equal(r.kind,'inventory'); assert.equal(r.findings[0].locations[0].pointer,'/tools/0/name'); assert.equal(r.coverage.complete,false);
});
test('HTML is a self-contained escaped document', () => {
  const html=renderHtml(result());
  assert.ok(html.startsWith('<!doctype html>')); assert.ok(html.includes('&lt;script&gt;')); assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert.ok(!html.includes('<script')); assert.ok(!html.includes('<img')); assert.ok(!/https?:\/\//.test(html));
});
test('HTML redacts fake canary evidence', () => assert.ok(renderHtml(result()).includes('[REDACTED]')));
test('report validation redacts secret-bearing change metadata keys', () => {
  const r=result({findings:[],changes:[{kind:'metadata',before:{access_token:'opaque-value'}}]});
  assert.equal(validateResult(r).changes[0].before.access_token,'[REDACTED]');
  assert.ok(!renderHtml(r).includes('opaque-value'));
});
test('terminal report includes coverage and pointer evidence', () => {
  const text=renderTerminal(result()); assert.ok(text.includes('Coverage: incomplete')); assert.ok(text.includes('/tools/0/name')); assert.ok(text.includes('[REDACTED]'));
});
test('operator-declared fixture paths are visible without removing findings', () => {
  const r=result({kind:'source',declaredFixtureRoots:['fixtures']});
  r.findings[0].locations=[{file:'fixtures/vulnerable/server.ts',line:8}];
  const other={...r.findings[0],locations:[{file:'src/server.ts',line:9}]};
  r.findings.push(other);
  const checked=validateResult(r),html=renderHtml(r),terminal=renderTerminal(r);
  assert.equal(checked.findings.length,2);
  assert.equal((html.match(/Operator-declared fixture path:/g)??[]).length,1);
  assert.match(terminal,/Context: operator-declared fixture path fixtures\//);
  assert.match(html,/src\/server.ts:9/);
  assert.match(terminal,/Coverage: incomplete/);
  assert.throws(()=>validateResult(result({kind:'source',declaredFixtureRoots:['../src']})),/declaredFixtureRoots/);
  assert.throws(()=>validateResult(result({declaredFixtureRoots:['fixtures']})),/declaredFixtureRoots/);
});
test('reports retain source coordinates, confidence assumptions, rules, and complete coverage exclusions', () => {
  const r=result();
  r.findings[0].confidence='medium';
  r.findings[0].assumptions=['The named handler is reachable from the exported tool.'];
  r.findings[0].locations=[{file:'src/server.ts',line:17,column:9,pointer:'/tools/0'}];
  r.coverage.rulesApplied=['MG001','MG005'];
  r.coverage.inspected=['tool descriptors','schema metadata'];
  r.coverage.excluded=['runtime network behavior'];
  r.coverage.failed=['dynamic handler resolution'];
  r.coverage.truncated=['source scan at configured bound'];
  // Deliberately contradictory producer input must remain visibly incomplete.
  r.coverage.complete=true;
  const html=renderHtml(r), terminal=renderTerminal(r);
  for (const text of [html,terminal]) {
    assert.ok(text.includes('src/server.ts:17:9'));
    assert.ok(text.includes('medium'));
    assert.ok(text.includes('The named handler is reachable from the exported tool.'));
    assert.ok(text.includes('MG001'));
    assert.ok(text.includes('runtime network behavior'));
    assert.ok(text.includes('dynamic handler resolution'));
    assert.ok(text.includes('source scan at configured bound'));
    assert.ok(text.includes('Coverage: incomplete'));
  }
});
test('terminal rendering converts ANSI and control sequences to visible escapes', () => {
  const r=result(); r.target='\u001b[31mred\u001b[0m\u0001';
  const text=renderTerminal(r); assert.ok(text.includes('\\u001b[31m')); assert.ok(text.includes('\\u0001'));
});
test('HTML includes diff observations without raw descriptor dumps or external assets', () => {
  const r=result({kind:'diff',findings:[],changes:[{kind:'tool-description-changed',tool:'x',pointer:'/tools/0/description',before:'<old>',after:'new'}]});
  const html=renderHtml(r); assert.ok(html.includes('&lt;old&gt;')); assert.ok(html.includes('tool-description-changed')); assert.ok(!html.includes('<script')); assert.ok(!html.includes('<link'));
});
test('malformed finding fields and missing locations are rejected', () => {
  const r=result(); delete r.findings[0].fingerprint; assert.throws(()=>validateResult(r),/finding.fingerprint/);
  const noLocations=result(); noLocations.findings[0].locations=[]; assert.throws(()=>validateResult(noLocations),/locations/);
});
test('malformed coverage is rejected rather than rendered as clean', () => {
  const r=result(); delete r.coverage.complete; assert.throws(()=>renderHtml(r),/coverage must include/);
  const bad=result(); bad.coverage.recognizedTools=-1; assert.throws(()=>validateResult(bad),/non-negative integer/);
});
test('coverage with unresolved handlers or a source scan with no recognized tools cannot be rendered complete', () => {
  const unresolved=result({kind:'source',findings:[],coverage:{complete:true,inspected:['server.ts'],excluded:[],failed:[],truncated:[],recognizedTools:1,unresolvedHandlers:1,rulesApplied:['MG001'],diagnostics:[]}});
  assert.equal(validateResult(unresolved).coverage.complete,false);
  assert.match(renderHtml(unresolved),/class="coverage incomplete"/);
  assert.match(renderTerminal(unresolved),/Coverage: incomplete/);

  const noTools=result({kind:'source',findings:[],coverage:{complete:true,inspected:['server.ts'],excluded:[],failed:[],truncated:[],recognizedTools:0,unresolvedHandlers:0,rulesApplied:['MG001'],diagnostics:[]}});
  assert.equal(validateResult(noTools).coverage.complete,false);

  // An empty inventory is still a valid complete inventory audit.
  const emptyInventory=result({kind:'inventory',findings:[],coverage:{complete:true,inspected:['inventory envelope','tool descriptors'],excluded:[],failed:[],truncated:[],recognizedTools:0,unresolvedHandlers:0,rulesApplied:['MG005'],diagnostics:[]}});
  assert.equal(validateResult(emptyInventory).coverage.complete,true);
});
test('malformed change data and unsafe nested keys are rejected', () => {
  assert.throws(()=>validateResult(result({changes:[{}]})),/change requires/);
  const unsafe=JSON.parse('{"schemaVersion":1,"kind":"inventory","target":"x","findings":[],"coverage":{"complete":true,"inspected":[],"excluded":[],"failed":[],"truncated":[],"recognizedTools":0,"unresolvedHandlers":0,"rulesApplied":[],"diagnostics":[],"constructor":{}}}');
  assert.throws(()=>validateResult(unsafe),/unsafe property/);
});
test('unbounded reports are rejected', () => {
  const huge=result(); huge.target='x'.repeat(1_050_000); assert.throws(()=>validateResult(huge),/byte limit/);
});
test('context-only report with no findings renders a deterministic empty state', () => {
  const r=result({findings:[]}); delete r.changes;
  assert.equal(renderTerminal(r),renderTerminal(r)); assert.ok(renderHtml(r).includes('No findings recorded.'));
});
