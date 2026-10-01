import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { auditInventory, snapshotInventory, diffSnapshots } from '../dist/inventory.js';
import { hash } from '../dist/shared.js';

const load = async name => JSON.parse(await readFile(new URL(`../fixtures/inventories/${name}.json`, import.meta.url), 'utf8'));
const clone = v => JSON.parse(JSON.stringify(v));
const base = () => ({tools:[{name:'lookup',inputSchema:{type:'object',properties:{id:{type:'string'}},required:['id']}}]});

test('valid fixture is completely inspected without findings', async () => {
  const r = auditInventory(await load('valid'));
  assert.equal(r.kind,'inventory'); assert.equal(r.coverage.complete,true); assert.deepEqual(r.findings,[]); assert.equal(r.coverage.recognizedTools,1);
});
test('vulnerable fixture is identified as a descriptor defect and corrected fixture is valid', async () => {
  const bad=auditInventory(await load('vulnerable')), good=auditInventory(await load('corrected'));
  assert.ok(bad.findings.some(f=>f.ruleId==='MG005' && f.category==='descriptor-invalid'));
  assert.equal(good.coverage.complete,true); assert.deepEqual(good.findings,[]);
});
test('an empty but valid permissive schema is not reported as a vulnerability', () => {
  const r = auditInventory({tools:[{name:'any',inputSchema:{}}]});
  assert.equal(r.coverage.complete,true); assert.equal(r.findings.length,0);
});
test('malformed envelope yields descriptor finding and failed coverage', () => {
  const r = auditInventory({});
  assert.equal(r.coverage.complete,false); assert.equal(r.findings[0].category,'descriptor-invalid'); assert.equal(r.findings[0].locations[0].pointer,'/tools');
});
test('non-object envelope is invalid', () => assert.equal(auditInventory([]).findings[0].category,'descriptor-invalid'));
test('missing name and required input schema are distinct findings', () => {
  const r=auditInventory({tools:[{}]}); assert.equal(r.findings.length,2); assert.deepEqual(r.findings.map(f=>f.locations[0].pointer),['/tools/0/name','/tools/0/inputSchema']);
});
test('duplicate names are invalid and identify second occurrence', async () => {
  const r=auditInventory(await load('invalid'));
  assert.ok(r.findings.some(f=>f.title==='Duplicate tool name' && f.locations[0].pointer==='/tools/1/name'));
  assert.ok(r.findings.some(f=>f.category==='schema-invalid'));
});
test('invalid schema format type is meta-schema checked', () => {
  const r=auditInventory({tools:[{name:'x',inputSchema:{type:'nonsense'}}]}); assert.ok(r.findings.some(f=>f.category==='schema-invalid'));
});
test('ordinary constraints are accepted without evaluating input data', () => {
  const r=auditInventory({tools:[{name:'x',inputSchema:{type:'object',properties:{n:{type:'integer',minimum:2}},additionalProperties:false}}]});
  assert.equal(r.coverage.complete,true); assert.equal(r.findings.length,0);
});
test('remote refs are never fetched and produce incomplete coverage', async () => {
  const r=auditInventory(await load('unsupported'));
  assert.equal(r.coverage.complete,false); assert.ok(r.coverage.diagnostics.some(d=>d.code==='MG005_UNRESOLVED_REMOTE_REF'));
});
test('unsupported advertised protocol version is surfaced', () => {
  const r=auditInventory({protocolVersion:'2099-01-01',tools:[]}); assert.equal(r.coverage.complete,false); assert.equal(r.coverage.diagnostics[0].code,'MG005_UNSUPPORTED_PROTOCOL_VERSION');
});
test('absent protocol version and absent metadata are acceptable', () => assert.equal(auditInventory({tools:[]}).coverage.complete,true));
test('unsupported custom schema keyword is surfaced distinctly', () => {
  const r=auditInventory({tools:[{name:'x',inputSchema:{type:'object',customPolicy:true}}]}); assert.equal(r.findings.length,0); assert.ok(r.coverage.diagnostics.some(d=>d.code==='MG005_UNSUPPORTED_SCHEMA_FEATURE'));
});
test('wrong dialect is incomplete without pretending invalidity', () => {
  const r=auditInventory({tools:[{name:'x',inputSchema:{$schema:'http://json-schema.org/draft-07/schema#',type:'object'}}]});
  assert.equal(r.findings.length,0); assert.equal(r.coverage.complete,false); assert.ok(r.coverage.diagnostics.some(d=>d.code==='MG005_UNSUPPORTED_SCHEMA_DIALECT'));
});
test('schema feature scan respects arbitrary property names', () => {
  const r=auditInventory({tools:[{name:'x',inputSchema:{properties:{someApplicationField:{type:'string'}}}}]}); assert.equal(r.coverage.complete,true);
});
test('dangerous object keys are rejected before scanning', () => {
  const value=JSON.parse('{"tools":[],"__proto__":{"polluted":true}}'); assert.throws(()=>auditInventory(value),/Unsafe property/);
});
test('tool count, depth, node and byte bounds fail closed', () => {
  assert.throws(()=>auditInventory({tools:Array.from({length:1001},(_,i)=>({name:`t${i}`,inputSchema:{}}))}),/tool limit/);
  let deep={}; for(let i=0;i<41;i++) deep={x:deep}; assert.throws(()=>auditInventory(deep),/depth limit/);
  assert.throws(()=>auditInventory({tools:[{name:'x',inputSchema:{description:'x'.repeat(1_050_000)}}]}),/byte limit/);
});
test('snapshot is deterministic across object key order while array order remains observable', () => {
  const first=snapshotInventory({tools:[{name:'x',inputSchema:{type:'object',properties:{a:{type:'string'},b:{type:'number'}},required:['a','b']}}]});
  const reordered=snapshotInventory({tools:[{inputSchema:{properties:{b:{type:'number'},a:{type:'string'}},required:['a','b'],type:'object'},name:'x'}]});
  assert.equal(first.hash,reordered.hash);
  const arrayChanged=snapshotInventory({tools:[{name:'x',inputSchema:{type:'object',properties:{a:{type:'string'},b:{type:'number'}},required:['b','a']}}]});
  assert.notEqual(first.hash,arrayChanged.hash);
});
test('snapshot rejects secret-bearing acquisition context', () => {
  assert.throws(()=>snapshotInventory({tools:[],acquisition:{apiKey:'FAKE_SECRET_CANARY_123'}}),/secret-bearing metadata/);
  assert.throws(()=>snapshotInventory({tools:[],metadata:{access_token:'opaque'}}),/secret-bearing metadata/);
});
test('snapshot rejects canary strings and secret keys anywhere in tool metadata before hashing', () => {
  assert.throws(() => snapshotInventory({tools:[{name:'lookup',description:'diagnostic FAKE_SECRET_CANARY_123',inputSchema:{}}]}), /secret-bearing metadata.*\/tools\/0\/description/);
  assert.throws(() => snapshotInventory({tools:[{name:'lookup',inputSchema:{},vendorMetadata:{clientSecret:'fixture-value'}}]}), /secret-bearing metadata.*\/tools\/0\/vendorMetadata\/clientSecret/);
  // Imported snapshots receive the same check, even when their content hash is valid.
  const payload={tools:[{name:'lookup',description:'CANARY_ALPHA_123',inputSchema:{}}]};
  assert.throws(() => diffSnapshots(snapshotInventory(base()), {schemaVersion:1,kind:'inventory-snapshot',hash:hash(payload),payload}), /secret-bearing metadata/);
});
test('schema property names may look sensitive, but schema values remain scanned and metadata keys stay rejected', () => {
  const value={tools:[{name:'lookup',inputSchema:{type:'object',properties:{apiKey:{type:'string'},token:{type:'string'}},$defs:{clientSecret:{type:'string'}}}}]};
  assert.doesNotThrow(()=>snapshotInventory(value));
  const canary=clone(value); canary.tools[0].inputSchema.properties.apiKey.default='FAKE_SECRET_CANARY_IN_SCHEMA';
  assert.throws(()=>snapshotInventory(canary),/secret-bearing metadata.*apiKey\/default/);
  const metadataKey=clone(value); metadataKey.tools[0].vendorMetadata={clientSecret:'ordinary-value'};
  assert.throws(()=>snapshotInventory(metadataKey),/secret-bearing metadata.*vendorMetadata\/clientSecret/);
});
test('known annotation fields require documented value types', () => {
  const r=auditInventory({tools:[{name:'lookup',inputSchema:{},annotations:{title:false,readOnlyHint:'yes',destructiveHint:0,idempotentHint:null,openWorldHint:{}}}]});
  assert.deepEqual(r.findings.map(f=>f.locations[0].pointer),[
    '/tools/0/annotations/title','/tools/0/annotations/readOnlyHint','/tools/0/annotations/destructiveHint','/tools/0/annotations/idempotentHint','/tools/0/annotations/openWorldHint'
  ]);
  const good=auditInventory({tools:[{name:'lookup',inputSchema:{},annotations:{title:'Read record',readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false}}]});
  assert.equal(good.coverage.complete,true); assert.deepEqual(good.findings,[]);
});
test('snapshot rejects invalid and incomplete inventory', async () => {
  const invalid = await load('invalid'), unsupported = await load('unsupported');
  assert.throws(()=>snapshotInventory(invalid),/Cannot snapshot invalid/);
  assert.throws(()=>snapshotInventory(unsupported),/Cannot snapshot invalid/);
});
test('diff reports tool and selected descriptor field changes without widening claim', () => {
  const before=snapshotInventory({tools:[{name:'a',description:'old',inputSchema:{type:'object',required:['id']}}]});
  const after=snapshotInventory({tools:[{name:'a',description:'new',inputSchema:{type:'object',required:[]}}, {name:'b',inputSchema:{}}]});
  const r=diffSnapshots(before,after);
  assert.ok(r.changes.some(c=>c.kind==='tool-added'&&c.tool==='b'));
  assert.ok(r.changes.some(c=>c.kind==='tool-description-changed'&&c.tool==='a'));
  assert.ok(r.changes.some(c=>c.kind==='required-input-removed'&&c.before==='id'));
  assert.deepEqual(r.findings,[]);
});
test('unchanged snapshots have no diff observations', () => {
  const s=snapshotInventory(base()); assert.deepEqual(diffSnapshots(s,clone(s)).changes,[]);
});
test('tampered snapshot payload and malformed hash are rejected', () => {
  const s=snapshotInventory(base()); const tampered=clone(s); tampered.payload.tools[0].name='evil';
  assert.throws(()=>diffSnapshots(s,tampered),/hash does not match/);
  assert.throws(()=>diffSnapshots(s,{...s,hash:'bad'}),/invalid envelope or hash/);
});
test('metadata or acquisition context drift is reported and marks coverage incomplete', () => {
  const a=snapshotInventory({tools:[],metadata:{source:'one'}}), b=snapshotInventory({tools:[],metadata:{source:'two'}});
  const r=diffSnapshots(a,b); assert.equal(r.coverage.complete,false); assert.ok(r.changes.some(c=>c.kind==='inventory-context-changed'));
});
test('diff marks missing or unknown acquisition and authorization context incomplete', () => {
  const explicit={tools:[],acquisitionContext:{transport:'stdio',authorization:'none',source:'owned fixture'}};
  for (const acquisitionContext of [undefined,{transport:'unknown',authorization:'none',source:'owned fixture'},{transport:'stdio',authorization:'unknown',source:'owned fixture'}]) {
    const payload=acquisitionContext===undefined?{tools:[]}:{...explicit,acquisitionContext};
    const r=diffSnapshots(snapshotInventory(explicit),snapshotInventory(payload));
    assert.equal(r.coverage.complete,false);
    assert.ok(r.coverage.diagnostics.some(d=>d.code==='MG005_ACQUISITION_CONTEXT_UNKNOWN'));
  }
});
test('unknown top-level metadata is preserved in snapshots and context drift is visible', () => {
  const a=snapshotInventory({tools:[],vendorInfo:{region:'a'}}), b=snapshotInventory({tools:[],vendorInfo:{region:'b'}});
  assert.notEqual(a.hash,b.hash); assert.ok(diffSnapshots(a,b).changes.some(c=>c.kind==='inventory-context-changed'));
});
test('unknown per-tool metadata drift is surfaced as incomplete context', () => {
  const a=snapshotInventory({tools:[{name:'x',inputSchema:{},vendorTag:{zone:'a'}}]});
  const b=snapshotInventory({tools:[{name:'x',inputSchema:{},vendorTag:{zone:'b'}}]});
  const r=diffSnapshots(a,b); assert.equal(r.coverage.complete,false); assert.ok(r.changes.some(c=>c.kind==='tool-extra-metadata-changed'));
});
test('tool array order drift is reported explicitly', () => {
  const a=snapshotInventory({tools:[{name:'a',inputSchema:{}},{name:'b',inputSchema:{}}]});
  const b=snapshotInventory({tools:[{name:'b',inputSchema:{}},{name:'a',inputSchema:{}}]});
  assert.ok(diffSnapshots(a,b).changes.some(c=>c.kind==='tool-order-changed'));
});
test('drift fixture demonstrates named tool and schema drift', async () => {
  const before=snapshotInventory(await load('valid')), after=snapshotInventory(await load('drift'));
  const r=diffSnapshots(before,after); assert.equal(r.coverage.complete,true);
  assert.ok(!r.changes.some(c=>c.kind==='inventory-context-changed'));
  assert.ok(r.changes.some(c=>c.kind==='tool-added'&&c.tool==='search'));
  assert.ok(r.changes.some(c=>c.kind==='tool-description-changed'&&c.tool==='lookup'));
  assert.ok(r.changes.some(c=>c.kind==='required-input-removed'&&c.tool==='lookup'));
});
test('input inventory is never mutated', () => {
  const value=base(), before=JSON.stringify(value); auditInventory(value); snapshotInventory(value); assert.equal(JSON.stringify(value),before);
});
