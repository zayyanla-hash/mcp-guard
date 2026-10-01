import { Ajv2020 } from 'ajv/dist/2020.js';
import { canonical, coverage, finding, hash, redactText } from './shared.js';
import type { AuditResult, Diagnostic, Snapshot } from './types.js';

const MAX_BYTES = 1_048_576;
const MAX_DEPTH = 40;
const MAX_NODES = 50_000;
const MAX_TOOLS = 1_000;
const SUPPORTED_PROTOCOLS = new Set(['2026-07-28', '2025-11-25']);
const JSON_SCHEMA_2020 = 'https://json-schema.org/draft/2020-12/schema';
const isSensitiveKey = (key: string) => {
  const normalized = key.replace(/[^a-z0-9]/gi, '').toLowerCase();
  return ['password','secret','token','apikey','authorization','privatekey','credential'].some(part => normalized.includes(part));
};
const STANDARD_SCHEMA_KEYS = new Set((
  '$schema $id $anchor $dynamicAnchor $ref $dynamicRef $vocabulary $comment title description default deprecated readOnly writeOnly examples type enum const multipleOf maximum exclusiveMaximum minimum exclusiveMinimum maxLength minLength pattern maxItems minItems uniqueItems maxContains minContains maxProperties minProperties required properties patternProperties additionalProperties dependencies dependentRequired dependentSchemas propertyNames if then else allOf anyOf oneOf not items prefixItems contains unevaluatedItems unevaluatedProperties format contentMediaType contentEncoding contentSchema definitions $defs'
).split(/\s+/));
const SCHEMA_MAP_KEYS = new Set(['properties','patternProperties','$defs','definitions','dependentSchemas']);
const SCHEMA_ARRAY_KEYS = new Set(['allOf','anyOf','oneOf','prefixItems']);
const SCHEMA_CHILD_KEYS = new Set(['additionalProperties','unevaluatedProperties','unevaluatedItems','items','contains','not','if','then','else','contentSchema','propertyNames']);

type Obj = Record<string, unknown>;
const isObject = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);
const ptr = (parts: Array<string | number>) => '/' + parts.map(p => String(p).replace(/~/g, '~0').replace(/\//g, '~1')).join('/');
function inspectBounds(value: unknown): { bytes: number; nodes: number; deepest: number } {
  let nodes = 0, deepest = 0;
  const walk = (v: unknown, d: number): void => {
    nodes++; deepest = Math.max(deepest, d);
    if (nodes > MAX_NODES) throw new Error(`Inventory exceeds the ${MAX_NODES} node limit.`);
    if (d > MAX_DEPTH) throw new Error(`Inventory exceeds the ${MAX_DEPTH} level depth limit.`);
    if (Array.isArray(v)) { for (const x of v) walk(x, d + 1); }
    else if (isObject(v)) {
      for (const [k, x] of Object.entries(v)) {
        if (k === '__proto__' || k === 'prototype' || k === 'constructor') throw new Error(`Unsafe property name at ${k}.`);
        walk(x, d + 1);
      }
    } else if (typeof v === 'number' && !Number.isFinite(v)) throw new Error('Inventory contains a non-finite number.');
    else if (typeof v === 'undefined' || typeof v === 'function' || typeof v === 'symbol' || typeof v === 'bigint') throw new Error('Inventory must contain JSON-compatible values only.');
  };
  walk(value, 0);
  let serialized: string;
  try { serialized = JSON.stringify(value); } catch { throw new Error('Inventory is not valid JSON data.'); }
  if (serialized === undefined) throw new Error('Inventory is not valid JSON data.');
  const bytes = new TextEncoder().encode(serialized).length;
  if (bytes > MAX_BYTES) throw new Error(`Inventory exceeds the ${MAX_BYTES} byte limit.`);
  return { bytes, nodes, deepest };
}

function schemaFeatures(schema: unknown, at: string, diagnostics: Diagnostic[]): void {
  if (!isObject(schema)) return;
  const o = schema;
  for (const [key, value] of Object.entries(o)) {
    const here = `${at}/${key.replace(/~/g, '~0').replace(/\//g, '~1')}`;
    if (!STANDARD_SCHEMA_KEYS.has(key)) diagnostics.push({ code: 'MG005_UNSUPPORTED_SCHEMA_FEATURE', message: `Schema keyword "${key}" is outside the supported JSON Schema 2020-12 subset.`, pointer: here });
    if (key === '$ref' && typeof value === 'string' && !value.startsWith('#')) diagnostics.push({ code: 'MG005_UNRESOLVED_REMOTE_REF', message: 'Remote or external $ref was not fetched; schema coverage is incomplete.', pointer: here });
    if (key === '$dynamicRef' && typeof value === 'string') diagnostics.push({ code: 'MG005_UNSUPPORTED_SCHEMA_FEATURE', message: 'Dynamic references are outside the supported inventory subset.', pointer: here });
    if (key === 'format' && typeof value === 'string' && value !== 'date-time' && value !== 'date' && value !== 'time' && value !== 'email' && value !== 'hostname' && value !== 'ipv4' && value !== 'ipv6' && value !== 'uri' && value !== 'uri-reference' && value !== 'uuid' && value !== 'regex' && value !== 'json-pointer' && value !== 'relative-json-pointer' && value !== 'uri-template') {
      diagnostics.push({ code: 'MG005_UNSUPPORTED_SCHEMA_FEATURE', message: `Custom format "${value}" is not evaluated by this offline auditor.`, pointer: here });
    }
    if (SCHEMA_MAP_KEYS.has(key) && isObject(value)) for (const [name, child] of Object.entries(value)) schemaFeatures(child, `${here}/${name.replace(/~/g, '~0').replace(/\//g, '~1')}`, diagnostics);
    else if (SCHEMA_ARRAY_KEYS.has(key) && Array.isArray(value)) value.forEach((child, i) => schemaFeatures(child, `${here}/${i}`, diagnostics));
    else if (SCHEMA_CHILD_KEYS.has(key)) schemaFeatures(value, here, diagnostics);
  }
}

type LocalRef = { ref: string; pointer: string; resource: unknown; resourcePath: string };
function schemaChildren(schema: Obj): Array<[string[], unknown]> {
  const children: Array<[string[], unknown]> = [];
  for (const [key, value] of Object.entries(schema)) {
    if (SCHEMA_MAP_KEYS.has(key) && isObject(value)) {
      for (const [name, child] of Object.entries(value)) children.push([[key,name], child]);
    } else if (SCHEMA_ARRAY_KEYS.has(key) && Array.isArray(value)) {
      value.forEach((child, index) => children.push([[key,String(index)], child]));
    } else if (SCHEMA_CHILD_KEYS.has(key)) children.push([[key], value]);
  }
  return children;
}
function pointerTarget(root: unknown, fragment: string): unknown {
  if (fragment === '') return root;
  if (!fragment.startsWith('/')) return undefined;
  let current = root;
  for (const raw of fragment.slice(1).split('/')) {
    if (/~(?:[^01]|$)/.test(raw)) return undefined;
    const part = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    if (Array.isArray(current)) {
      if (!/^(0|[1-9]\d*)$/.test(part)) return undefined;
      current = current[Number(part)];
    } else if (isObject(current) && Object.hasOwn(current, part)) current = current[part];
    else return undefined;
    if (current === undefined) return undefined;
  }
  return current;
}
function checkLocalRefs(schema: Obj, at: string, diagnostics: Diagnostic[]): void {
  const refs: LocalRef[] = [];
  const anchors = new Map<string, Set<string>>();
  const visit = (node: unknown, pointer: string, resource: unknown, resourcePath: string): void => {
    if (!isObject(node)) return;
    if (typeof node.$id === 'string' && pointer !== resourcePath) {
      resource = node;
      resourcePath = pointer;
    }
    for (const key of ['$anchor','$dynamicAnchor'] as const) {
      const name = node[key];
      if (typeof name === 'string') {
        let names = anchors.get(resourcePath);
        if (!names) anchors.set(resourcePath, names = new Set());
        names.add(name);
      }
    }
    if (typeof node.$ref === 'string' && node.$ref.startsWith('#')) refs.push({ref:node.$ref,pointer:`${pointer}/$ref`,resource,resourcePath});
    for (const [childPath, child] of schemaChildren(node)) visit(child, `${pointer}/${childPath.map(part=>part.replace(/~/g,'~0').replace(/\//g,'~1')).join('/')}`, resource, resourcePath);
  };
  const initialResourcePath = typeof schema.$id === 'string' ? at : '';
  visit(schema, at, schema, initialResourcePath);
  for (const ref of refs) {
    let fragment: string;
    try { fragment = decodeURIComponent(ref.ref.slice(1)); }
    catch { diagnostics.push({code:'MG005_UNRESOLVED_LOCAL_REF',message:'Local $ref has an invalid percent-encoded fragment.',pointer:ref.pointer}); continue; }
    if (fragment === '') continue; // A fragment-only self-reference resolves to its current schema resource.
    if (fragment.startsWith('/')) {
      const target = pointerTarget(ref.resource, fragment);
      if (!(isObject(target) || typeof target === 'boolean')) diagnostics.push({code:'MG005_UNRESOLVED_LOCAL_REF',message:'Local $ref JSON Pointer does not resolve to a JSON Schema object or boolean schema.',pointer:ref.pointer});
    } else if (!anchors.get(ref.resourcePath)?.has(fragment)) {
      diagnostics.push({code:'MG005_UNRESOLVED_LOCAL_REF',message:'Local $ref anchor is not declared in its schema resource.',pointer:ref.pointer});
    }
  }
}

function secretInMetadata(value: unknown, path: string[] = []): string | undefined {
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) { const found = secretInMetadata(value[i], [...path, String(i)]); if (found) return found; }
  } else if (isObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      const next = [...path, k];
      // This exact field is provenance metadata, not a credential. Keep the
      // value scan below active so canaries or credential-shaped values fail.
      const isAcquisitionAuthorization = k === 'authorization' && path.at(-1) === 'acquisitionContext';
      // Schema map keys name properties/definitions. Treat those names as
      // identifiers, while recursively checking their schema values as usual.
      const isSchemaMapName = ['properties','patternProperties','$defs','definitions','dependentSchemas'].includes(path.at(-1) ?? '')
        && path[0] === 'tools'
        && /^\d+$/.test(path[1] ?? '')
        && (path[2] === 'inputSchema' || path[2] === 'outputSchema');
      if (isSensitiveKey(k) && !isAcquisitionAuthorization && !isSchemaMapName) return ptr(next);
      const found = secretInMetadata(v, next); if (found) return found;
    }
  } else if (typeof value === 'string' && redactText(value) !== value) return ptr(path);
  return undefined;
}

export function auditInventory(value: unknown): AuditResult {
  inspectBounds(value);
  const result: AuditResult = { schemaVersion: 1, kind: 'inventory', target: 'MCP inventory', findings: [], coverage: coverage(['MG005']) };
  result.coverage.inspected.push('inventory envelope', 'tool descriptors', 'input schemas', 'output schemas', 'protocol version');
  const invalid = (title: string, category: string, pointer: string, observed: string, why: string, remediation: string) => {
    result.findings.push(finding({ ruleId:'MG005', title, category, severity:'medium', confidence:'high', evidenceType:'metadata-observation', locations:[{pointer}], evidence:`Observed ${observed} at ${pointer}.`, observed, why, assumptions:[], remediation, limitations:['Offline descriptor inspection cannot establish server runtime behavior.'] }));
  };
  const diag = (code: string, message: string, pointer?: string) => {
    result.coverage.diagnostics.push({ code, message: redactText(message), ...(pointer ? { pointer } : {}) });
    result.coverage.complete = false;
  };
  if (!isObject(value)) {
    invalid('Invalid inventory envelope', 'descriptor-invalid', '', 'inventory is not an object', 'The inventory must be a JSON object containing a tools array.', 'Provide a JSON object with a tools array of MCP tool descriptors.');
    result.coverage.complete = false; result.coverage.failed.push('inventory envelope'); return result;
  }
  const root = value;
  if (!Array.isArray(root.tools)) {
    invalid('Invalid inventory envelope', 'descriptor-invalid', '/tools', 'tools is missing or is not an array', 'Tool descriptors cannot be audited without a tools array.', 'Provide tools as an array.');
    result.coverage.complete = false; result.coverage.failed.push('tool descriptors'); return result;
  }
  if (root.tools.length > MAX_TOOLS) throw new Error(`Inventory exceeds the ${MAX_TOOLS} tool limit.`);
  result.coverage.recognizedTools = root.tools.length;
  if (root.protocolVersion !== undefined && (typeof root.protocolVersion !== 'string' || !SUPPORTED_PROTOCOLS.has(root.protocolVersion))) {
    diag('MG005_UNSUPPORTED_PROTOCOL_VERSION', `Advertised protocolVersion ${String(root.protocolVersion)} is not in the supported descriptor envelope set.`, '/protocolVersion');
  }
  const names = new Map<string, number>();
  const validator = new Ajv2020({ validateFormats:false, strict:false, allErrors:true, loadSchema: undefined });
  for (let i = 0; i < root.tools.length; i++) {
    const tool = root.tools[i];
    const base = `/tools/${i}`;
    if (!isObject(tool)) {
      invalid('Invalid tool descriptor', 'descriptor-invalid', base, 'tool descriptor is not an object', 'Each inventory entry must be an object with a name and inputSchema.', 'Provide a valid tool descriptor object.');
      continue;
    }
    if (typeof tool.name !== 'string' || !tool.name.trim()) invalid('Invalid tool descriptor', 'descriptor-invalid', `${base}/name`, 'tool name is missing or empty', 'Tool names identify descriptors and must be non-empty strings.', 'Provide a non-empty tool name.');
    else {
      const first = names.get(tool.name);
      if (first !== undefined) invalid('Duplicate tool name', 'descriptor-invalid', `${base}/name`, `duplicate tool name ${tool.name}`, 'Duplicate names make inventory identity and drift comparison ambiguous.', 'Give every tool a unique name.');
      else names.set(tool.name, i);
    }
    if (!Object.hasOwn(tool, 'inputSchema')) invalid('Invalid tool descriptor', 'descriptor-invalid', `${base}/inputSchema`, 'inputSchema is missing', 'An input schema is required for an MCP tool descriptor.', 'Provide an inputSchema object.');
    for (const field of ['description'] as const) if (tool[field] !== undefined && typeof tool[field] !== 'string') invalid('Invalid tool descriptor', 'descriptor-invalid', `${base}/${field}`, `${field} is not a string`, 'Optional descriptor text fields must use their documented string type.', `Provide ${field} as a string or omit it.`);
    if (tool.annotations !== undefined) {
      if (!isObject(tool.annotations)) invalid('Invalid tool descriptor', 'descriptor-invalid', `${base}/annotations`, 'annotations is not an object', 'Optional annotations must be an object when present.', 'Provide annotations as an object or omit it.');
      else {
        const annotations = tool.annotations;
        if (annotations.title !== undefined && typeof annotations.title !== 'string') invalid('Invalid tool annotation', 'descriptor-invalid', `${base}/annotations/title`, 'annotation title is not a string', 'An annotation title must be a string when present.', 'Provide annotations.title as a string or omit it.');
        for (const key of ['readOnlyHint','destructiveHint','idempotentHint','openWorldHint'] as const) {
          if (annotations[key] !== undefined && typeof annotations[key] !== 'boolean') invalid('Invalid tool annotation', 'descriptor-invalid', `${base}/annotations/${key}`, `annotation ${key} is not a boolean`, `The ${key} annotation must be a boolean when present.`, `Provide annotations.${key} as a boolean or omit it.`);
        }
      }
    }
    for (const field of ['inputSchema','outputSchema'] as const) {
      if (tool[field] === undefined) continue;
      const schema = tool[field];
      if (!isObject(schema)) {
        invalid('Invalid tool schema', 'schema-invalid', `${base}/${field}`, `${field} is not an object`, 'A JSON Schema descriptor must be an object.', 'Provide a valid JSON Schema 2020-12 object.');
        continue;
      }
      const dialect = schema.$schema;
      if (dialect !== undefined && dialect !== JSON_SCHEMA_2020) {
        diag('MG005_UNSUPPORTED_SCHEMA_DIALECT', `Schema dialect ${String(dialect)} is not supported; only JSON Schema 2020-12 is inspected.`, `${base}/${field}/$schema`);
        continue;
      }
      const featuresBefore = result.coverage.diagnostics.length;
      schemaFeatures(schema, `${base}/${field}`, result.coverage.diagnostics);
      checkLocalRefs(schema, `${base}/${field}`, result.coverage.diagnostics);
      if (result.coverage.diagnostics.length > featuresBefore) result.coverage.complete = false;
      if (!validator.validateSchema(schema)) {
        const errors = validator.errors?.map(e => `${e.instancePath || base}/${field}: ${e.message || 'invalid schema'}`).join('; ') || 'schema failed JSON Schema 2020-12 meta-validation';
        invalid('Invalid tool schema', 'schema-invalid', `${base}/${field}`, 'schema failed JSON Schema 2020-12 meta-validation', errors, 'Correct the schema so it validates against JSON Schema 2020-12.');
      }
    }
  }
  return result;
}

function contextProjection(value: Obj): unknown {
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'tools'));
}

export function snapshotInventory(value: unknown): Snapshot {
  const audited = auditInventory(value);
  if (audited.findings.length || !audited.coverage.complete) {
    const reason = audited.coverage.diagnostics[0]?.message ?? audited.findings[0]?.observed ?? 'inventory is incomplete';
    throw new Error(`Cannot snapshot invalid or incomplete inventory: ${reason}`);
  }
  if (!isObject(value)) throw new Error('Cannot snapshot: inventory is not an object.');
  // Reject secret-like strings anywhere in the snapshot payload before hashing or persistence.
  // Redacting these strings here would make the stored payload differ from the source inventory.
  const metadataPath = secretInMetadata(value);
  if (metadataPath) throw new Error(`Cannot snapshot: secret-bearing metadata or acquisition context at ${metadataPath}.`);
  const payload = JSON.parse(JSON.stringify(value)) as unknown;
  return { schemaVersion:1, kind:'inventory-snapshot', hash:hash(payload), payload };
}

function toolMap(value: Obj): Map<string, Obj> {
  const out = new Map<string, Obj>();
  for (const t of value.tools as unknown[]) if (isObject(t) && typeof t.name === 'string') out.set(t.name, t);
  return out;
}
function validSnapshot(input: unknown, label: string): Snapshot {
  if (!isObject(input) || input.schemaVersion !== 1 || input.kind !== 'inventory-snapshot' || typeof input.hash !== 'string' || !/^[a-f0-9]{64}$/.test(input.hash)) throw new Error(`${label} snapshot has an invalid envelope or hash.`);
  inspectBounds(input);
  const actual = hash(input.payload);
  if (actual !== input.hash) throw new Error(`${label} snapshot hash does not match its payload.`);
  const checked = auditInventory(input.payload);
  if (checked.findings.length || !checked.coverage.complete) throw new Error(`${label} snapshot payload is invalid or incomplete.`);
  const sensitivePath = secretInMetadata(input.payload);
  if (sensitivePath) throw new Error(`${label} snapshot payload contains secret-bearing metadata at ${sensitivePath}.`);
  return input as unknown as Snapshot;
}

export function diffSnapshots(before: unknown, after: unknown): AuditResult {
  const a = validSnapshot(before, 'Before');
  const b = validSnapshot(after, 'After');
  const av = a.payload as Obj, bv = b.payload as Obj;
  const result: AuditResult = { schemaVersion:1, kind:'diff', target:'MCP inventory snapshots', findings:[], coverage:coverage(['MG005']), changes:[] };
  result.coverage.inspected.push('snapshot integrity', 'named tool descriptors', 'inventory context');
  const hasKnownAcquisitionContext = (value: Obj): boolean => {
    const context = value.acquisitionContext;
    if (!isObject(context)) return false;
    return ['transport','authorization','source'].every(key => typeof context[key] === 'string' && !!(context[key] as string).trim() && (context[key] as string).trim().toLowerCase() !== 'unknown');
  };
  if (!hasKnownAcquisitionContext(av) || !hasKnownAcquisitionContext(bv)) {
    result.coverage.complete = false;
    result.coverage.diagnostics.push({code:'MG005_ACQUISITION_CONTEXT_UNKNOWN',message:'Acquisition transport, authorization, and source context must be explicitly recorded on both snapshots; provenance is unknown.'});
  }
  const am = toolMap(av), bm = toolMap(bv);
  const beforeOrder = (av.tools as Obj[]).map(t => t.name as string);
  const afterOrder = (bv.tools as Obj[]).map(t => t.name as string);
  if (canonical(beforeOrder) !== canonical(afterOrder)) result.changes!.push({kind:'tool-order-changed',pointer:'/tools',before:beforeOrder,after:afterOrder});
  for (const [name, tool] of bm) if (!am.has(name)) result.changes!.push({kind:'tool-added',tool:name, pointer:'/tools', after:redact(tool)});
  for (const [name, tool] of am) if (!bm.has(name)) result.changes!.push({kind:'tool-removed',tool:name, pointer:'/tools', before:redact(tool)});
  const fields = ['description','inputSchema','outputSchema','annotations'] as const;
  for (const name of [...am.keys()].filter(n => bm.has(n)).sort()) {
    const oldTool = am.get(name)!, newTool = bm.get(name)!;
    for (const field of fields) {
      const oldHas = Object.hasOwn(oldTool, field), newHas = Object.hasOwn(newTool, field);
      if (oldHas === newHas && canonical(oldTool[field]) === canonical(newTool[field])) continue;
      const oldIndex = (av.tools as Obj[]).findIndex(t => t.name === name);
      const base = `/tools/${oldIndex}/${field}`;
      result.changes!.push({kind:`tool-${field}-changed`,tool:name,pointer:base,...(oldHas ? {before:redact(oldTool[field])} : {}),...(newHas ? {after:redact(newTool[field])} : {})});
      if (field === 'inputSchema' && isObject(oldTool.inputSchema) && isObject(newTool.inputSchema) && Array.isArray(oldTool.inputSchema.required)) {
        const removed = (oldTool.inputSchema.required as unknown[]).filter(x => typeof x === 'string' && (!Array.isArray(newTool.inputSchema && (newTool.inputSchema as Obj).required) || !((newTool.inputSchema as Obj).required as unknown[]).includes(x)));
        for (const prop of removed) result.changes!.push({kind:'required-input-removed',tool:name,pointer:`${base}/required`,before:prop});
      }
    }
    const known = new Set(['name','description','inputSchema','outputSchema','annotations']);
    const oldExtra = Object.fromEntries(Object.entries(oldTool).filter(([key]) => !known.has(key)));
    const newExtra = Object.fromEntries(Object.entries(newTool).filter(([key]) => !known.has(key)));
    if (canonical(oldExtra) !== canonical(newExtra)) {
      result.changes!.push({kind:'tool-extra-metadata-changed',tool:name,pointer:`/tools/${(av.tools as Obj[]).findIndex(t => t.name === name)}`,before:redact(oldExtra),after:redact(newExtra)});
      result.coverage.complete = false;
      result.coverage.diagnostics.push({code:'MG005_TOOL_METADATA_CHANGED',message:`Unclassified metadata for tool ${name} differs and requires interpretation.`});
    }
  }
  if (canonical(contextProjection(av)) !== canonical(contextProjection(bv))) {
    result.changes!.push({kind:'inventory-context-changed',pointer:'',before:redact(contextProjection(av)),after:redact(contextProjection(bv))});
    result.coverage.complete = false;
    result.coverage.diagnostics.push({code:'MG005_CONTEXT_CHANGED',message:'Inventory metadata or acquisition context differs; interpret descriptor drift with this context change.'});
  }
  return result;
}

// Kept local to avoid exposing mutable input objects in the diff result.
function redact(value: unknown, path: string[] = []): unknown {
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map((v, i) => redact(v, [...path, String(i)]));
  if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([k,v]) => {
    const acquisitionAuthorization = k === 'authorization' && path.at(-1) === 'acquisitionContext';
    return [k, isSensitiveKey(k) && !acquisitionAuthorization ? '[REDACTED]' : redact(v, [...path, k])];
  }));
  return value;
}
