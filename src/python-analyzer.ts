import { createRequire } from 'node:module';
import path from 'node:path';
import { Parser, Language, type Node as SyntaxNode } from 'web-tree-sitter';
import { SOURCE_RULES } from './analyzer.js';
import { coverage, finding } from './shared.js';
import type { AuditResult, Finding, Location } from './types.js';

type Value = { input: boolean; env: false | 'whole' | 'secret'; uncertain: boolean };
const empty = (): Value => ({ input: false, env: false, uncertain: false });
const wholeEnv = (): Value => ({ input: false, env: 'whole', uncertain: false });
const combine = (vals: Value[]): Value => ({
  input: vals.some(v => v.input),
  env: vals.some(v => v.env === 'whole') ? 'whole' : vals.some(v => v.env === 'secret') ? 'secret' : false,
  uncertain: vals.some(v => v.uncertain)
});

const secretEnvironmentName = (name: string) =>
  /(?:SECRET|TOKEN|PASSWORD|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL|DATABASE_?URL|DB_?URL|REDIS_?URL|DSN)/i.test(name);

interface PyImport {
  module: string;
  name: string;
}

const require = createRequire(import.meta.url);
let parserReady: Promise<{ parser: Parser; language: Language }> | undefined;

async function getPythonParser(): Promise<Parser> {
  if (!parserReady) {
    parserReady = (async () => {
      const wasmPath = require.resolve('tree-sitter-python/tree-sitter-python.wasm');
      const webTsWasm = require.resolve('web-tree-sitter/web-tree-sitter.wasm');
      await Parser.init({
        locateFile: (scriptName: string) => (scriptName.endsWith('.wasm') ? webTsWasm : path.join(path.dirname(webTsWasm), scriptName))
      });
      const language = await Language.load(wasmPath);
      const parser = new Parser();
      parser.setLanguage(language);
      return { parser, language };
    })();
  }
  const { parser } = await parserReady;
  return parser;
}

function unquotePyString(node: SyntaxNode): string | undefined {
  if (node.type !== 'string') return undefined;
  const content = node.namedChildren.find(c => c.type === 'string_content');
  if (content && !node.namedChildren.some(c => c.type === 'interpolation')) {
    return content.text;
  }
  const raw = node.text;
  const m = raw.match(/^[rRbBuU]{0,2}(?:"""([\s\S]*)"""|'''([\s\S]*)'''|"([^"]*)"|'([^']*)')$/);
  if (!m) return undefined;
  return m[1] ?? m[2] ?? m[3] ?? m[4] ?? '';
}

function isMcpServerImport(imp: PyImport | undefined): boolean {
  if (!imp) return false;
  if ((imp.module === 'mcp.server.fastmcp' || imp.module === 'fastmcp') && imp.name === 'FastMCP') return true;
  if ((imp.module === 'mcp.server' || imp.module === 'mcp.server.lowlevel') && imp.name === 'Server') return true;
  return false;
}

export async function analyzePythonSource(file: string, text: string): Promise<AuditResult> {
  const cov = coverage(SOURCE_RULES);
  cov.inspected = [file];
  const out: AuditResult = { schemaVersion: 1, kind: 'source', target: file, findings: [], coverage: cov };

  const parser = await getPythonParser();
  const tree = parser.parse(text);
  if (!tree || tree.rootNode.hasError) {
    cov.complete = false;
    cov.failed = [file];
    cov.diagnostics.push({ code: 'PARSE_ERROR', file, message: 'Python syntax error detected by tree-sitter-python.' });
    return out;
  }

  const root = tree.rootNode;
  const diagnostics = new Set<string>();
  const loc = (n: SyntaxNode): Location => ({
    file,
    line: n.startPosition.row + 1,
    column: n.startPosition.column + 1
  });
  const note = (code: string, n: SyntaxNode, message: string) => {
    const key = `${code}:${n.startIndex}`;
    if (diagnostics.has(key)) return;
    diagnostics.add(key);
    cov.complete = false;
    cov.diagnostics.push({ code, file, message: `${message} (line ${loc(n).line})` });
  };

  const imports = new Map<string, PyImport>();
  const servers = new Set<string>();
  const funcDefs = new Map<string, SyntaxNode>();
  const moduleConsts = new Map<string, Value>();

  const registerImportStmt = (stmt: SyntaxNode) => {
    if (stmt.type === 'import_statement') {
      for (const child of stmt.namedChildren) {
        if (child.type === 'dotted_name') {
          const top = child.text.split('.')[0]!;
          imports.set(top, { module: child.text, name: '*' });
        } else if (child.type === 'aliased_import') {
          const target = child.childForFieldName('name')?.text;
          const alias = child.childForFieldName('alias')?.text;
          if (target && alias) imports.set(alias, { module: target, name: '*' });
        }
      }
    } else if (stmt.type === 'import_from_statement') {
      const modNode = stmt.childForFieldName('module_name');
      const mod = modNode?.text ?? '';
      for (const child of stmt.namedChildren) {
        if (child === modNode) continue;
        if (child.type === 'dotted_name') {
          imports.set(child.text, { module: mod, name: child.text });
        } else if (child.type === 'aliased_import') {
          const target = child.childForFieldName('name')?.text;
          const alias = child.childForFieldName('alias')?.text;
          if (target && alias) imports.set(alias, { module: mod, name: target });
        }
      }
    }
  };

  const resolveApi = (node: SyntaxNode | null | undefined): PyImport | undefined => {
    if (!node) return undefined;
    if (node.type === 'identifier') return imports.get(node.text);
    if (node.type === 'attribute') {
      const obj = node.childForFieldName('object');
      const attr = node.childForFieldName('attribute')?.text;
      if (!obj || !attr) return undefined;
      const base = resolveApi(obj);
      if (base?.name === '*') return { module: base.module, name: attr };
      if (base?.module === 'os' && base.name === 'path') return { module: 'os.path', name: attr };
      if (base?.module === 'urllib' && base.name === 'request') return { module: 'urllib.request', name: attr };
    }
    return undefined;
  };

  // Pass 1: top-level imports, function definitions, server bindings, and 1-level factory servers
  const factoryBodies = new Set<SyntaxNode>();
  const supportedServerCalls = new Set<number>();

  for (const stmt of root.namedChildren) {
    registerImportStmt(stmt);
    if (stmt.type === 'function_definition') {
      const fnName = stmt.childForFieldName('name')?.text;
      if (fnName) funcDefs.set(fnName, stmt);
      const body = stmt.childForFieldName('body');
      if (body) factoryBodies.add(body);
    } else if (stmt.type === 'expression_statement' && stmt.firstNamedChild?.type === 'assignment') {
      const assign = stmt.firstNamedChild;
      const left = assign.childForFieldName('left');
      const right = assign.childForFieldName('right');
      if (left?.type === 'identifier' && right?.type === 'call') {
        const api = resolveApi(right.childForFieldName('function'));
        if (isMcpServerImport(api)) {
          servers.add(left.text);
          supportedServerCalls.add(right.startIndex);
        }
      }
    }
  }

  // Also check 1-level factory bodies for local mcp = FastMCP(...)
  for (const body of factoryBodies) {
    for (const stmt of body.namedChildren) {
      if (stmt.type === 'expression_statement' && stmt.firstNamedChild?.type === 'assignment') {
        const assign = stmt.firstNamedChild;
        const left = assign.childForFieldName('left');
        const right = assign.childForFieldName('right');
        if (left?.type === 'identifier' && right?.type === 'call') {
          const api = resolveApi(right.childForFieldName('function'));
          if (isMcpServerImport(api)) {
            servers.add(left.text);
            supportedServerCalls.add(right.startIndex);
          }
        }
      }
    }
  }

  // Flag nested/unsupported FastMCP/Server constructions or calls creating servers via external factories
  const walkAll = (n: SyntaxNode) => {
    if (n.type === 'call') {
      const fn = n.childForFieldName('function');
      const api = resolveApi(fn);
      if (isMcpServerImport(api) && !supportedServerCalls.has(n.startIndex)) {
        note('UNRESOLVED_FACTORY', n, 'MCP server constructed outside top-level or 1-level local factory scope');
      }
    }
    for (const c of n.namedChildren) walkAll(c);
  };
  walkAll(root);

  const emit = (ruleId: string, node: SyntaxNode, tool: string, readonlyNode?: SyntaxNode) => {
    const descriptions: Record<string, { title: string; observed: string; why: string; remediation: string; severity: Finding['severity'] }> = {
      MG001: {
        title: 'Tool input reaches shell command construction',
        observed: 'Supported direct tool input reaches shell-interpreted process execution.',
        why: 'A shell may interpret metacharacters in client-controlled command text.',
        remediation: 'Use subprocess with an explicit argument list and shell=False.',
        severity: 'high'
      },
      MG002: {
        title: 'Tool input reaches a filesystem path',
        observed: 'No supported containment check was established for this direct tool-input filesystem path.',
        why: 'Under server process permissions, arbitrary paths may expose or mutate files outside the intended directory.',
        remediation: 'Use fixed paths or resolve and verify containment within an allowed root.',
        severity: 'medium'
      },
      MG003: {
        title: 'Tool input controls an outbound destination',
        observed: 'Supported direct tool input reaches an outbound request URL without an established destination policy.',
        why: 'Unrestricted outbound URLs can allow SSRF depending on network policy and redirects.',
        remediation: 'Restrict outbound destinations to fixed endpoints or an explicit allowlist.',
        severity: 'medium'
      },
      MG004: {
        title: 'Environment values reach output',
        observed: 'An entire environment mapping or explicit secret-bearing environment value reaches an output sink.',
        why: 'Environment variables may hold credentials that can leak to MCP clients or logs.',
        remediation: 'Return explicit non-sensitive configuration fields and avoid logging secret env values.',
        severity: 'high'
      },
      MG006: {
        title: 'Read-only declaration contradicts a filesystem mutation',
        observed: 'A supported handler with readOnlyHint=True invokes a filesystem mutation.',
        why: 'Annotations are declarations, not enforced runtime sandboxes; the operation contradicts read-only metadata.',
        remediation: 'Fix the tool annotation or remove the filesystem mutation.',
        severity: 'medium'
      }
    };
    const d = descriptions[ruleId]!;
    out.findings.push(finding({
      engine: 'vambrace-py',
      ruleId,
      title: d.title,
      category: ruleId === 'MG006' ? 'declaration-contradiction' : 'implementation-pattern',
      severity: d.severity,
      confidence: 'high',
      evidenceType: 'static-pattern',
      locations: readonlyNode ? [loc(readonlyNode), loc(node)] : [loc(node)],
      evidence: (readonlyNode ? `${readonlyNode.text} | ` : '') + node.text.slice(0, 320),
      observed: `${d.observed} Tool: ${tool}`,
      why: d.why,
      assumptions: ['This supported Python MCP registration maps directly to this handler.', 'The server executes under its deployed OS permissions.'],
      remediation: d.remediation,
      limitations: ['Static AST pattern evidence is not confirmed exploitation.', 'Interprocedural helper calls and dynamic sinks remain outside supported coverage.']
    }));
  };

  interface RegisteredTool {
    name: string;
    fnNode: SyntaxNode;
    readonlyNode?: SyntaxNode;
  }

  const registered: RegisteredTool[] = [];

  const checkReadOnlyInArgs = (argsNode: SyntaxNode | null | undefined): SyntaxNode | undefined => {
    if (!argsNode) return undefined;
    let found: SyntaxNode | undefined;
    const visitArg = (n: SyntaxNode) => {
      if (n.type === 'keyword_argument') {
        const k = n.childForFieldName('name')?.text;
        const v = n.childForFieldName('value');
        if ((k === 'readOnlyHint' || k === 'read_only') && v?.type === 'true') found = n;
        else if (k === 'annotations' && v) {
          if (v.type === 'dictionary') {
            for (const pair of v.namedChildren) {
              if (pair.type === 'pair') {
                const pk = unquotePyString(pair.childForFieldName('key')!);
                const pv = pair.childForFieldName('value');
                if (pk === 'readOnlyHint' && pv?.type === 'true') found = pair;
                else if (pk === 'readOnlyHint' && pv && pv.type !== 'false') note('UNRESOLVED_ANNOTATIONS', pair, 'Dynamic readOnlyHint is not assessed');
              }
            }
          } else if (v.type === 'call') {
            visitArg(v.childForFieldName('arguments') ?? v);
          } else {
            note('UNRESOLVED_ANNOTATIONS', v, 'Non-literal annotations are not assessed');
          }
        }
      } else if (n.type === 'dictionary_splat') {
        note('UNRESOLVED_ANNOTATIONS', n, 'Spread keyword annotations are not assessed');
      } else {
        for (const c of n.namedChildren) visitArg(c);
      }
    };
    visitArg(argsNode);
    return found;
  };

  const checkDecoratorNode = (dec: SyntaxNode): { serverOk: boolean; readonlyNode?: SyntaxNode; isToolDec: boolean } => {
    const expr = dec.namedChildren[0];
    if (!expr) return { serverOk: false, isToolDec: false };
    let targetAttr: SyntaxNode | undefined;
    let argsNode: SyntaxNode | null | undefined;
    if (expr.type === 'call') {
      targetAttr = expr.childForFieldName('function') ?? undefined;
      argsNode = expr.childForFieldName('arguments');
    } else if (expr.type === 'attribute') {
      targetAttr = expr;
    }
    if (!targetAttr || targetAttr.type !== 'attribute') return { serverOk: false, isToolDec: false };
    const attrName = targetAttr.childForFieldName('attribute')?.text;
    const receiver = targetAttr.childForFieldName('object');
    if (attrName !== 'tool') return { serverOk: false, isToolDec: false };
    const serverOk = receiver?.type === 'identifier' && servers.has(receiver.text);
    const readonlyNode = checkReadOnlyInArgs(argsNode);
    return { serverOk, readonlyNode, isToolDec: true };
  };

  // Collect decorated tool definitions & add_tool calls
  const collectRegistrations = (scopeNode: SyntaxNode, depth: number) => {
    for (const stmt of scopeNode.namedChildren) {
      if (stmt.type === 'decorated_definition') {
        const def = stmt.childForFieldName('definition');
        const decorators = stmt.namedChildren.filter(c => c.type === 'decorator');
        let matched = false;
        let readonlyNode: SyntaxNode | undefined;
        for (const dec of decorators) {
          const info = checkDecoratorNode(dec);
          if (info.isToolDec) {
            if (!info.serverOk || depth > 1) {
              cov.unresolvedHandlers++;
              note('UNRESOLVED_FACTORY', dec, 'Tool decorator receiver is outside supported top-level or 1-level local MCP server scope');
            } else {
              matched = true;
              readonlyNode = info.readonlyNode;
            }
          }
        }
        if (matched && def?.type === 'function_definition') {
          const fnName = def.childForFieldName('name')?.text ?? 'unnamed';
          registered.push({ name: fnName, fnNode: def, readonlyNode });
        }
      } else if (stmt.type === 'function_definition') {
        const body = stmt.childForFieldName('body');
        if (body && depth === 0) collectRegistrations(body, 1);
      } else if (stmt.type === 'expression_statement' && stmt.firstNamedChild?.type === 'call') {
        const call = stmt.firstNamedChild;
        const fn = call.childForFieldName('function');
        if (fn?.type === 'attribute' && fn.childForFieldName('attribute')?.text === 'add_tool') {
          const receiver = fn.childForFieldName('object');
          const args = call.childForFieldName('arguments');
          const firstArg = args?.namedChildren.find(c => c.type !== 'keyword_argument');
          if (receiver?.type !== 'identifier' || !servers.has(receiver.text) || depth > 1) {
            cov.unresolvedHandlers++;
            note('UNRESOLVED_FACTORY', call, 'add_tool receiver is outside supported local server scope');
          } else if (firstArg?.type === 'identifier' && funcDefs.has(firstArg.text)) {
            const targetFn = funcDefs.get(firstArg.text)!;
            const readonlyNode = checkReadOnlyInArgs(args);
            registered.push({ name: firstArg.text, fnNode: targetFn, readonlyNode });
          } else {
            cov.unresolvedHandlers++;
            note('UNRESOLVED_HANDLER', call, 'add_tool handler could not be mapped to a local function definition');
          }
        }
      }
    }
  };
  collectRegistrations(root, 0);

  // Also check module-level constants
  for (const stmt of root.namedChildren) {
    if (stmt.type === 'expression_statement' && stmt.firstNamedChild?.type === 'assignment') {
      const left = stmt.firstNamedChild.childForFieldName('left');
      const right = stmt.firstNamedChild.childForFieldName('right');
      if (left?.type === 'identifier' && right) {
        if (right.type === 'string' && !right.namedChildren.some(c => c.type === 'interpolation')) {
          moduleConsts.set(left.text, empty());
        }
      }
    }
  }

  for (const reg of registered) {
    cov.recognizedTools++;
    const localValues = new Map<string, Value>(moduleConsts);
    const paramsNode = reg.fnNode.childForFieldName('parameters');
    if (paramsNode) {
      for (const p of paramsNode.namedChildren) {
        let pname: string | undefined;
        let ptype = '';
        if (p.type === 'identifier') pname = p.text;
        else if (p.type === 'typed_parameter') {
          pname = p.namedChildren.find(c => c.type === 'identifier')?.text;
          ptype = p.childForFieldName('type')?.text ?? '';
        } else if (p.type === 'default_parameter' || p.type === 'typed_default_parameter') {
          pname = p.childForFieldName('name')?.text;
          ptype = p.childForFieldName('type')?.text ?? '';
        }
        if (pname && pname !== 'self' && pname !== 'cls' && !/\bContext\b/.test(ptype)) {
          localValues.set(pname, { input: true, env: false, uncertain: false });
        }
      }
    }

    const body = reg.fnNode.childForFieldName('body');
    if (!body) {
      cov.unresolvedHandlers++;
      note('UNRESOLVED_HANDLER', reg.fnNode, 'Tool handler has no body');
      continue;
    }

    const pathVars = new Set<string>();

    const isOsEnviron = (node: SyntaxNode): boolean => {
      if (node.type === 'identifier') return resolveApi(node)?.module === 'os' && resolveApi(node)?.name === 'environ';
      if (node.type === 'attribute') {
        const api = resolveApi(node);
        return api?.module === 'os' && api.name === 'environ';
      }
      return false;
    };

    const evalPy = (node: SyntaxNode | null | undefined, depth = 0): Value => {
      if (!node || depth > 40) return { ...empty(), uncertain: depth > 40 };
      if (isOsEnviron(node)) return wholeEnv();
      if (node.type === 'identifier') return localValues.get(node.text) ?? empty();
      if (node.type === 'integer' || node.type === 'float' || node.type === 'true' || node.type === 'false' || node.type === 'none') return empty();
      if (node.type === 'string') {
        const interps = node.namedChildren.filter(c => c.type === 'interpolation');
        if (interps.length === 0) return empty();
        return combine(interps.map(i => evalPy(i.namedChildren[0], depth + 1)));
      }
      if (node.type === 'parenthesized_expression' || node.type === 'await') {
        return evalPy(node.namedChildren[0], depth + 1);
      }
      if (node.type === 'binary_operator' || node.type === 'concatenated_string') {
        return combine(node.namedChildren.map(c => evalPy(c, depth + 1)));
      }
      if (node.type === 'list' || node.type === 'tuple' || node.type === 'set') {
        return combine(node.namedChildren.map(c => evalPy(c, depth + 1)));
      }
      if (node.type === 'dictionary') {
        const vals: Value[] = [];
        for (const p of node.namedChildren) {
          if (p.type === 'pair') vals.push(evalPy(p.childForFieldName('value'), depth + 1));
          else if (p.type === 'dictionary_splat') vals.push({ ...evalPy(p.namedChildren[0], depth + 1), uncertain: true });
        }
        return combine(vals);
      }
      if (node.type === 'subscript') {
        const valNode = node.childForFieldName('value');
        const subNode = node.childForFieldName('subscript');
        if (valNode && isOsEnviron(valNode)) {
          const key = subNode ? unquotePyString(subNode) : undefined;
          if (!key) return { ...empty(), uncertain: true };
          return { input: false, env: secretEnvironmentName(key) ? 'secret' : false, uncertain: false };
        }
        const combined = combine([evalPy(valNode, depth + 1), evalPy(subNode, depth + 1)]);
        return combined.input || combined.env ? { ...combined, uncertain: true } : combined;
      }
      if (node.type === 'call') {
        const fnNode = node.childForFieldName('function');
        const argsNode = node.childForFieldName('arguments');
        const posArgs = argsNode ? argsNode.namedChildren.filter(c => c.type !== 'keyword_argument' && c.type !== 'list_splat' && c.type !== 'dictionary_splat') : [];
        const api = resolveApi(fnNode);

        // os.environ.keys() -> key names only (safe)
        if (fnNode?.type === 'attribute' && fnNode.childForFieldName('object') && isOsEnviron(fnNode.childForFieldName('object')!)) {
          const method = fnNode.childForFieldName('attribute')?.text;
          if (method === 'keys') return empty();
          if (method === 'get') {
            const key = posArgs[0] ? unquotePyString(posArgs[0]) : undefined;
            if (!key) return { ...empty(), uncertain: true };
            return { input: false, env: secretEnvironmentName(key) ? 'secret' : false, uncertain: false };
          }
        }
        // os.getenv("KEY")
        if (api?.module === 'os' && api.name === 'getenv') {
          const key = posArgs[0] ? unquotePyString(posArgs[0]) : undefined;
          if (!key) return { ...empty(), uncertain: true };
          return { input: false, env: secretEnvironmentName(key) ? 'secret' : false, uncertain: false };
        }
        // pathlib.Path(x) or os.path.join(...) or str(...)
        if ((api?.module === 'pathlib' && api.name === 'Path') || (api?.module === 'os.path' && ['join', 'abspath', 'normpath'].includes(api.name)) || fnNode?.text === 'str') {
          return combine(posArgs.map(a => evalPy(a, depth + 1)));
        }
        // json.dumps(...)
        if (api?.module === 'json' && api.name === 'dumps') {
          return combine(posArgs.map(a => evalPy(a, depth + 1)));
        }
        // "...".format(...)
        if (fnNode?.type === 'attribute' && ['format', 'strip', 'lower', 'upper'].includes(fnNode.childForFieldName('attribute')?.text ?? '')) {
          return combine([evalPy(fnNode.childForFieldName('object'), depth + 1), ...posArgs.map(a => evalPy(a, depth + 1))]);
        }

        const merged = combine(posArgs.map(a => evalPy(a, depth + 1)));
        if (merged.input || merged.env) return { ...merged, uncertain: true };
        return merged;
      }
      return empty();
    };

    const visitBody = (node: SyntaxNode) => {
      if (node !== body && (node.type === 'function_definition' || node.type === 'lambda')) {
        note('NESTED_FUNCTION', node, 'Nested Python function or lambda is not analyzed');
        return;
      }
      if (node.type === 'if_statement' || node.type === 'for_statement' || node.type === 'while_statement' || node.type === 'try_statement') {
        note('UNSUPPORTED_CONTROL_FLOW', node, 'Branch, loop, or exception control flow requires manual review');
      }
      if (node.type === 'augmented_assignment') {
        note('UNSUPPORTED_COMPOUND_ASSIGNMENT', node, 'Augmented assignment dataflow is not assessed');
      }
      if (node.type === 'assignment') {
        const left = node.childForFieldName('left');
        const right = node.childForFieldName('right');
        if (left?.type === 'identifier' && right) {
          if (localValues.has(left.text)) {
            note('MUTABLE_ASSIGNMENT', node, 'Variable reassignment dataflow is not fully assessed');
          }
          const val = evalPy(right);
          localValues.set(left.text, val);
          if (val.uncertain) note('UNRESOLVED_VALUE', node, 'Value passes through an unsupported transformation');
          if (right.type === 'call') {
            const api = resolveApi(right.childForFieldName('function'));
            if (api?.module === 'pathlib' && api.name === 'Path') pathVars.add(left.text);
          }
        }
      }
      if (node.type === 'return_statement') {
        const expr = node.namedChildren[0];
        if (evalPy(expr).env) emit('MG004', node, reg.name);
      }
      if (node.type === 'call') {
        const fnNode = node.childForFieldName('function');
        const argsNode = node.childForFieldName('arguments');
        const allArgs = argsNode?.namedChildren ?? [];
        const posArgs = allArgs.filter(c => c.type !== 'keyword_argument' && c.type !== 'list_splat' && c.type !== 'dictionary_splat');
        const kwArgs = new Map<string, SyntaxNode>();
        for (const a of allArgs) {
          if (a.type === 'keyword_argument') {
            const k = a.childForFieldName('name')?.text;
            const v = a.childForFieldName('value');
            if (k && v) kwArgs.set(k, v);
          } else if (a.type === 'dictionary_splat' || a.type === 'list_splat') {
            note('UNRESOLVED_CALL', node, 'Starred or double-starred call arguments are not assessed');
          }
        }
        const api = resolveApi(fnNode);
        let handled = false;

        // MG001: subprocess.* with shell=True, os.system, os.popen
        if (api?.module === 'subprocess' && ['run', 'Popen', 'call', 'check_call', 'check_output'].includes(api.name)) {
          handled = true;
          const shellVal = kwArgs.get('shell');
          const cmdArg = kwArgs.get('args') ?? posArgs[0];
          if (shellVal && shellVal.type !== 'true' && shellVal.type !== 'false') {
            note('UNKNOWN_SHELL_OPTION', node, 'Dynamic subprocess shell flag is not assessed');
          } else if (shellVal?.type === 'true' && evalPy(cmdArg).input) {
            emit('MG001', node, reg.name);
          }
        } else if (api?.module === 'os' && ['system', 'popen'].includes(api.name)) {
          handled = true;
          if (evalPy(posArgs[0]).input) emit('MG001', node, reg.name);
        }

        // MG002 & MG006: open(...), pathlib.Path(...).* and os.* file mutations
        if (fnNode?.type === 'identifier' && fnNode.text === 'open') {
          handled = true;
          const fileArg = kwArgs.get('file') ?? posArgs[0];
          const modeArg = kwArgs.get('mode') ?? posArgs[1];
          if (evalPy(fileArg).input) emit('MG002', node, reg.name);
          if (reg.readonlyNode) {
            if (!modeArg) {
              // default mode in Python open() is 'r'
            } else {
              const modeStr = unquotePyString(modeArg);
              if (modeStr === undefined) note('UNRESOLVED_OPEN_FLAGS', node, 'Dynamic open() mode is not assessed');
              else if (/[wax+]/.test(modeStr)) emit('MG006', node, reg.name, reg.readonlyNode);
            }
          }
        } else if (fnNode?.type === 'attribute') {
          const obj = fnNode.childForFieldName('object');
          const method = fnNode.childForFieldName('attribute')?.text ?? '';
          const isPathInstance = (obj?.type === 'identifier' && pathVars.has(obj.text))
            || (obj?.type === 'call' && resolveApi(obj.childForFieldName('function'))?.module === 'pathlib' && resolveApi(obj.childForFieldName('function'))?.name === 'Path');
          if (isPathInstance && ['read_text', 'read_bytes', 'write_text', 'write_bytes', 'open', 'unlink', 'mkdir', 'rmdir', 'rename'].includes(method)) {
            handled = true;
            if (evalPy(obj).input) emit('MG002', node, reg.name);
            if (reg.readonlyNode) {
              if (['write_text', 'write_bytes', 'unlink', 'mkdir', 'rmdir', 'rename'].includes(method)) {
                emit('MG006', node, reg.name, reg.readonlyNode);
              } else if (method === 'open') {
                const modeArg = kwArgs.get('mode') ?? posArgs[0];
                const modeStr = modeArg ? unquotePyString(modeArg) : 'r';
                if (modeStr === undefined) note('UNRESOLVED_OPEN_FLAGS', node, 'Dynamic Path.open() mode is not assessed');
                else if (/[wax+]/.test(modeStr)) emit('MG006', node, reg.name, reg.readonlyNode);
              }
            }
          }
        }
        if (api?.module === 'os' && ['remove', 'unlink', 'rmdir', 'mkdir', 'makedirs', 'rename'].includes(api.name)) {
          handled = true;
          if (posArgs.some(a => evalPy(a).input)) emit('MG002', node, reg.name);
          if (reg.readonlyNode) emit('MG006', node, reg.name, reg.readonlyNode);
        }

        // MG003: requests.*, httpx.*, urllib.request.urlopen
        if (api && ['requests', 'httpx'].includes(api.module) && ['get', 'post', 'put', 'delete', 'patch', 'head', 'request'].includes(api.name)) {
          handled = true;
          const urlArg = kwArgs.get('url') ?? (api.name === 'request' ? posArgs[1] : posArgs[0]);
          if (evalPy(urlArg).input) emit('MG003', node, reg.name);
        } else if (api?.module === 'urllib.request' && api.name === 'urlopen') {
          handled = true;
          if (evalPy(kwArgs.get('url') ?? posArgs[0]).input) emit('MG003', node, reg.name);
        }

        // MG004: print(...) / logging.*(...)
        const isPrint = fnNode?.type === 'identifier' && fnNode.text === 'print';
        const isLogging = api?.module === 'logging' && ['info', 'warning', 'error', 'debug', 'critical', 'exception'].includes(api.name);
        if (isPrint || isLogging) {
          handled = true;
          if (posArgs.some(a => evalPy(a).env) || [...kwArgs.values()].some(v => evalPy(v).env)) {
            emit('MG004', node, reg.name);
          }
        }

        // Known safe helpers & stream methods on open()
        if (api && ['pathlib', 'os.path', 'json'].includes(api.module)) handled = true;
        if (api?.module === 'os' && api.name === 'getenv') handled = true;
        if (fnNode?.type === 'identifier' && ['str', 'len', 'int', 'float', 'bool', 'dict', 'list'].includes(fnNode.text)) handled = true;
        if (fnNode?.type === 'attribute') {
          const obj = fnNode.childForFieldName('object');
          const m = fnNode.childForFieldName('attribute')?.text ?? '';
          if (['keys', 'get', 'format', 'strip', 'lower', 'upper'].includes(m)) handled = true;
          if (obj?.type === 'call' && obj.childForFieldName('function')?.text === 'open' && ['read', 'readline', 'readlines', 'write', 'writelines', 'close'].includes(m)) {
            handled = true;
          }
        }

        if (!handled) {
          const argVals = [...posArgs, ...kwArgs.values()].map(a => evalPy(a));
          if (reg.readonlyNode || argVals.some(v => v.input || v.env)) {
            note('UNRESOLVED_CALL', node, 'Input, environment value, or read-only effect reaches an unsupported Python call');
          }
        }
      }

      for (const child of node.namedChildren) visitBody(child);
    };

    visitBody(body);
  }

  out.findings.sort((a, b) => a.ruleId.localeCompare(b.ruleId) || (a.locations.at(-1)?.line ?? 0) - (b.locations.at(-1)?.line ?? 0));
  return out;
}
