import ts from 'typescript';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeSource } from '../../dist/analyzer.js';

const CONTROLS = [
  {
    id: 'MG001-exec',
    ruleId: 'MG001',
    code: `import { McpServer } from '@modelcontextprotocol/server';
import { exec } from 'node:child_process';
const server = new McpServer({ name: 'evasion', version: '1.0.0' });
server.registerTool('run', { inputSchema: {} }, async (args) => {
  exec(args.cmd);
  return { content: [] };
});`
  },
  {
    id: 'MG002-readFile',
    ruleId: 'MG002',
    code: `import { McpServer } from '@modelcontextprotocol/server';
import { readFile } from 'node:fs/promises';
const server = new McpServer({ name: 'evasion', version: '1.0.0' });
server.registerTool('read', { inputSchema: {} }, async (args) => {
  return await readFile(args.path, 'utf8');
});`
  },
  {
    id: 'MG003-fetch',
    ruleId: 'MG003',
    code: `import { McpServer } from '@modelcontextprotocol/server';
const server = new McpServer({ name: 'evasion', version: '1.0.0' });
server.registerTool('fetch_url', { inputSchema: {} }, async (args) => {
  return await fetch(args.url);
});`
  },
  {
    id: 'MG004-env',
    ruleId: 'MG004',
    code: `import { McpServer } from '@modelcontextprotocol/server';
const server = new McpServer({ name: 'evasion', version: '1.0.0' });
server.registerTool('secret', { inputSchema: {} }, async () => {
  return process.env.API_KEY;
});`
  }
];

function printAst(sf) {
  return ts.createPrinter({ newLine: ts.NewLineKind.LineFeed }).printFile(sf);
}

function transformCode(code, transformerFactory) {
  const sf = ts.createSourceFile('control.ts', code, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const result = ts.transform(sf, [transformerFactory]);
  const printed = printAst(result.transformed[0]);
  result.dispose();
  return printed;
}

const TRANSFORMS = {
  aliased_import(control) {
    if (control.ruleId === 'MG003' || control.ruleId === 'MG004') {
      // Alias McpServer import to exercise import alias tracking
      return transformCode(control.code, (ctx) => (sf) => {
        const f = ctx.factory;
        const visit = (n) => {
          if (ts.isImportSpecifier(n) && n.name.text === 'McpServer') {
            return f.createImportSpecifier(false, f.createIdentifier('McpServer'), f.createIdentifier('AliasedServer'));
          }
          if (ts.isIdentifier(n) && n.text === 'McpServer' && !ts.isImportSpecifier(n.parent)) {
            return f.createIdentifier('AliasedServer');
          }
          return ts.visitEachChild(n, visit, ctx);
        };
        return ts.visitNode(sf, visit);
      });
    }
    const targetName = control.ruleId === 'MG001' ? 'exec' : 'readFile';
    const aliasName = control.ruleId === 'MG001' ? 'runShellAlias' : 'readFileAlias';
    return transformCode(control.code, (ctx) => (sf) => {
      const f = ctx.factory;
      const visit = (n) => {
        if (ts.isImportSpecifier(n) && n.name.text === targetName) {
          return f.createImportSpecifier(false, f.createIdentifier(targetName), f.createIdentifier(aliasName));
        }
        if (ts.isIdentifier(n) && n.text === targetName && !ts.isImportSpecifier(n.parent)) {
          return f.createIdentifier(aliasName);
        }
        return ts.visitEachChild(n, visit, ctx);
      };
      return ts.visitNode(sf, visit);
    });
  },

  destructured_args(control) {
    if (control.ruleId === 'MG004') return control.code;
    const field = control.ruleId === 'MG001' ? 'cmd' : control.ruleId === 'MG002' ? 'path' : 'url';
    return transformCode(control.code, (ctx) => (sf) => {
      const f = ctx.factory;
      const visit = (n) => {
        if (ts.isArrowFunction(n) && n.parameters.length === 1 && ts.isIdentifier(n.parameters[0].name) && n.parameters[0].name.text === 'args') {
          const binding = f.createObjectBindingPattern([f.createBindingElement(undefined, undefined, f.createIdentifier(field))]);
          const newParam = f.createParameterDeclaration(undefined, undefined, binding);
          const bodyVisit = (inner) => {
            if (ts.isPropertyAccessExpression(inner) && ts.isIdentifier(inner.expression) && inner.expression.text === 'args' && inner.name.text === field) {
              return f.createIdentifier(field);
            }
            return ts.visitEachChild(inner, bodyVisit, ctx);
          };
          return f.updateArrowFunction(n, n.modifiers, n.typeParameters, [newParam], n.type, n.equalsGreaterThanToken, ts.visitNode(n.body, bodyVisit));
        }
        return ts.visitEachChild(n, visit, ctx);
      };
      return ts.visitNode(sf, visit);
    });
  },

  one_level_wrapper(control) {
    return transformCode(control.code, (ctx) => (sf) => {
      const f = ctx.factory;
      const visit = (n) => {
        if (ts.isArrowFunction(n) && ts.isBlock(n.body)) {
          const wrapFn = f.createVariableStatement(
            undefined,
            f.createVariableDeclarationList([
              f.createVariableDeclaration(
                f.createIdentifier('wrapHelper'),
                undefined,
                undefined,
                f.createArrowFunction(undefined, undefined, [f.createParameterDeclaration(undefined, undefined, 'x')], undefined, f.createToken(ts.SyntaxKind.EqualsGreaterThanToken), f.createIdentifier('x'))
              )
            ], ts.NodeFlags.Const)
          );
          const replaceArg = (inner) => {
            if (ts.isPropertyAccessExpression(inner) && ts.isIdentifier(inner.expression) && inner.expression.text === 'args') {
              return f.createCallExpression(f.createIdentifier('wrapHelper'), undefined, [inner]);
            }
            return ts.visitEachChild(inner, replaceArg, ctx);
          };
          const newStmts = [wrapFn, ...n.body.statements.map(s => ts.visitNode(s, replaceArg))];
          return f.updateArrowFunction(n, n.modifiers, n.typeParameters, n.parameters, n.type, n.equalsGreaterThanToken, f.updateBlock(n.body, newStmts));
        }
        return ts.visitEachChild(n, visit, ctx);
      };
      return ts.visitNode(sf, visit);
    });
  },

  computed_property_access(control) {
    if (control.ruleId === 'MG004') {
      return transformCode(control.code, (ctx) => (sf) => {
        const f = ctx.factory;
        const visit = (n) => {
          if (ts.isPropertyAccessExpression(n) && n.name.text === 'API_KEY') {
            return f.createElementAccessExpression(
              f.createElementAccessExpression(f.createIdentifier('process'), f.createStringLiteral('env')),
              f.createStringLiteral('API_KEY')
            );
          }
          return ts.visitEachChild(n, visit, ctx);
        };
        return ts.visitNode(sf, visit);
      });
    }
    const field = control.ruleId === 'MG001' ? 'cmd' : control.ruleId === 'MG002' ? 'path' : 'url';
    return transformCode(control.code, (ctx) => (sf) => {
      const f = ctx.factory;
      const visit = (n) => {
        if (ts.isPropertyAccessExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === 'args' && n.name.text === field) {
          return f.createElementAccessExpression(f.createIdentifier('args'), f.createStringLiteral(field));
        }
        return ts.visitEachChild(n, visit, ctx);
      };
      return ts.visitNode(sf, visit);
    });
  },

  template_literal_command(control) {
    if (control.ruleId !== 'MG001' && control.ruleId !== 'MG003') return control.code;
    const field = control.ruleId === 'MG001' ? 'cmd' : 'url';
    const prefixText = control.ruleId === 'MG001' ? 'echo ' : 'https://example.invalid/';
    return transformCode(control.code, (ctx) => (sf) => {
      const f = ctx.factory;
      const visit = (n) => {
        if (ts.isPropertyAccessExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === 'args' && n.name.text === field) {
          return f.createTemplateExpression(f.createTemplateHead(prefixText), [f.createTemplateSpan(n, f.createTemplateTail(''))]);
        }
        return ts.visitEachChild(n, visit, ctx);
      };
      return ts.visitNode(sf, visit);
    });
  }
};

export function runEvasionSuite() {
  const cases = [];
  const summary = { detected: 0, incomplete: 0, silent_miss: 0 };
  for (const control of CONTROLS) {
    for (const [transformName, transformFn] of Object.entries(TRANSFORMS)) {
      const mutated = transformFn(control);
      const result = analyzeSource(`evasion-${control.id}-${transformName}.ts`, mutated);
      const hit = result.findings.some(f => f.ruleId === control.ruleId);
      const outcome = hit ? 'detected' : (result.coverage.complete ? 'silent_miss' : 'incomplete');
      summary[outcome]++;
      cases.push({
        control: control.id,
        ruleId: control.ruleId,
        transform: transformName,
        outcome,
        complete: result.coverage.complete,
        diagnostics: result.coverage.diagnostics.map(d => d.code)
      });
    }
  }
  return { total: cases.length, summary, cases };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(runEvasionSuite(), null, 2));
}
