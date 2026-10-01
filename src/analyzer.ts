import ts from 'typescript';
import { coverage, finding } from './shared.js';
import type { AuditResult, Finding, Location } from './types.js';

export const SOURCE_RULES = ['MG001','MG002','MG003','MG004','MG006'];
type Value = {input:boolean; env:false|'whole'|'secret'; uncertain:boolean};
const empty = (): Value => ({input:false,env:false,uncertain:false});
const combine = (values: Value[]): Value => ({input:values.some(v=>v.input),env:values.some(v=>v.env==='whole')?'whole':values.some(v=>v.env==='secret')?'secret':false,uncertain:values.some(v=>v.uncertain)});
type Import = {module:string; name:string};
const moduleName = (name:string) => name.replace(/^node:/,'');

export function analyzeSource(file:string, text:string): AuditResult {
  const cov=coverage(SOURCE_RULES); cov.inspected=[file];
  const out:AuditResult={schemaVersion:1,kind:'source',target:file,findings:[],coverage:cov};
  const sf=ts.createSourceFile(file,text,ts.ScriptTarget.Latest,true,file.endsWith('.ts')||file.endsWith('.mts')?ts.ScriptKind.TS:ts.ScriptKind.JS);
  const parse=(sf as ts.SourceFile & {parseDiagnostics:readonly ts.Diagnostic[]}).parseDiagnostics;
  if(parse.length){cov.complete=false;cov.failed=[file];cov.diagnostics.push({code:'PARSE_ERROR',file,message:ts.flattenDiagnosticMessageText(parse[0]!.messageText,' ')});return out;}
  const host:ts.CompilerHost={getSourceFile:n=>n===file?sf:undefined,getDefaultLibFileName:()=>'',writeFile:()=>{},getCurrentDirectory:()=>'',getDirectories:()=>[],fileExists:n=>n===file,readFile:n=>n===file?text:undefined,getCanonicalFileName:n=>n,useCaseSensitiveFileNames:()=>true,getNewLine:()=> '\n'};
  const program=ts.createProgram([file],{noLib:true,noResolve:true,allowJs:true},host);
  const checker=program.getTypeChecker();
  const symbol=(n:ts.Node)=>checker.getSymbolAtLocation(n);
  const imports=new Map<ts.Symbol,Import>();
  const values=new Map<ts.Symbol,Value>();
  const servers=new Set<ts.Symbol>();
  const constants=new Map<ts.Symbol,ts.Expression>();
  const diagnostics=new Set<string>();
  const loc=(n:ts.Node):Location=>{const p=sf.getLineAndCharacterOfPosition(n.getStart(sf));return {file,line:p.line+1,column:p.character+1};};
  const note=(code:string,n:ts.Node,message:string)=>{const key=code+':'+n.pos;if(diagnostics.has(key))return;diagnostics.add(key);cov.complete=false;cov.diagnostics.push({code,file,message:message+' (line '+loc(n).line+')'});};
  for(const st of sf.statements){
    if(ts.isImportDeclaration(st)&&ts.isStringLiteral(st.moduleSpecifier)){
      const mod=moduleName(st.moduleSpecifier.text), clause=st.importClause;
      if(clause?.name){const s=symbol(clause.name);if(s)imports.set(s,{module:mod,name:'*'});}
      if(clause?.namedBindings&&ts.isNamespaceImport(clause.namedBindings)){const s=symbol(clause.namedBindings.name);if(s)imports.set(s,{module:mod,name:'*'});}
      if(clause?.namedBindings&&ts.isNamedImports(clause.namedBindings))for(const el of clause.namedBindings.elements){const s=symbol(el.name);if(s)imports.set(s,{module:mod,name:el.propertyName?.text??el.name.text});}
    }
  }
  const api=(expr:ts.Expression):Import|undefined=>{
    if(ts.isIdentifier(expr)){const s=symbol(expr);return s?imports.get(s):undefined;}
    if(ts.isPropertyAccessExpression(expr)){
      const base=api(expr.expression);
      if(base?.name==='*')return {module:base.module,name:expr.name.text};
      if(base?.module==='fs'&&base.name==='promises')return {module:'fs/promises',name:expr.name.text};
    }
    return undefined;
  };
  const global=(node:ts.Expression,name:string)=>ts.isIdentifier(node)&&node.text===name&&!symbol(node);
  const environment=(expr:ts.Expression)=>(ts.isPropertyAccessExpression(expr)&&global(expr.expression,'process')&&expr.name.text==='env')||(ts.isElementAccessExpression(expr)&&global(expr.expression,'process')&&!!expr.argumentExpression&&ts.isStringLiteralLike(expr.argumentExpression)&&expr.argumentExpression.text==='env');
  const evalValue=(expr:ts.Expression|undefined,depth=0):Value=>{
    if(!expr||depth>40)return {...empty(),uncertain:depth>40};
    if(environment(expr))return {input:false,env:'whole',uncertain:false};
    if(ts.isIdentifier(expr)){const s=symbol(expr);return s?values.get(s)??empty():empty();}
    if(ts.isStringLiteralLike(expr)||ts.isNumericLiteral(expr)||expr.kind===ts.SyntaxKind.TrueKeyword||expr.kind===ts.SyntaxKind.FalseKeyword||expr.kind===ts.SyntaxKind.NullKeyword)return empty();
    if(ts.isParenthesizedExpression(expr)||ts.isAsExpression(expr)||ts.isNonNullExpression(expr)||ts.isTypeAssertionExpression(expr)||ts.isAwaitExpression(expr))return evalValue(expr.expression,depth+1);
    if(ts.isPropertyAccessExpression(expr)||ts.isElementAccessExpression(expr)){
      const base=expr.expression;
      if(environment(base)){
        const name=ts.isPropertyAccessExpression(expr)?expr.name.text:expr.argumentExpression&&ts.isStringLiteral(expr.argumentExpression)?expr.argumentExpression.text:undefined;
        if(!name)return {...empty(),uncertain:true};
        return {input:false,env:/(?:SECRET|TOKEN|PASSWORD|API_?KEY|PRIVATE_?KEY)/i.test(name)?'secret':false,uncertain:false};
      }
      if(ts.isElementAccessExpression(expr)) {
        const value=combine([evalValue(base,depth+1),evalValue(expr.argumentExpression,depth+1)]);
        if(value.input||value.env)return {...value,uncertain:true};
      }
      return evalValue(base,depth+1);
    }
    if(ts.isTemplateExpression(expr))return combine(expr.templateSpans.map(x=>evalValue(x.expression,depth+1)));
    if(ts.isBinaryExpression(expr))return combine([evalValue(expr.left,depth+1),evalValue(expr.right,depth+1)]);
    if(ts.isConditionalExpression(expr))return combine([evalValue(expr.whenTrue,depth+1),evalValue(expr.whenFalse,depth+1)]);
    if(ts.isObjectLiteralExpression(expr))return combine(expr.properties.map(p=>ts.isPropertyAssignment(p)?evalValue(p.initializer,depth+1):ts.isSpreadAssignment(p)?evalValue(p.expression,depth+1):ts.isShorthandPropertyAssignment(p)?evalValue(p.name,depth+1):empty()));
    if(ts.isArrayLiteralExpression(expr))return combine(expr.elements.map(x=>ts.isSpreadElement(x)?evalValue(x.expression,depth+1):evalValue(x as ts.Expression,depth+1)));
    if(ts.isCallExpression(expr)||ts.isNewExpression(expr)){
      const args=expr.arguments??[], merged=combine(args.map(x=>evalValue(x,depth+1)));
      const called=api(expr.expression);
      const raw=expr.expression.getText(sf);
      if(raw==='Object.keys'&&ts.isPropertyAccessExpression(expr.expression)&&global(expr.expression.expression,'Object'))return empty();
      if((raw==='JSON.stringify'&&ts.isPropertyAccessExpression(expr.expression)&&global(expr.expression.expression,'JSON'))||(raw==='Object.values'&&ts.isPropertyAccessExpression(expr.expression)&&global(expr.expression.expression,'Object')))return merged;
      if((called?.module==='path'||called?.module==='path/posix')&&['join','resolve','normalize'].includes(called.name))return merged;
      if(global(expr.expression,'String')||global(expr.expression,'URL'))return merged;
      if(ts.isPropertyAccessExpression(expr.expression)&&['trim','toString','toLowerCase','toUpperCase'].includes(expr.expression.name.text))return evalValue(expr.expression.expression,depth+1);
      if(merged.input||merged.env)return {...merged,uncertain:true};
      return merged;
    }
    return empty();
  };
  const bind=(name:ts.BindingName,val:Value)=>{
    if(ts.isIdentifier(name)){const s=symbol(name);if(s)values.set(s,val);}
    else for(const el of name.elements)if(ts.isBindingElement(el))bind(el.name,val);
  };
  // Only top-level constants are carried into tool callbacks; no target module resolution occurs.
  for(const st of sf.statements)if(ts.isVariableStatement(st))for(const decl of st.declarationList.declarations){
    if(!ts.isIdentifier(decl.name)||!decl.initializer)continue;
    const s=symbol(decl.name);if(!s)continue;
    if(st.declarationList.flags&ts.NodeFlags.Const){constants.set(s,decl.initializer);bind(decl.name,evalValue(decl.initializer));}
    if(ts.isNewExpression(decl.initializer)){const ctor=api(decl.initializer.expression);if(ctor?.name==='McpServer'&&ctor.module==='@modelcontextprotocol/sdk/server/mcp.js'&&(st.declarationList.flags&ts.NodeFlags.Const))servers.add(s);}
  }
  const prop=(obj:ts.ObjectLiteralExpression,name:string)=>obj.properties.find(p=>ts.isPropertyAssignment(p)&&((ts.isIdentifier(p.name)||ts.isStringLiteral(p.name))&&p.name.text===name)) as ts.PropertyAssignment|undefined;
  const emit=(ruleId:string,n:ts.Node,tool:string,readonlyNode?:ts.Node)=>{
    const descriptions:Record<string,{title:string;observed:string;why:string;remediation:string;severity:Finding['severity']}>={
      MG001:{title:'Tool input reaches shell command construction',observed:'Supported direct tool input reaches shell-interpreted process execution.',why:'A shell may interpret metacharacters in client-controlled command text.',remediation:'Use a fixed executable with structured arguments and a documented argument policy; avoid shell interpretation.',severity:'high'},
      MG002:{title:'Tool input reaches a filesystem path',observed:'No supported containment check was established for this direct tool-input filesystem path.',why:'Under the server process permissions, arbitrary paths may expose or mutate files outside the intended capability.',remediation:'Use fixed capabilities or enforce canonical root containment and symlink policy at the actual filesystem boundary.',severity:'medium'},
      MG003:{title:'Tool input controls an outbound destination',observed:'Supported direct tool input reaches an outbound request URL without an established destination policy.',why:'This is a general outbound-fetch capability; SSRF exploitability depends on redirects, DNS, network policy and deployment.',remediation:'Restrict destinations to fixed capabilities and separately enforce redirects, resolved addresses and network egress.',severity:'medium'},
      MG004:{title:'Environment values reach output',observed:'An entire environment object or explicit secret-bearing environment value reaches a supported output sink.',why:'Environment values may contain credentials; returning or logging them can expose them to clients or log readers.',remediation:'Return an explicit allowlist of non-sensitive values and avoid logging secret-bearing data.',severity:'high'},
      MG006:{title:'Read-only declaration contradicts a filesystem mutation',observed:'A supported handler with readOnlyHint:true directly invokes a filesystem mutation.',why:'Annotations are declarations, not enforced permissions; the observed operation contradicts this declaration.',remediation:'Correct the annotation and review the actual mutation permissions and host approval policy.',severity:'medium'}
    };
    const d=descriptions[ruleId]!;
    const uncertain=ts.isCallExpression(n)&&n.arguments.some(a=>evalValue(a).uncertain);
    out.findings.push(finding({ruleId,title:d.title,category:ruleId==='MG006'?'declaration-contradiction':'implementation-pattern',severity:d.severity,confidence:uncertain?'medium':'high',evidenceType:'static-pattern',locations:readonlyNode?[loc(readonlyNode),loc(n)]:[loc(n)],evidence:(readonlyNode?readonlyNode.getText(sf)+' | ':'')+n.getText(sf).slice(0,320),observed:d.observed+' Tool: '+tool,why:d.why,assumptions:['This supported registration maps to this direct handler.','The server executes under its deployed process permissions.'],remediation:d.remediation,limitations:['Static pattern evidence is not a confirmed exploit.','No imported helper, interprocedural, race-safe containment or deployment-policy analysis.','Structured process arguments can carry other risks outside MG001.']}));
  };
  const handler=(expr:ts.Expression|undefined):ts.FunctionLikeDeclaration|undefined=>{
    if(!expr)return;
    if(ts.isArrowFunction(expr)||ts.isFunctionExpression(expr))return expr;
    if(ts.isIdentifier(expr)){const s=symbol(expr);for(const d of s?.declarations??[]){if(ts.isFunctionDeclaration(d))return d;if(ts.isVariableDeclaration(d)&&d.initializer&&(ts.isArrowFunction(d.initializer)||ts.isFunctionExpression(d.initializer)))return d.initializer;}}
  };
  const regs:ts.CallExpression[]=[];
  const collect=(n:ts.Node)=>{if(ts.isCallExpression(n)&&ts.isElementAccessExpression(n.expression)&&ts.isIdentifier(n.expression.expression)&&servers.has(symbol(n.expression.expression)!))note('COMPUTED_REGISTRATION',n,'Computed server method registration is not assessed');if(ts.isCallExpression(n)&&ts.isPropertyAccessExpression(n.expression)&&['registerTool','tool'].includes(n.expression.name.text))regs.push(n);ts.forEachChild(n,collect);};collect(sf);
  for(const reg of regs){
    const method=reg.expression as ts.PropertyAccessExpression;
    const receiver=ts.isIdentifier(method.expression)?symbol(method.expression):undefined;
    if(method.name.text!=='registerTool'||!receiver||!servers.has(receiver)){cov.unresolvedHandlers++;note('UNSUPPORTED_REGISTRATION',reg,'Registration receiver or method is outside the supported direct McpServer.registerTool subset');continue;}
    cov.recognizedTools++;
    const name=reg.arguments[0],config=reg.arguments[1],fn=handler(reg.arguments[2]);
    if(!name||!ts.isStringLiteralLike(name)||!config||!ts.isObjectLiteralExpression(config)||!fn?.body){cov.unresolvedHandlers++;note('UNRESOLVED_HANDLER',reg,'Tool name/configuration/handler could not be mapped directly');continue;}
    if(config.properties.some(p=>ts.isSpreadAssignment(p)))note('UNRESOLVED_CONFIG_SPREAD',config,'Spread registration configuration is not fully assessed');
    const saved=new Map(values);
    if(fn.parameters[0])bind(fn.parameters[0].name,{input:true,env:false,uncertain:false});
    const annotation=prop(config,'annotations');let readonly:ts.Node|undefined;
    if(annotation&&!ts.isObjectLiteralExpression(annotation.initializer))note('UNRESOLVED_ANNOTATIONS',annotation,'Annotation mapping is not assessed');
    if(annotation&&ts.isObjectLiteralExpression(annotation.initializer)){const p=prop(annotation.initializer,'readOnlyHint');if(p?.initializer.kind===ts.SyntaxKind.TrueKeyword)readonly=p;else if(p&&!([ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword].includes(p.initializer.kind)))note('UNRESOLVED_ANNOTATIONS',p,'Dynamic readOnlyHint is not assessed');if(annotation.initializer.properties.some(p=>ts.isSpreadAssignment(p)))note('UNRESOLVED_ANNOTATIONS',annotation,'Spread annotations are not assessed');}
    const visit=(node:ts.Node)=>{
      if(node!==fn.body&&ts.isFunctionLike(node)){note('NESTED_FUNCTION',node,'Nested functions and callbacks are not analyzed');return;}
      if(ts.isElementAccessExpression(node)&&evalValue(node).uncertain)note('UNRESOLVED_COMPUTED_VALUE',node,'Computed input/environment lookup requires review');
      if(ts.isVariableDeclaration(node)&&node.initializer){const val=evalValue(node.initializer);bind(node.name,val);if(val.uncertain)note('UNRESOLVED_VALUE',node,'Value passes through an unsupported transformation');if(!(node.parent.flags&ts.NodeFlags.Const)&&val.input)note('MUTABLE_FLOW',node,'Mutable input flows require manual review');}
      if(ts.isIfStatement(node)||ts.isSwitchStatement(node)||ts.isIterationStatement(node,false)||ts.isTryStatement(node))note('UNSUPPORTED_CONTROL_FLOW',node,'Branch/loop/exception flow is not path-sensitive and requires review');
      if(ts.isBinaryExpression(node)&&node.operatorToken.kind>=ts.SyntaxKind.FirstAssignment&&node.operatorToken.kind<=ts.SyntaxKind.LastAssignment&&node.operatorToken.kind!==ts.SyntaxKind.EqualsToken)note('UNSUPPORTED_COMPOUND_ASSIGNMENT',node,'Compound assignment dataflow is not assessed');
      if((ts.isPrefixUnaryExpression(node)||ts.isPostfixUnaryExpression(node))&&[ts.SyntaxKind.PlusPlusToken,ts.SyntaxKind.MinusMinusToken].includes(node.operator))note('UNSUPPORTED_INPLACE_MUTATION',node,'In-place mutation dataflow is not assessed');
      if(ts.isBinaryExpression(node)&&node.operatorToken.kind===ts.SyntaxKind.EqualsToken){const val=evalValue(node.right);if(ts.isIdentifier(node.left)){bind(node.left,val);note('MUTABLE_ASSIGNMENT',node,'Reassignment dataflow is not fully assessed');}else if(val.input||val.env)note('UNSUPPORTED_ASSIGNMENT',node,'Object mutation dataflow is not assessed');}
      if(ts.isReturnStatement(node)&&evalValue(node.expression).env)emit('MG004',node,name.text);
      if(ts.isCallExpression(node)){
        const called=api(node.expression), vals=node.arguments.map(x=>evalValue(x)), first=vals[0]??empty();
        if(ts.isElementAccessExpression(node.expression))note('COMPUTED_CALL',node,'Computed call target is not assessed');
        const direct=(vals:Value[])=>{if(vals.some(x=>x.uncertain))note('UNRESOLVED_VALUE',node,'Sink value includes an unsupported transformation');};
        if(called?.module==='child_process'){
          if(['spawn','spawnSync','execFile','execFileSync'].includes(called.name)&&node.arguments[2]&&!ts.isObjectLiteralExpression(node.arguments[2]))note('UNRESOLVED_SHELL_OPTIONS',node,'Nonliteral shell options are not assessed');
          if(node.arguments.some(a=>ts.isObjectLiteralExpression(a)&&a.properties.some(p=>ts.isSpreadAssignment(p)||(ts.isPropertyAssignment(p)&&ts.isComputedPropertyName(p.name)))))note('UNRESOLVED_SHELL_OPTIONS',node,'Spread process options are not assessed');
          const shellOption=node.arguments.some(a=>ts.isObjectLiteralExpression(a)&&prop(a,'shell')?.initializer.kind===ts.SyntaxKind.TrueKeyword);
          if(['exec','execSync'].includes(called.name)&&first.input){direct([first]);emit('MG001',node,name.text);}
          if(['spawn','spawnSync','execFile','execFileSync'].includes(called.name)&&shellOption&&vals.slice(0,2).some(x=>x.input)){direct(vals.slice(0,2));emit('MG001',node,name.text);}
          if(node.arguments.some(a=>ts.isObjectLiteralExpression(a)&&prop(a,'shell')&&!([ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword].includes(prop(a,'shell')!.initializer.kind))))note('UNKNOWN_SHELL_OPTION',node,'Dynamic shell option is not assessed');
        }else if(called&&['fs','fs/promises'].includes(called.module)){
          const mutations=['writeFile','writeFileSync','appendFile','appendFileSync','unlink','unlinkSync','rm','rmSync','rmdir','rmdirSync','mkdir','mkdirSync','rename','renameSync','copyFile','copyFileSync','truncate','truncateSync'];
          const paths=[...mutations,'readFile','readFileSync','readdir','readdirSync','open','openSync','stat','statSync','access','accessSync','createReadStream','createWriteStream'];
          if(paths.includes(called.name)&&first.input){direct([first]);emit('MG002',node,name.text);}
          if(['rename','renameSync','copyFile','copyFileSync'].includes(called.name)&&vals[1]?.input&&!first.input)emit('MG002',node,name.text);
          if(readonly&&mutations.includes(called.name))emit('MG006',node,name.text,readonly);
        }else if(global(node.expression,'fetch')&&first.input){direct([first]);emit('MG003',node,name.text);
        }else if(called&&['http','https'].includes(called.module)&&['get','request'].includes(called.name)&&first.input){direct([first]);emit('MG003',node,name.text);}
        const consoleSink=ts.isPropertyAccessExpression(node.expression)&&global(node.expression.expression,'console')&&['log','warn','error','info','debug'].includes(node.expression.name.text);
        if((consoleSink||(called?.module==='console'&&['log','warn','error','info','debug'].includes(called.name)))&&vals.some(x=>x.env))emit('MG004',node,name.text);
        const known=called&&['child_process','fs','fs/promises','path','path/posix','http','https','console'].includes(called.module)||global(node.expression,'fetch')||global(node.expression,'String')||global(node.expression,'URL')||consoleSink||['JSON.stringify','Object.keys','Object.values'].includes(node.expression.getText(sf));
        if(!known&&(readonly||vals.some(x=>x.input||x.env)))note('UNRESOLVED_CALL',node,'Input or environment value reaches a call outside the supported API subset');
      }
      ts.forEachChild(node,visit);
    };visit(fn.body);
    if(!ts.isBlock(fn.body)&&evalValue(fn.body).env)emit('MG004',fn.body,name.text);
    values.clear();for(const [k,v] of saved)values.set(k,v);
  }
  out.findings.sort((a,b)=>a.ruleId.localeCompare(b.ruleId)||(a.locations.at(-1)?.line??0)-(b.locations.at(-1)?.line??0));
  return out;
}
