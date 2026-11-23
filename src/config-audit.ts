import path from 'node:path';
import { coverage, finding } from './shared.js';
import type { AuditResult } from './types.js';

export const CONFIG_RULES = ['MG008', 'MG009', 'MG010', 'MG011', 'MG012'];

type Obj = Record<string, unknown>;
const isObject = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);

const SECRET_ENV_KEY = /(?:SECRET|TOKEN|PASSWORD|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL|DATABASE_?URL|DB_?URL|REDIS_?URL|DSN|AUTH_?HEADER)/i;
const SECRET_VALUE_PATTERN = /\b(?:FAKE_[A-Z0-9_]*(?:SECRET|TOKEN|KEY|CANARY)[A-Z0-9_]*|CANARY_[A-Z0-9_]+|gh[pousr]_[A-Za-z0-9_]{16,}|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b/;
const ENV_PLACEHOLDER = /^(?:\$\{[A-Za-z0-9_.:-]+\}|\$[A-Za-z_][A-Za-z0-9_]*|<[A-Za-z0-9_-]+>|YOUR_[A-Z0-9_]+|REPLACE_ME|changeme|example)$/i;

const BROAD_ROOT = /^(?:\/|~\/?|~\/\*|\$HOME|\$\{HOME\}|\/Users\/[^/]+\/?|\/home\/[^/]+\/?|[A-Za-z]:\\?)$/i;
const SHELL_BINARIES = new Set(['sh', 'bash', 'zsh', 'dash', 'ash', 'ksh', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh']);

function isUnpinnedNpxPackage(spec: string): boolean {
  const trimmed = spec.trim();
  if (!trimmed || trimmed.startsWith('-')) return false;
  if (trimmed.startsWith('@')) {
    const slashIdx = trimmed.indexOf('/');
    if (slashIdx === -1) return true;
    const afterScope = trimmed.slice(slashIdx + 1);
    const atIdx = afterScope.indexOf('@');
    if (atIdx === -1) return true;
    const version = afterScope.slice(atIdx + 1);
    return !version || version === 'latest' || version === 'next';
  }
  const atIdx = trimmed.indexOf('@');
  if (atIdx === -1) return true;
  const version = trimmed.slice(atIdx + 1);
  return !version || version === 'latest' || version === 'next';
}

export function auditClientConfig(input: unknown, targetLabel = 'mcp.json'): AuditResult {
  const cov = coverage(CONFIG_RULES);
  const out: AuditResult = {
    schemaVersion: 1,
    kind: 'config',
    target: targetLabel,
    findings: [],
    coverage: cov
  };

  if (!isObject(input)) {
    cov.complete = false;
    cov.failed = [targetLabel];
    cov.diagnostics.push({ code: 'INVALID_CONFIG', file: targetLabel, message: 'MCP client configuration must be a JSON object.' });
    return out;
  }

  let serverMap: Record<string, unknown> | undefined;
  let rootKey = '';
  if (isObject(input.mcpServers)) {
    serverMap = input.mcpServers;
    rootKey = 'mcpServers';
  } else if (isObject(input.servers)) {
    serverMap = input.servers;
    rootKey = 'servers';
  }

  if (!serverMap) {
    cov.complete = false;
    cov.diagnostics.push({ code: 'UNSUPPORTED_CONFIG_SHAPE', file: targetLabel, message: 'Expected a top-level "mcpServers" or "servers" object.' });
    return out;
  }

  cov.inspected = [targetLabel];
  const entries = Object.entries(serverMap);
  cov.recognizedTools = entries.length;
  if (entries.length === 0) {
    cov.complete = false;
    cov.diagnostics.push({ code: 'EMPTY_CONFIG_SERVERS', file: targetLabel, message: 'No MCP servers configured in config file.' });
    return out;
  }

  for (const [serverName, cfg] of entries) {
    const basePtr = `/${rootKey}/${serverName.replace(/~/g, '~0').replace(/\//g, '~1')}`;
    if (!isObject(cfg)) {
      cov.complete = false;
      cov.unresolvedHandlers++;
      cov.diagnostics.push({ code: 'INVALID_SERVER_ENTRY', file: targetLabel, pointer: basePtr, message: `Server "${serverName}" entry is not an object.` });
      continue;
    }

    const command = typeof cfg.command === 'string' ? cfg.command : undefined;
    const args = Array.isArray(cfg.args) ? cfg.args.filter((a): a is string => typeof a === 'string') : [];
    if (Array.isArray(cfg.args) && cfg.args.some(a => typeof a !== 'string')) {
      cov.complete = false;
      cov.diagnostics.push({ code: 'NONSTRING_CONFIG_ARG', file: targetLabel, pointer: `${basePtr}/args`, message: `Server "${serverName}" has non-string args.` });
    }

    // MG008: secrets in env or args
    if (isObject(cfg.env)) {
      for (const [envKey, envVal] of Object.entries(cfg.env)) {
        if (typeof envVal !== 'string') continue;
        const val = envVal.trim();
        if (!val || ENV_PLACEHOLDER.test(val)) continue;
        if (SECRET_ENV_KEY.test(envKey) || SECRET_VALUE_PATTERN.test(val)) {
          out.findings.push(finding({
            engine: 'vambrace-config',
            ruleId: 'MG008',
            title: 'Hardcoded secret in MCP server env configuration',
            category: 'client-config',
            severity: 'high',
            confidence: 'high',
            evidenceType: 'metadata-observation',
            locations: [{ file: targetLabel, pointer: `${basePtr}/env/${envKey}` }],
            evidence: `${envKey}=[REDACTED]`,
            observed: `Server "${serverName}" defines a literal value for sensitive env key "${envKey}".`,
            why: 'Literal secrets in client configs are easily leaked via dotfiles, backups, or shared repositories.',
            assumptions: ['Client config is parsed statically and never executed.'],
            remediation: 'Reference environment variables or an OS keychain/secret manager instead of embedding literals.',
            limitations: ['Static inspection flags secret-looking key names and known token formats without verifying token validity.']
          }));
        }
      }
    }
    args.forEach((arg, idx) => {
      if (SECRET_VALUE_PATTERN.test(arg) || /^--(?:api[-_]?key|token|password|secret)=.+$/i.test(arg)) {
        const valPart = arg.includes('=') ? arg.slice(arg.indexOf('=') + 1).trim() : arg;
        if (!ENV_PLACEHOLDER.test(valPart)) {
          out.findings.push(finding({
            engine: 'vambrace-config',
            ruleId: 'MG008',
            title: 'Hardcoded secret in MCP server args configuration',
            category: 'client-config',
            severity: 'high',
            confidence: 'high',
            evidenceType: 'metadata-observation',
            locations: [{ file: targetLabel, pointer: `${basePtr}/args/${idx}` }],
            evidence: arg,
            observed: `Server "${serverName}" passes a credential-like value in command arguments.`,
            why: 'Secrets in CLI args can expose credentials in process lists and config files.',
            assumptions: ['Client config is parsed statically and never executed.'],
            remediation: 'Pass credentials via secret injection or environment variable references rather than CLI arguments.',
            limitations: ['Heuristic token/flag detection only.']
          }));
        }
      }
    });

    // MG009: npx -y without pinned version
    if (command && path.posix.basename(command.replace(/\\/g, '/')) === 'npx') {
      const hasAutoYes = args.some(a => a === '-y' || a === '--yes');
      if (hasAutoYes) {
        const pkgArgIndex = args.findIndex(a => !a.startsWith('-'));
        const pkgArg = pkgArgIndex >= 0 ? args[pkgArgIndex] : undefined;
        if (!pkgArg || isUnpinnedNpxPackage(pkgArg)) {
          out.findings.push(finding({
            engine: 'vambrace-config',
            ruleId: 'MG009',
            title: 'Unpinned npx -y package execution in MCP config',
            category: 'client-config',
            severity: 'medium',
            confidence: 'high',
            evidenceType: 'metadata-observation',
            locations: [{ file: targetLabel, pointer: `${basePtr}/args${pkgArgIndex >= 0 ? `/${pkgArgIndex}` : ''}` }],
            evidence: `${command} ${args.join(' ')}`.trim(),
            observed: `Server "${serverName}" invokes npx with auto-install (-y) and an unpinned package (${pkgArg ?? 'missing package'}).`,
            why: 'Unpinned npx -y fetches and runs the latest remote package version without integrity pinning.',
            assumptions: ['Client runs npx against the configured registry when launching the server.'],
            remediation: 'Pin an exact package version (e.g. pkg@1.2.3) and verify integrity/lockfiles before execution.',
            limitations: ['Version pinning check is syntactic and does not verify registry provenance.']
          }));
        }
      }
    }

    // MG010: plain http:// URLs
    for (const urlField of ['url', 'endpoint', 'baseUrl', 'sseUrl']) {
      const val = cfg[urlField];
      if (typeof val === 'string' && /^http:\/\//i.test(val.trim())) {
        out.findings.push(finding({
          engine: 'vambrace-config',
          ruleId: 'MG010',
          title: 'Cleartext http:// URL in MCP client configuration',
          category: 'client-config',
          severity: 'medium',
          confidence: 'high',
          evidenceType: 'metadata-observation',
          locations: [{ file: targetLabel, pointer: `${basePtr}/${urlField}` }],
          evidence: `${urlField}: ${val}`,
          observed: `Server "${serverName}" configures plaintext HTTP endpoint "${val}".`,
          why: 'Plain HTTP exposes tool traffic and credentials in transit.',
          assumptions: ['Transport uses the configured URL without an external TLS wrapper.'],
          remediation: 'Use https:// with TLS verification for remote MCP endpoints.',
          limitations: ['Loopback addresses may be intentional in local dev but are still flagged for review.']
        }));
      }
    }
    args.forEach((arg, idx) => {
      if (/^http:\/\//i.test(arg.trim())) {
        out.findings.push(finding({
          engine: 'vambrace-config',
          ruleId: 'MG010',
          title: 'Cleartext http:// URL argument in MCP client configuration',
          category: 'client-config',
          severity: 'medium',
          confidence: 'high',
          evidenceType: 'metadata-observation',
          locations: [{ file: targetLabel, pointer: `${basePtr}/args/${idx}` }],
          evidence: arg,
          observed: `Server "${serverName}" passes plaintext HTTP URL "${arg}" in args.`,
          why: 'Plain HTTP exposes tool traffic and credentials in transit.',
          assumptions: ['Argument configures an outbound or server transport endpoint.'],
          remediation: 'Use https:// instead of plaintext http://.',
          limitations: ['Syntactic URL inspection only.']
        }));
      }
    });

    // MG011: broad filesystem roots (/ or home)
    args.forEach((arg, idx) => {
      if (BROAD_ROOT.test(arg.trim())) {
        out.findings.push(finding({
          engine: 'vambrace-config',
          ruleId: 'MG011',
          title: 'Broad filesystem root exposed in MCP configuration',
          category: 'client-config',
          severity: 'high',
          confidence: 'high',
          evidenceType: 'metadata-observation',
          locations: [{ file: targetLabel, pointer: `${basePtr}/args/${idx}` }],
          evidence: arg,
          observed: `Server "${serverName}" passes broad root path "${arg}" in args.`,
          why: 'Granting access to "/" or the entire user home directory exposes SSH keys, cloud credentials, and system files.',
          assumptions: ['Server treats directory arguments as allowed filesystem roots.'],
          remediation: 'Restrict filesystem roots to a narrow project subdirectory.',
          limitations: ['Matches common root/home paths; custom symlinks or mounts are not resolved.']
        }));
      }
    });
    if (Array.isArray(cfg.roots)) {
      cfg.roots.forEach((r, idx) => {
        if (typeof r === 'string' && BROAD_ROOT.test(r.trim())) {
          out.findings.push(finding({
            engine: 'vambrace-config',
            ruleId: 'MG011',
            title: 'Broad filesystem root in MCP roots configuration',
            category: 'client-config',
            severity: 'high',
            confidence: 'high',
            evidenceType: 'metadata-observation',
            locations: [{ file: targetLabel, pointer: `${basePtr}/roots/${idx}` }],
            evidence: r,
            observed: `Server "${serverName}" lists broad root "${r}" in roots.`,
            why: 'Granting access to "/" or the user home folder exposes sensitive host files.',
            assumptions: ['Client enforces or forwards configured roots to the MCP server.'],
            remediation: 'Scope configured roots to specific workspace directories.',
            limitations: ['Syntactic root inspection only.']
          }));
        }
      });
    }

    // MG012: shell wrappers (sh -c, bash -c, cmd /c, etc.)
    if (command) {
      const base = path.posix.basename(command.replace(/\\/g, '/')).toLowerCase();
      const firstFlag = args[0]?.toLowerCase() ?? '';
      const hasShellFlag = args.some(a => ['-c', '-lc', '/c', '/k', '-command'].includes(a.toLowerCase()));
      if (SHELL_BINARIES.has(base) && (hasShellFlag || firstFlag === '-c' || firstFlag === '/c')) {
        out.findings.push(finding({
          engine: 'vambrace-config',
          ruleId: 'MG012',
          title: 'Shell wrapper used to launch MCP server',
          category: 'client-config',
          severity: 'high',
          confidence: 'high',
          evidenceType: 'metadata-observation',
          locations: [{ file: targetLabel, pointer: `${basePtr}/command` }],
          evidence: `${command} ${args.join(' ')}`.trim(),
          observed: `Server "${serverName}" launches through shell wrapper "${base}".`,
          why: 'Shell wrappers introduce shell parsing, metacharacter expansion, and injection risks on launch.',
          assumptions: ['Client invokes the configured command and args directly.'],
          remediation: 'Invoke the MCP server executable directly with structured argument arrays instead of a shell wrapper.',
          limitations: ['Checks common POSIX and Windows shell wrapper binaries.']
        }));
      }
    }
  }

  return out;
}
