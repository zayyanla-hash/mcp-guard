import { execFileSync } from 'node:child_process';
import { constants, promises as fs } from 'node:fs';
import path from 'node:path';
import { coverage, finding } from './shared.js';
import type { AuditResult, Finding } from './types.js';

export type ExecFileSyncLike = (
  file: string,
  args: string[],
  options: { encoding: 'utf8'; timeout: number; stdio: ['ignore', 'pipe', 'pipe'] }
) => string;

export interface DepsScanOptions {
  allowNetwork?: boolean;
  execImpl?: ExecFileSyncLike;
}

function mapOsvSeverity(vuln: Record<string, unknown>): Finding['severity'] {
  const dbSpec = vuln.database_specific as Record<string, unknown> | undefined;
  const raw = String(dbSpec?.severity ?? '').toUpperCase();
  if (raw === 'CRITICAL' || raw === 'HIGH') return 'high';
  if (raw === 'MODERATE' || raw === 'MEDIUM') return 'medium';
  if (raw === 'LOW') return 'low';
  const sevArr = Array.isArray(vuln.severity) ? vuln.severity : [];
  for (const s of sevArr) {
    if (s && typeof s === 'object' && 'score' in s) {
      const scoreText = String((s as Record<string, unknown>).score ?? '');
      const num = Number(scoreText);
      if (Number.isFinite(num)) {
        if (num >= 7) return 'high';
        if (num >= 4) return 'medium';
        return 'low';
      }
    }
  }
  return 'medium';
}

export async function scanDepsLockfile(lockfilePath: string, options: DepsScanOptions = {}): Promise<AuditResult> {
  const cov = coverage(['OSV']);
  const displayPath = lockfilePath;
  const out: AuditResult = {
    schemaVersion: 1,
    kind: 'deps',
    target: displayPath,
    findings: [],
    coverage: cov
  };

  if (options.allowNetwork !== true) {
    cov.complete = false;
    cov.diagnostics.push({
      code: 'NETWORK_OPT_IN_REQUIRED',
      file: displayPath,
      message: 'osv-scanner dependency lookup requires explicit --allow-network opt-in; refusing network access by default.'
    });
    return out;
  }

  const stat = await fs.lstat(lockfilePath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error('Lockfile input must be a regular file, not a symlink.');
  }
  const fd = await fs.open(lockfilePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await fd.stat();
    if (opened.ino !== stat.ino || opened.dev !== stat.dev) {
      throw new Error('Lockfile changed during verification.');
    }
  } finally {
    await fd.close();
  }

  const execImpl = options.execImpl ?? ((file, args, opts) => execFileSync(file, args, opts));
  let stdout = '';
  try {
    stdout = execImpl('osv-scanner', ['scan', 'source', '--format', 'json', '--lockfile', path.resolve(lockfilePath)], {
      encoding: 'utf8',
      timeout: 30_000,
      stdio: ['ignore', 'pipe', 'pipe']
    });
  } catch (err: unknown) {
    const e = err as { code?: string; status?: number; stdout?: Buffer | string; message?: string };
    // osv-scanner exits 1 when vulnerabilities are found and still writes JSON to stdout
    if (e.status === 1 && e.stdout) {
      stdout = typeof e.stdout === 'string' ? e.stdout : e.stdout.toString('utf8');
    } else if (e.code === 'ENOENT') {
      cov.complete = false;
      cov.failed = [displayPath];
      cov.diagnostics.push({
        code: 'OSV_SCANNER_UNAVAILABLE',
        file: displayPath,
        message: 'osv-scanner binary was not found on PATH; lockfile was not scanned.'
      });
      return out;
    } else {
      cov.complete = false;
      cov.failed = [displayPath];
      cov.diagnostics.push({
        code: 'OSV_SCANNER_ERROR',
        file: displayPath,
        message: e.message ? String(e.message) : 'osv-scanner failed to execute.'
      });
      return out;
    }
  }

  let parsed: { results?: Array<{ packages?: Array<{ package?: { name?: string; version?: string; ecosystem?: string }; vulnerabilities?: Array<Record<string, unknown>> }> }> };
  try {
    parsed = JSON.parse(stdout);
  } catch {
    cov.complete = false;
    cov.failed = [displayPath];
    cov.diagnostics.push({
      code: 'OSV_OUTPUT_INVALID',
      file: displayPath,
      message: 'osv-scanner output was not valid JSON.'
    });
    return out;
  }

  cov.inspected = [displayPath];
  const results = Array.isArray(parsed.results) ? parsed.results : [];
  let pkgIdx = 0;
  for (const r of results) {
    const packages = Array.isArray(r.packages) ? r.packages : [];
    cov.recognizedTools += packages.length;
    for (const pkgEntry of packages) {
      const pkgName = String(pkgEntry.package?.name ?? 'unknown');
      const pkgVersion = String(pkgEntry.package?.version ?? 'unknown');
      const vulns = Array.isArray(pkgEntry.vulnerabilities) ? pkgEntry.vulnerabilities : [];
      for (const vuln of vulns) {
        const id = String(vuln.id ?? 'OSV-UNKNOWN');
        const summary = String(vuln.summary ?? vuln.details ?? 'Known vulnerability in lockfile dependency.');
        out.findings.push(finding({
          engine: 'osv-scanner',
          ruleId: 'OSV',
          title: `${id}: ${pkgName}@${pkgVersion}`,
          category: 'dependency-vulnerability',
          severity: mapOsvSeverity(vuln),
          confidence: 'high',
          evidenceType: 'metadata-observation',
          locations: [{ file: displayPath, pointer: `/packages/${pkgIdx}/${pkgName}` }],
          evidence: `${pkgName}@${pkgVersion} (${id})`,
          observed: `OSV-Scanner matched ${id} in ${pkgName}@${pkgVersion}.`,
          why: summary.slice(0, 280),
          assumptions: ['The lockfile reflects the packages installed for this server.'],
          remediation: `Upgrade ${pkgName} to a patched release listed in ${id}.`,
          limitations: ['OSV-Scanner reports known advisory matches; reachability is not established.']
        }));
      }
      pkgIdx++;
    }
  }
  return out;
}
