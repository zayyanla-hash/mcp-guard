import { validateResult } from './reporting.js';
import { ruleMeta } from './rules.js';
import { hash } from './shared.js';
import { VERSION } from './version.js';
import type { AuditResult, Finding, Location } from './types.js';

function sarifLevel(severity: Finding['severity']): 'error' | 'warning' | 'note' {
  if (severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

function normalizeUri(raw: string | undefined, fallback: string): string {
  const value = (raw && raw.trim()) ? raw.trim() : fallback;
  return value.replace(/\\/g, '/').replace(/^\/+/, '') || 'target';
}

function toSarifLocation(loc: Location, fallbackUri: string) {
  const uri = normalizeUri(loc.file, fallbackUri);
  const physicalLocation: Record<string, unknown> = {
    artifactLocation: { uri, uriBaseId: '%SRCROOT%' }
  };
  if (loc.line !== undefined) {
    physicalLocation.region = {
      startLine: loc.line,
      ...(loc.column !== undefined ? { startColumn: loc.column } : {})
    };
  }
  const out: Record<string, unknown> = { physicalLocation };
  if (loc.pointer) {
    out.logicalLocations = [{ fullyQualifiedName: loc.pointer, kind: 'member' }];
  }
  return out;
}

export function buildSarif(input: AuditResult): Record<string, unknown> {
  const result = validateResult(input);
  const fallbackUri = normalizeUri(result.target, 'audit-target');

  const ruleIds = new Set<string>(result.coverage.rulesApplied);
  for (const f of result.findings) ruleIds.add(f.ruleId);
  if (result.kind === 'diff' && result.changes?.length) ruleIds.add('MG-DRIFT');

  const rules = [...ruleIds].sort().map(id => {
    const meta = ruleMeta(id);
    const findingExample = result.findings.find(f => f.ruleId === id);
    const owasp = meta?.owaspMcpTop10 ?? findingExample?.owaspMcpTop10;
    return {
      id,
      name: meta?.name ?? id,
      shortDescription: { text: meta?.shortDescription ?? findingExample?.title ?? `Vambrace rule ${id}` },
      helpUri: owasp?.url ?? 'https://owasp.org/www-project-mcp-top-10/',
      properties: {
        tags: ['security', 'mcp', ...(owasp ? [owasp.id] : [])],
        ...(owasp ? { owaspMcpTop10: owasp } : {})
      }
    };
  });

  const results: Array<Record<string, unknown>> = result.findings.map(f => ({
    ruleId: f.ruleId,
    level: sarifLevel(f.severity),
    message: {
      text: `${f.title}. ${f.observed} Evidence: ${f.evidence} Remediation: ${f.remediation}`
    },
    locations: f.locations.map(loc => toSarifLocation(loc, fallbackUri)),
    partialFingerprints: {
      'vambrace/v1': f.fingerprint
    },
    properties: {
      ruleVersion: f.ruleVersion,
      confidence: f.confidence,
      evidenceType: f.evidenceType,
      ...(f.engine ? { engine: f.engine } : {}),
      ...(f.owaspMcpTop10 ? { owaspMcpTop10: f.owaspMcpTop10 } : {})
    }
  }));

  if (result.kind === 'diff' && result.changes?.length) {
    for (const change of result.changes) {
      results.push({
        ruleId: 'MG-DRIFT',
        level: 'warning',
        message: {
          text: `Descriptor drift observed (${change.kind})${change.tool ? ` on tool "${change.tool}"` : ''}${change.pointer ? ` at ${change.pointer}` : ''}.`
        },
        locations: [toSarifLocation({ pointer: change.pointer ?? '/tools' }, fallbackUri)],
        partialFingerprints: {
          'vambrace/v1': hash(change)
        },
        properties: {
          engine: 'vambrace-inventory',
          kind: change.kind
        }
      });
    }
  }

  const notifications = result.coverage.diagnostics.map(d => ({
    descriptor: { id: d.code },
    level: 'warning',
    message: { text: `${d.code}: ${d.message}` },
    ...(d.file || d.pointer
      ? { locations: [toSarifLocation({ file: d.file, pointer: d.pointer }, fallbackUri)] }
      : {})
  }));

  if (!result.coverage.complete && notifications.length === 0) {
    notifications.push({
      descriptor: { id: 'COVERAGE_INCOMPLETE' },
      level: 'warning',
      message: { text: 'Coverage is incomplete for declared checks.' }
    });
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Vambrace',
            semanticVersion: VERSION,
            informationUri: 'https://github.com/zayyanla-hash/vambrace',
            rules
          }
        },
        results,
        invocations: [
          {
            executionSuccessful: result.coverage.complete,
            ...(notifications.length ? { toolExecutionNotifications: notifications } : {})
          }
        ]
      }
    ]
  };
}

export function renderSarif(input: AuditResult): string {
  return JSON.stringify(buildSarif(input), null, 2);
}
