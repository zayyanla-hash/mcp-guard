export type Severity = 'low' | 'medium' | 'high';
export interface Location { file?: string; line?: number; column?: number; pointer?: string }
export interface Finding {
  ruleId: string; ruleVersion: string; title: string; category: string;
  severity: Severity; confidence: 'high' | 'medium'; evidenceType: 'static-pattern' | 'metadata-observation';
  locations: Location[]; evidence: string; observed: string; why: string;
  assumptions: string[]; remediation: string; limitations: string[]; fingerprint: string;
}
export interface Diagnostic { code: string; message: string; file?: string; pointer?: string }
export interface Coverage {
  complete: boolean; inspected: string[]; excluded: string[]; failed: string[]; truncated: string[];
  recognizedTools: number; unresolvedHandlers: number; rulesApplied: string[]; diagnostics: Diagnostic[];
}
export interface AuditResult {
  schemaVersion: 1; kind: 'source' | 'inventory' | 'diff'; target: string;
  findings: Finding[]; coverage: Coverage; changes?: {kind: string; tool?: string; pointer?: string; before?: unknown; after?: unknown}[];
}
export interface Snapshot { schemaVersion: 1; kind: 'inventory-snapshot'; hash: string; payload: unknown }
