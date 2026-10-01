import type { AuditResult, Severity } from './types.js';
const levels:Record<Severity,number>={low:0,medium:1,high:2};
export function policyExit(result:AuditResult,threshold:Severity='medium'):0|1|3 {
  if(!result.coverage.complete)return 3;
  if(result.kind==='diff'&&result.changes?.length)return 1;
  return result.findings.some(f=>levels[f.severity]>=levels[threshold])?1:0;
}
