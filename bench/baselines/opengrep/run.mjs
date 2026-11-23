import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const rulesFile = path.join(here, 'mg001-mg004.yaml');

export function runOpengrepBaseline(targetPaths, { execImpl = execFileSync } = {}) {
  try {
    execImpl('opengrep', ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch {
    return { engine: 'opengrep', status: 'skipped', reason: 'opengrep binary not installed', findings: [] };
  }
  try {
    const stdout = execImpl('opengrep', ['scan', '--json', '--config', rulesFile, ...targetPaths], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 30_000
    });
    const parsed = JSON.parse(stdout);
    const results = Array.isArray(parsed.results) ? parsed.results : [];
    return { engine: 'opengrep', status: 'ok', total: results.length, findings: results };
  } catch (err) {
    return { engine: 'opengrep', status: 'error', reason: err instanceof Error ? err.message : String(err), findings: [] };
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const targets = process.argv.slice(2);
  console.log(JSON.stringify(runOpengrepBaseline(targets.length ? targets : ['.']), null, 2));
}
