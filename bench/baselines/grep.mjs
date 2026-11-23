import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const GREP_PATTERNS = {
  MG001: /\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/g,
  MG002: /\b(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|unlink|rmSync|mkdir|createWriteStream|openSync)\s*\(/g,
  MG003: /\b(?:fetch|https?\.(?:get|request))\s*\(/g,
  MG004: /\bprocess\.env\b/g
};

export function grepScanSource(file, text) {
  const hits = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const [ruleId, re] of Object.entries(GREP_PATTERNS)) {
      re.lastIndex = 0;
      const m = re.exec(line);
      if (m) {
        hits.push({ ruleId, file, line: i + 1, match: m[0] });
      }
    }
  }
  return hits;
}

export function runGrepBaseline(files) {
  const findings = [];
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    findings.push(...grepScanSource(file, text));
  }
  const byRule = Object.fromEntries(Object.keys(GREP_PATTERNS).map(r => [r, findings.filter(f => f.ruleId === r).length]));
  return { engine: 'baseline-grep', total: findings.length, byRule, findings };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const files = process.argv.slice(2);
  console.log(JSON.stringify(runGrepBaseline(files), null, 2));
}
