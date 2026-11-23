import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeSource } from '../dist/analyzer.js';

function percentile(sorted, p) {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return Number(sorted[idx].toFixed(3));
}

export function measurePerf(files, iterations = 3) {
  const durations = [];
  const memoriesMb = [];
  for (let iter = 0; iter < iterations; iter++) {
    for (const file of files) {
      const text = readFileSync(file, 'utf8');
      const start = performance.now();
      analyzeSource(file, text);
      const elapsed = performance.now() - start;
      durations.push(elapsed);
      memoriesMb.push(process.memoryUsage().rss / (1024 * 1024));
    }
  }
  const sortedDur = [...durations].sort((a, b) => a - b);
  const sortedMem = [...memoriesMb].sort((a, b) => a - b);
  return {
    samples: durations.length,
    files: files.length,
    latency_ms: { p50: percentile(sortedDur, 50), p95: percentile(sortedDur, 95) },
    rss_mb: { p50: percentile(sortedMem, 50), p95: percentile(sortedMem, 95) }
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const files = process.argv.slice(2);
  console.log(JSON.stringify(measurePerf(files.length ? files : ['fixtures/vulnerable/server.ts', 'fixtures/corrected/server.ts']), null, 2));
}
