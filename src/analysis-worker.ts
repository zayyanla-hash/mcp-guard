import { parentPort, workerData } from 'node:worker_threads';
import { analyzeSource } from './analyzer.js';
import { analyzePythonSource } from './python-analyzer.js';

void (async () => {
  try {
    const file = String(workerData.file);
    const result = file.endsWith('.py')
      ? await analyzePythonSource(file, workerData.text)
      : analyzeSource(file, workerData.text);
    parentPort!.postMessage({ result });
  } catch (error) {
    parentPort!.postMessage({ error: error instanceof Error ? error.message : 'Analyzer failed' });
  }
})();
