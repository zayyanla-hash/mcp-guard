import { parentPort, workerData } from 'node:worker_threads';
import { analyzeSource } from './analyzer.js';
try { parentPort!.postMessage({result:analyzeSource(workerData.file,workerData.text)}); }
catch(error) { parentPort!.postMessage({error:error instanceof Error?error.message:'Analyzer failed'}); }
