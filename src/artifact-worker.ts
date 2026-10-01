import { parentPort, workerData } from 'node:worker_threads';
import { auditInventory, snapshotInventory, diffSnapshots } from './inventory.js';
import { renderHtml, validateResult } from './reporting.js';
try {
  const {operation, inputs} = workerData as {operation:string;inputs:unknown[]};
  let result:unknown;
  switch(operation) {
    case 'inventory': result=auditInventory(inputs[0]);break;
    case 'snapshot': result=snapshotInventory(inputs[0]);break;
    case 'diff': result=diffSnapshots(inputs[0],inputs[1]);break;
    case 'report': result=renderHtml(validateResult(inputs[0]));break;
    default: throw new Error('Unsupported artifact operation');
  }
  parentPort!.postMessage({result});
} catch(error) { parentPort!.postMessage({error:error instanceof Error?error.message:String(error)}); }
