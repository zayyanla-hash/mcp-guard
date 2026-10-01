// Reviewed project-owned behavior fixture, executed only by the fixture tests.
// Existing-file containment; not race safe. No claim about general write paths.
import { realpath } from 'node:fs/promises';
import { resolve, relative, isAbsolute, sep } from 'node:path';
export async function containedExistingPath(root, candidate) {
  if (isAbsolute(candidate)) throw new Error('Absolute paths rejected');
  const base = await realpath(root);
  const full = resolve(base, candidate);
  const rel = relative(base, full);
  if (rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel)) throw new Error('Traversal rejected');
  const actual = await realpath(full);
  const realRel = relative(base, actual);
  if (realRel === '..' || realRel.startsWith('..' + sep) || isAbsolute(realRel)) throw new Error('Symlink escape rejected');
  return actual;
}
