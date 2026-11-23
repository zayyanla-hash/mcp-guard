import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const cacheDir = path.join(here, '.cache');
const manifestPath = path.join(here, 'manifest.json');

export function loadManifest(file = manifestPath) {
  const manifest = JSON.parse(readFileSync(file, 'utf8'));
  if (!Array.isArray(manifest.servers) || manifest.servers.length === 0) {
    throw new Error('bench/manifest.json must define a non-empty servers array.');
  }
  for (const server of manifest.servers) {
    if (!server.id || !server.url || !server.commit || !server.license || !server.selectionReason) {
      throw new Error(`Manifest entry ${server.id ?? '<unknown>'} missing required fields (url, commit, license, selectionReason).`);
    }
    if (!/^[0-9a-f]{40}$/i.test(server.commit)) {
      throw new Error(`Manifest entry ${server.id} commit must be a 40-char hex SHA.`);
    }
  }
  return manifest;
}

export function fetchManifest({ manifestFile = manifestPath, targetCache = cacheDir, onlyRemote = true } = {}) {
  const manifest = loadManifest(manifestFile);
  mkdirSync(targetCache, { recursive: true });
  const results = [];
  for (const server of manifest.servers) {
    if (onlyRemote && /^0+$/.test(server.commit)) {
      results.push({ id: server.id, status: 'local-only', path: path.resolve(root, server.localFallback ?? '.') });
      continue;
    }
    const dest = path.join(targetCache, server.id);
    if (!existsSync(path.join(dest, '.git'))) {
      execFileSync('git', ['clone', '--no-checkout', server.url, dest], { stdio: 'inherit' });
    }
    execFileSync('git', ['-C', dest, 'fetch', '--depth', '1', 'origin', server.commit], { stdio: 'inherit' });
    execFileSync('git', ['-C', dest, 'checkout', '--detach', server.commit], { stdio: 'inherit' });
    const head = execFileSync('git', ['-C', dest, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    if (head !== server.commit) {
      throw new Error(`Pinned SHA mismatch for ${server.id}: expected ${server.commit}, got ${head}`);
    }
    results.push({ id: server.id, status: 'fetched', commit: head, path: server.subpath ? path.join(dest, server.subpath) : dest });
  }
  return results;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const out = fetchManifest();
  console.log(JSON.stringify(out, null, 2));
}
