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
  const seenIds = new Map();
  for (const server of manifest.servers) {
    if (!server.id || !server.url || !server.commit || !server.license || !server.selectionReason) {
      throw new Error(`Manifest entry ${server.id ?? '<unknown>'} missing required fields (url, commit, license, selectionReason).`);
    }
    if (!/^[0-9a-f]{40}$/i.test(server.commit)) {
      throw new Error(`Manifest entry ${server.id} commit must be a 40-char hex SHA.`);
    }
    const split = server.split ?? 'dev';
    if (split !== 'dev' && split !== 'test') {
      throw new Error(`Manifest entry ${server.id} has invalid split "${split}"; expected dev or test.`);
    }
    if (seenIds.has(server.id)) {
      throw new Error(`Duplicate manifest server id "${server.id}"; splits must stay partitioned by server.`);
    }
    seenIds.set(server.id, split);
  }
  return manifest;
}

export function validateSplitByServer(manifest) {
  if (!Number.isInteger(manifest.seed)) {
    throw new Error('Manifest must declare an integer fixed seed.');
  }
  if (manifest.splitBy !== 'server') {
    throw new Error('Manifest must declare splitBy: "server".');
  }
  const devServers = manifest.servers.filter(s => s.split === 'dev').map(s => s.id);
  const testServers = manifest.servers.filter(s => s.split === 'test').map(s => s.id);
  if (devServers.length === 0 || testServers.length === 0) {
    throw new Error('Manifest must include non-empty dev and test server splits.');
  }
  const overlap = devServers.filter(id => testServers.includes(id));
  if (overlap.length > 0) {
    throw new Error(`Server split overlap detected: ${overlap.join(', ')}`);
  }
  return { seed: manifest.seed, devServers, testServers };
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
