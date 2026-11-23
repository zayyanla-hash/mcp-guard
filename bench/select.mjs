import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const REGISTRY_URL = 'https://registry.modelcontextprotocol.io/v0.1/servers';
const FIXED_SEED = 20261123;
const DEV_RATIO = 0.6;
const EXCLUDED_REPO_PATTERN = /(?:zayyanla-hash\/vambrace|zayyanla-hash\/mcp-guard|modelcontextprotocol\/typescript-sdk)/i;

function seedRank(seed, key) {
  return createHash('sha256').update(`${seed}:${key}`).digest('hex');
}

function normalizeGithubRepo(url) {
  if (typeof url !== 'string') return null;
  const m = url.trim().replace(/\.git$/i, '').match(/^https?:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)(?:\/|$)/i);
  if (!m) return null;
  return { owner: m[1], repo: m[2], canonicalUrl: `https://github.com/${m[1]}/${m[2]}.git` };
}

function classifyLicenseText(text) {
  if (/Permission is hereby granted, free of charge, to any person obtaining a copy/i.test(text) && /THE SOFTWARE IS PROVIDED "AS IS"/i.test(text)) {
    return 'MIT';
  }
  if (/Apache License\s+Version 2\.0/i.test(text) || /http:\/\/www\.apache\.org\/licenses\/LICENSE-2\.0/i.test(text)) {
    return 'Apache-2.0';
  }
  return null;
}

async function detectRepoLicense(owner, repo, commit, subpath) {
  const candidates = [];
  if (subpath) {
    for (const f of ['LICENSE', 'LICENSE.md', 'LICENSE.txt']) {
      candidates.push(`https://raw.githubusercontent.com/${owner}/${repo}/${commit}/${subpath}/${f}`);
    }
  }
  for (const f of ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'LICENSE-MIT', 'LICENSE-APACHE']) {
    candidates.push(`https://raw.githubusercontent.com/${owner}/${repo}/${commit}/${f}`);
  }
  for (const url of candidates) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
      if (!res.ok) continue;
      const body = await res.text();
      const lic = classifyLicenseText(body);
      if (lic) return lic;
    } catch { /* try next candidate */ }
  }
  try {
    const apiRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/license`, {
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'vambrace-benchmark-selector' },
      signal: AbortSignal.timeout(8000)
    });
    if (apiRes.ok) {
      const json = await apiRes.json();
      const spdx = json?.license?.spdx_id;
      if (spdx === 'MIT' || spdx === 'Apache-2.0') return spdx;
    }
  } catch { /* ignore */ }
  return null;
}

function resolveRemoteHead(repoUrl) {
  try {
    const out = execFileSync('git', ['ls-remote', '--exit-code', repoUrl, 'HEAD'], {
      encoding: 'utf8',
      timeout: 15000,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    const sha = out.trim().split(/\s+/)[0];
    return /^[0-9a-f]{40}$/i.test(sha) ? sha.toLowerCase() : null;
  } catch {
    return null;
  }
}

async function fetchRegistrySnapshot(maxPages = 40) {
  const seen = new Map();
  let cursor = null;
  let pages = 0;
  while (pages < maxPages) {
    const url = new URL(REGISTRY_URL);
    url.searchParams.set('limit', '100');
    if (cursor) url.searchParams.set('cursor', cursor);
    const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) {
      throw new Error(`Registry fetch failed (${res.status}) at ${url}`);
    }
    const page = await res.json();
    const list = Array.isArray(page.servers) ? page.servers : [];
    for (const entry of list) {
      const s = entry?.server;
      const meta = entry?._meta?.['io.modelcontextprotocol.registry/official'];
      if (!s?.name || (meta && meta.status !== 'active')) continue;
      if (meta && meta.isLatest === false && seen.has(s.name)) continue;
      seen.set(s.name, { server: s, meta: meta ?? null });
    }
    pages++;
    cursor = page?.metadata?.nextCursor ?? null;
    if (!cursor || list.length === 0) break;
  }
  return {
    schemaVersion: 1,
    fetchedAt: new Date().toISOString(),
    sourceUrl: REGISTRY_URL,
    pagesFetched: pages,
    totalLatestServers: seen.size,
    servers: [...seen.values()]
  };
}

function detectLanguage(server) {
  const pkgs = Array.isArray(server.packages) ? server.packages : [];
  const types = new Set(pkgs.map(p => String(p?.registryType ?? p?.registry_type ?? '').toLowerCase()));
  if (types.has('npm')) return 'ts';
  if (types.has('pypi')) return 'py';
  return null;
}

function makeServerId(name, owner, repo) {
  return `${owner}-${repo}-${name}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
}

async function pickSeededServers(candidates, lang, targetCount, seed) {
  const ranked = [...candidates]
    .map(c => ({ ...c, rank: seedRank(seed, `${lang}:${c.server.name}:${c.repo.canonicalUrl}`) }))
    .sort((a, b) => a.rank.localeCompare(b.rank));

  const picked = [];
  const seenRepos = new Set();
  const seenIds = new Set();
  for (const item of ranked) {
    if (picked.length >= targetCount) break;
    if (seenRepos.has(item.repo.canonicalUrl)) continue;
    const sha = resolveRemoteHead(item.repo.canonicalUrl);
    if (!sha) continue;
    const subpath = typeof item.server.repository?.subfolder === 'string' && item.server.repository.subfolder.trim()
      ? item.server.repository.subfolder.trim().replace(/^\/+|\/+$/g, '')
      : undefined;
    const license = await detectRepoLicense(item.repo.owner, item.repo.repo, sha, subpath);
    if (!license) continue;
    const id = makeServerId(item.server.name, item.repo.owner, item.repo.repo);
    if (seenIds.has(id)) continue;
    seenRepos.add(item.repo.canonicalUrl);
    seenIds.add(id);
    picked.push({
      id,
      registryName: item.server.name,
      url: item.repo.canonicalUrl,
      commit: sha,
      ...(subpath ? { subpath } : {}),
      license,
      selectionReason: `MCP Registry (${lang}) seeded sample (rank ${item.rank.slice(0, 12)}, verified ${license} license)`,
      seedRank: item.rank
    });
  }

  // Partition deterministically by server into dev (60%) and test (40%) using fixed seed
  const devCount = Math.max(1, Math.round(picked.length * DEV_RATIO));
  return picked.map((entry, idx) => {
    const { seedRank: _rank, registryName: _reg, ...rest } = entry;
    return {
      ...rest,
      split: idx < devCount ? 'dev' : 'test'
    };
  });
}

export async function runSelect({
  snapshotPath = path.join(here, 'registry-snapshot.json'),
  fromSnapshot = false,
  seed = FIXED_SEED,
  tsCount = 5,
  pyCount = 5,
  maxPages = 40
} = {}) {
  const snapshot = fromSnapshot && existsSync(snapshotPath)
    ? JSON.parse(readFileSync(snapshotPath, 'utf8'))
    : await fetchRegistrySnapshot(maxPages);

  if (!fromSnapshot) {
    writeFileSync(snapshotPath, JSON.stringify(snapshot, null, 2) + '\n', 'utf8');
  }

  const tsCandidates = [];
  const pyCandidates = [];
  for (const item of snapshot.servers) {
    const s = item.server;
    const repo = normalizeGithubRepo(s?.repository?.url);
    if (!repo) continue;
    if (EXCLUDED_REPO_PATTERN.test(repo.canonicalUrl)) continue;
    const lang = detectLanguage(s);
    if (lang === 'ts') tsCandidates.push({ server: s, repo });
    else if (lang === 'py') pyCandidates.push({ server: s, repo });
  }

  const tsServers = await pickSeededServers(tsCandidates, 'ts', tsCount, seed);
  const pyServers = await pickSeededServers(pyCandidates, 'py', pyCount, seed);

  const samplingRule = `Sort active MCP Registry servers (npm/pypi, public GitHub, verified MIT or Apache-2.0, excluding Vambrace fixtures and typescript-sdk examples) ascending by sha256("${seed}:<lang>:<registryName>:<repoUrl>"). Take first N per language and assign first round(N * ${DEV_RATIO}) servers to dev, remaining to test.`;

  const tsManifest = {
    schemaVersion: 1,
    seed,
    splitBy: 'server',
    splitRatio: { dev: DEV_RATIO, test: Number((1 - DEV_RATIO).toFixed(2)) },
    samplingRule,
    snapshotFile: 'bench/registry-snapshot.json',
    snapshotFetchedAt: snapshot.fetchedAt,
    note: 'Real-world TypeScript/JavaScript MCP servers sampled from the official MCP Registry. Run node bench/fetch.mjs to clone pinned commits into bench/.cache/. Test-split labels remain outside this repository.',
    servers: tsServers
  };

  const pyManifest = {
    schemaVersion: 1,
    seed,
    splitBy: 'server',
    splitRatio: { dev: DEV_RATIO, test: Number((1 - DEV_RATIO).toFixed(2)) },
    samplingRule,
    snapshotFile: 'bench/registry-snapshot.json',
    snapshotFetchedAt: snapshot.fetchedAt,
    note: 'Real-world Python MCP servers sampled from the official MCP Registry. Run node bench/fetch.mjs to clone pinned commits into bench/.cache/. Test-split labels remain outside this repository.',
    servers: pyServers
  };

  writeFileSync(path.join(here, 'manifest.json'), JSON.stringify(tsManifest, null, 2) + '\n', 'utf8');
  writeFileSync(path.join(here, 'python-manifest.json'), JSON.stringify(pyManifest, null, 2) + '\n', 'utf8');

  return {
    snapshotPath,
    snapshotTotalServers: snapshot.totalLatestServers,
    candidates: { ts: tsCandidates.length, py: pyCandidates.length },
    typescript: { count: tsServers.length, dev: tsServers.filter(s => s.split === 'dev').map(s => s.id), test: tsServers.filter(s => s.split === 'test').map(s => s.id) },
    python: { count: pyServers.length, dev: pyServers.filter(s => s.split === 'dev').map(s => s.id), test: pyServers.filter(s => s.split === 'test').map(s => s.id) }
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const get = (flag) => {
    const idx = args.indexOf(flag);
    const val = idx !== -1 ? args[idx + 1] : undefined;
    return val && !val.startsWith('--') ? val : undefined;
  };
  const out = await runSelect({
    fromSnapshot: args.includes('--from-snapshot'),
    ...(get('--seed') ? { seed: Number(get('--seed')) } : {}),
    ...(get('--ts-count') ? { tsCount: Number(get('--ts-count')) } : {}),
    ...(get('--py-count') ? { pyCount: Number(get('--py-count')) } : {}),
    ...(get('--max-pages') ? { maxPages: Number(get('--max-pages')) } : {})
  });
  console.log(JSON.stringify(out, null, 2));
}
