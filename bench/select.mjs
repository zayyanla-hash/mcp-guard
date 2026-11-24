import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const cacheDir = path.join(here, '.cache');
const REGISTRY_URL = 'https://registry.modelcontextprotocol.io/v0.1/servers';
const FIXED_SEED = 20261123;
const DEV_RATIO = 0.6;
const EXCLUDED_REPO_PATTERN = /(?:zayyanla-hash\/vambrace|zayyanla-hash\/mcp-guard|modelcontextprotocol\/typescript-sdk)/i;

const OSI_SPDX_LICENSES = new Set([
  'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MPL-2.0',
  'GPL-2.0', 'GPL-2.0-only', 'GPL-2.0-or-later',
  'GPL-3.0', 'GPL-3.0-only', 'GPL-3.0-or-later',
  'LGPL-2.1', 'LGPL-2.1-only', 'LGPL-2.1-or-later',
  'LGPL-3.0', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
  'AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later',
  'EPL-2.0', 'Unlicense', '0BSD', 'BSL-1.0', 'Zlib', 'Artistic-2.0', 'CC0-1.0'
]);

const TS_SINK_PATTERNS = [
  ['exec', /\bexec\s*\(/],
  ['execSync', /\bexecSync\s*\(/],
  ['spawn_shell', /\bspawn(?:Sync)?\s*\([\s\S]{0,160}\bshell\s*:/],
  ['child_process', /\bchild_process\b/],
  ['readFile', /\breadFile(?:Sync)?\s*\(/],
  ['writeFile', /\bwriteFile(?:Sync)?\s*\(/],
  ['unlink', /\bunlink(?:Sync)?\s*\(/],
  ['fetch', /\bfetch\s*\(/],
  ['axios', /\baxios\b/],
  ['http.request', /\bhttp\.request\s*\(/],
  ['process.env', /\bprocess\.env\b/]
];

const PY_SINK_PATTERNS = [
  ['subprocess', /\bsubprocess\b/],
  ['os.system', /\bos\.system\s*\(/],
  ['open', /\bopen\s*\(/],
  ['requests', /\brequests\b/],
  ['httpx', /\bhttpx\b/],
  ['os.environ', /\bos\.environ\b/]
];

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
  if (/GNU GENERAL PUBLIC LICENSE\s+Version 3/i.test(text)) return 'GPL-3.0';
  if (/GNU GENERAL PUBLIC LICENSE\s+Version 2/i.test(text)) return 'GPL-2.0';
  if (/GNU LESSER GENERAL PUBLIC LICENSE\s+Version 3/i.test(text)) return 'LGPL-3.0';
  if (/GNU LESSER GENERAL PUBLIC LICENSE\s+Version 2\.1/i.test(text)) return 'LGPL-2.1';
  if (/GNU AFFERO GENERAL PUBLIC LICENSE\s+Version 3/i.test(text)) return 'AGPL-3.0';
  if (/Mozilla Public License Version 2\.0/i.test(text)) return 'MPL-2.0';
  if (/ISC License/i.test(text) || /Permission to use, copy, modify, and\/or distribute this software for any purpose with or without fee/i.test(text)) {
    return 'ISC';
  }
  if (/Redistribution and use in source and binary forms/i.test(text)) {
    return /Neither the name of/i.test(text) ? 'BSD-3-Clause' : 'BSD-2-Clause';
  }
  if (/This is free and unencumbered software released into the public domain/i.test(text)) return 'Unlicense';
  if (/Eclipse Public License - v 2\.0/i.test(text)) return 'EPL-2.0';
  if (/Boost Software License - Version 1\.0/i.test(text)) return 'BSL-1.0';
  return null;
}

function normalizeSpdx(raw) {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (OSI_SPDX_LICENSES.has(trimmed)) return trimmed;
  return null;
}

async function detectRepoLicense(owner, repo, commit, subpath) {
  const prefixes = subpath ? [`${subpath}/`, ''] : [''];
  for (const prefix of prefixes) {
    for (const f of ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'LICENSE-MIT', 'LICENSE-APACHE', 'COPYING']) {
      try {
        const res = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${commit}/${prefix}${f}`, {
          signal: AbortSignal.timeout(6000)
        });
        if (!res.ok) continue;
        const lic = classifyLicenseText(await res.text());
        if (lic) return lic;
      } catch { /* try next */ }
    }
    try {
      const pkgRes = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${commit}/${prefix}package.json`, {
        signal: AbortSignal.timeout(6000)
      });
      if (pkgRes.ok) {
        const pkg = JSON.parse(await pkgRes.text());
        const spdx = normalizeSpdx(typeof pkg.license === 'string' ? pkg.license : pkg.license?.type);
        if (spdx) return spdx;
      }
    } catch { /* ignore */ }
    try {
      const pyRes = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${commit}/${prefix}pyproject.toml`, {
        signal: AbortSignal.timeout(6000)
      });
      if (pyRes.ok) {
        const toml = await pyRes.text();
        const m = toml.match(/license\s*=\s*(?:"([^"]+)"|'([^']+)'|\{\s*text\s*=\s*"([^"]+)")/i);
        const spdx = normalizeSpdx(m?.[1] ?? m?.[2] ?? m?.[3]);
        if (spdx) return spdx;
      }
    } catch { /* ignore */ }
  }
  return null;
}

function resolveRemoteHead(repoUrl) {
  try {
    const out = execFileSync('git', ['ls-remote', '--exit-code', repoUrl, 'HEAD'], {
      encoding: 'utf8',
      timeout: 12000,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    const sha = out.trim().split(/\s+/)[0];
    return /^[0-9a-f]{40}$/i.test(sha) ? sha.toLowerCase() : null;
  } catch {
    return null;
  }
}

async function fetchRegistrySnapshot() {
  const seen = new Map();
  let cursor = null;
  let pages = 0;
  while (true) {
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

function collectPlainTextFiles(dir, extPattern) {
  const out = [];
  if (!existsSync(dir)) return out;
  const walk = (d) => {
    for (const entry of readdirSync(d)) {
      if (['node_modules', '.git', 'dist', 'build', 'coverage', '__pycache__', '.venv', 'venv'].includes(entry)) continue;
      const full = path.join(d, entry);
      const st = statSync(full);
      if (st.isDirectory()) walk(full);
      else if (extPattern.test(entry) && !entry.endsWith('.d.ts') && !entry.endsWith('.min.js')) out.push(full);
    }
  };
  walk(dir);
  return out;
}

function scanRepoSinksPlainText(candidate, lang) {
  const dest = path.join(cacheDir, candidate.id);
  try {
    if (!existsSync(path.join(dest, '.git'))) {
      execFileSync('git', ['clone', '--no-checkout', '--depth', '1', candidate.url, dest], { stdio: 'pipe', timeout: 45000 });
    }
    execFileSync('git', ['-C', dest, 'fetch', '--depth', '1', 'origin', candidate.commit], { stdio: 'pipe', timeout: 45000 });
    execFileSync('git', ['-C', dest, 'checkout', '--detach', candidate.commit], { stdio: 'pipe', timeout: 30000 });
  } catch {
    return [];
  }
  const scanRoot = candidate.subpath ? path.join(dest, candidate.subpath) : dest;
  const ext = lang === 'py' ? /\.py$/i : /\.(ts|mts|js|mjs)$/i;
  const patterns = lang === 'py' ? PY_SINK_PATTERNS : TS_SINK_PATTERNS;
  const matched = new Set();
  for (const f of collectPlainTextFiles(scanRoot, ext)) {
    let text;
    try {
      text = readFileSync(f, 'utf8');
    } catch { continue; }
    for (const [label, re] of patterns) {
      if (re.test(text)) matched.add(label);
    }
  }
  return [...matched];
}

function assignStratumSplits(items, stratum) {
  const devCount = items.length <= 1 ? items.length : Math.max(1, Math.round(items.length * DEV_RATIO));
  return items.map((item, idx) => ({
    ...item,
    stratum,
    split: idx < devCount ? 'dev' : 'test'
  }));
}

async function selectLanguageStrata(candidates, lang, stratum1Target, stratum2Target, seed) {
  const ranked = [...candidates]
    .map(c => ({ ...c, rank: seedRank(seed, `${lang}:${c.server.name}:${c.repo.canonicalUrl}`) }))
    .sort((a, b) => a.rank.localeCompare(b.rank));

  const seenRepos = new Set();
  const seenIds = new Set();
  const qualifying = [];

  for (const item of ranked) {
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
    qualifying.push({
      id,
      url: item.repo.canonicalUrl,
      commit: sha,
      ...(subpath ? { subpath } : {}),
      license,
      selectionReason: `MCP Registry (${lang}) seeded sample (rank ${item.rank.slice(0, 12)}, verified ${license} license)`
    });
  }

  const stratum1 = assignStratumSplits(qualifying.slice(0, stratum1Target), 'random-registry');
  const remaining = qualifying.slice(stratum1Target);
  const stratum2Raw = [];
  for (const cand of remaining) {
    if (stratum2Raw.length >= stratum2Target) break;
    const sinks = scanRepoSinksPlainText(cand, lang);
    if (sinks.length > 0) {
      stratum2Raw.push({
        ...cand,
        matchedSinks: sinks,
        selectionReason: `${cand.selectionReason}; plain-text sinks: ${sinks.join(', ')}`
      });
    }
  }
  const stratum2 = assignStratumSplits(stratum2Raw, 'sink-enriched');

  return {
    totalCandidates: candidates.length,
    totalQualifying: qualifying.length,
    stratum1Count: stratum1.length,
    stratum2Count: stratum2.length,
    servers: [...stratum1, ...stratum2]
  };
}

export async function runSelect({
  snapshotPath = path.join(here, 'registry-snapshot.json'),
  fromSnapshot = false,
  seed = FIXED_SEED
} = {}) {
  mkdirSync(cacheDir, { recursive: true });
  const snapshot = fromSnapshot && existsSync(snapshotPath)
    ? JSON.parse(readFileSync(snapshotPath, 'utf8'))
    : await fetchRegistrySnapshot();

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

  const tsResult = await selectLanguageStrata(tsCandidates, 'ts', 40, 15, seed);
  const pyResult = await selectLanguageStrata(pyCandidates, 'py', 20, 10, seed);

  const samplingRule = `Full MCP Registry snapshot (latest active entries, public GitHub, verified OSI-approved license, excluding Vambrace fixtures and typescript-sdk). Stratum 1 (random-registry): first 40 TS / 20 Python sorted by sha256("${seed}:<lang>:<registryName>:<repoUrl>"). Stratum 2 (sink-enriched): among remaining qualifying servers in seeded order, up to 15 TS / 10 Python containing >=1 fixed sink token via plain-text search. Both strata split 60/40 by server.`;

  const tsManifest = {
    schemaVersion: 1,
    seed,
    splitBy: 'server',
    splitRatio: { dev: DEV_RATIO, test: Number((1 - DEV_RATIO).toFixed(2)) },
    samplingRule,
    snapshotFile: 'bench/registry-snapshot.json',
    snapshotFetchedAt: snapshot.fetchedAt,
    note: 'Real-world TypeScript/JavaScript MCP servers sampled across random-registry and sink-enriched strata. Test-split labels remain outside this repository.',
    servers: tsResult.servers
  };

  const pyManifest = {
    schemaVersion: 1,
    seed,
    splitBy: 'server',
    splitRatio: { dev: DEV_RATIO, test: Number((1 - DEV_RATIO).toFixed(2)) },
    samplingRule,
    snapshotFile: 'bench/registry-snapshot.json',
    snapshotFetchedAt: snapshot.fetchedAt,
    note: 'Real-world Python MCP servers sampled across random-registry and sink-enriched strata. Test-split labels remain outside this repository.',
    servers: pyResult.servers
  };

  writeFileSync(path.join(here, 'manifest.json'), JSON.stringify(tsManifest, null, 2) + '\n', 'utf8');
  writeFileSync(path.join(here, 'python-manifest.json'), JSON.stringify(pyManifest, null, 2) + '\n', 'utf8');

  return {
    snapshotPath,
    pagesFetched: snapshot.pagesFetched,
    snapshotTotalServers: snapshot.totalLatestServers,
    typescript: {
      candidates: tsResult.totalCandidates,
      qualifying: tsResult.totalQualifying,
      randomRegistry: tsResult.stratum1Count,
      sinkEnriched: tsResult.stratum2Count,
      dev: tsResult.servers.filter(s => s.split === 'dev').length,
      test: tsResult.servers.filter(s => s.split === 'test').length
    },
    python: {
      candidates: pyResult.totalCandidates,
      qualifying: pyResult.totalQualifying,
      randomRegistry: pyResult.stratum1Count,
      sinkEnriched: pyResult.stratum2Count,
      dev: pyResult.servers.filter(s => s.split === 'dev').length,
      test: pyResult.servers.filter(s => s.split === 'test').length
    }
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const out = await runSelect({ fromSnapshot: args.includes('--from-snapshot') });
  console.log(JSON.stringify(out, null, 2));
}
