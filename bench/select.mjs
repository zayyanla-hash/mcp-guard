import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const cacheDir = path.join(here, '.cache');
const REGISTRY_URL = 'https://registry.modelcontextprotocol.io/v0.1/servers';
const FIXED_SEED = 20261123;
const DEV_RATIO = 0.6;
const MAX_CANDIDATE_CHECKS = 250;
const execFileAsync = promisify(execFile);
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
  ['spawn_shell', /\bspawn(?:Sync)?\s*\([\s\S]{0,160}\bshell\s*:\s*(?:true\b|["'`])/],
  ['child_process', /\bchild_process\b/],
  ['readFile', /\breadFile(?:Sync)?\s*\(/],
  ['writeFile', /\bwriteFile(?:Sync)?\s*\(/],
  ['unlink', /\bunlink(?:Sync)?\s*\(/],
  ['fetch', /\bfetch\s*\(/],
  ['axios', /\baxios\b/],
  ['http.request', /\bhttp\.request\s*\(/],
  ['process.env', /\bprocess\.env\b/]
];

const STRONG_SINKS = {
  ts: new Set(['exec', 'execSync', 'child_process', 'spawn_shell', 'writeFile', 'unlink']),
  py: new Set(['subprocess', 'os.system'])
};
const MANUAL_SUBPATHS = {
  'mcparmory-registry-com-mcparmory-mailersend': {
    subpath: 'servers/mailersend',
    subpathNote: 'Manual: the registry entry gives no repository.subfolder, and mcparmory/registry is a monorepo of 76 servers. Scoped to the mailersend server it names.'
  },
  'estruyf-vscode-demo-time-io-github-estruyf-vscode-demo-time': {
    subpath: 'apps/mcp',
    subpathNote: 'Manual: the registry entry gives no repository.subfolder. apps/mcp declares the registry npm package @demotime/mcp.'
  },
  'vitalytolstik-janosik-io-github-vitalytolstik-janosik': {
    subpath: 'mcp',
    subpathNote: 'Manual: the registry entry gives no repository.subfolder. mcp declares the registry npm package @janosik/mcp.'
  }
};

export function hasStrongSink(sinks, lang) {
  return sinks.some(sink => STRONG_SINKS[lang].has(sink));
}

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

function detectRepoLicense(dest, commit, subpath) {
  const prefixes = subpath ? [`${subpath}/`, ''] : [''];
  const readBlob = file => {
    try {
      return execFileSync('git', ['-C', dest, 'show', `${commit}:${file}`], {
        encoding: 'utf8', timeout: 6000, maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe']
      });
    } catch { return null; }
  };
  for (const prefix of prefixes) {
    for (const f of ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'LICENSE-MIT', 'LICENSE-APACHE', 'COPYING']) {
      const license = classifyLicenseText(readBlob(prefix + f) ?? '');
      if (license) return license;
    }
    try {
      const pkg = JSON.parse(readBlob(prefix + 'package.json') ?? '{}');
      const spdx = normalizeSpdx(typeof pkg.license === 'string' ? pkg.license : pkg.license?.type);
      if (spdx) return spdx;
    } catch { /* malformed metadata is not license evidence */ }
    const toml = readBlob(prefix + 'pyproject.toml') ?? '';
    const m = toml.match(/license\s*=\s*(?:"([^"]+)"|'([^']+)'|\{\s*text\s*=\s*"([^"]+)")/i);
    const spdx = normalizeSpdx(m?.[1] ?? m?.[2] ?? m?.[3]);
    if (spdx) return spdx;
  }
  return null;
}

async function resolveRemoteHead(repoUrl) {
  try {
    const { stdout } = await execFileAsync('git', ['ls-remote', '--exit-code', repoUrl, 'HEAD'], {
      encoding: 'utf8', timeout: 12000,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0' }
    });
    const sha = stdout.trim().split(/\s+/)[0];
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
      const st = lstatSync(full);
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) walk(full);
      else if (extPattern.test(entry) && !entry.endsWith('.d.ts') && !entry.endsWith('.min.js')) out.push(full);
    }
  };
  walk(dir);
  return out;
}

function preparePinnedRepo(candidate) {
  const dest = path.join(cacheDir, candidate.id);
  try {
    if (!existsSync(path.join(dest, '.git'))) {
      execFileSync('git', ['clone', '--no-checkout', '--depth', '1', candidate.url, dest], { stdio: 'pipe', timeout: 45000 });
    }
    try {
      execFileSync('git', ['-C', dest, 'cat-file', '-e', `${candidate.commit}^{commit}`], { stdio: 'pipe', timeout: 12000 });
    } catch {
      execFileSync('git', ['-C', dest, 'fetch', '--depth', '1', 'origin', candidate.commit], { stdio: 'pipe', timeout: 45000 });
    }
    return dest;
  } catch {
    return null;
  }
}

function scanRepoSinksPlainText(dest, candidate, lang) {
  try {
    execFileSync('git', ['-C', dest, '-c', 'core.hooksPath=/dev/null', 'checkout', '--detach', candidate.commit], { stdio: 'pipe', timeout: 30000 });
  } catch {
    return [];
  }
  const scanRoot = candidate.subpath ? path.join(dest, candidate.subpath) : dest;
  try {
    // Do not follow an explicit worktree subpath through a symlink.
    let parent = dest;
    for (const component of (candidate.subpath ?? '').split('/').filter(Boolean)) {
      parent = path.join(parent, component);
      if (!lstatSync(parent).isDirectory()) return [];
    }
  } catch { return []; }
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

async function selectLanguageStrata(candidates, lang, stratum1Target, stratum2Target, seed, pinnedStratum1) {
  const ranked = [...candidates]
    .map(c => ({ ...c, rank: seedRank(seed, `${lang}:${c.server.name}:${c.repo.canonicalUrl}`) }))
    .sort((a, b) => a.rank.localeCompare(b.rank));
  const random = pinnedStratum1 ? [...pinnedStratum1] : [];
  const seenRepos = new Set(random.map(s => s.url.toLowerCase()));
  const seenIds = new Set(random.map(s => s.id));
  const enriched = [];
  let startIndex = 0;
  if (pinnedStratum1) {
    const last = random.at(-1);
    const rankPrefix = last?.selectionReason.match(/rank ([a-f0-9]{12}),/)?.[1];
    const matching = ranked.flatMap((item, index) =>
      item.repo.canonicalUrl === last?.url &&
      makeServerId(item.server.name, item.repo.owner, item.repo.repo) === last?.id &&
      rankPrefix && item.rank.startsWith(rankPrefix) ? [index] : []);
    if (matching.length !== 1 || random.length !== stratum1Target) {
      throw new Error(`Cannot unambiguously resume after frozen ${lang} random-registry stratum.`);
    }
    startIndex = matching[0] + 1;
  }

  let verified = 0;
  let checked = 0;
  for (let index = startIndex; index < ranked.length && enriched.length < stratum2Target; index++) {
    const item = ranked[index];
    const url = item.repo.canonicalUrl;
    const id = makeServerId(item.server.name, item.repo.owner, item.repo.repo);
    if (seenRepos.has(url.toLowerCase()) || seenIds.has(id)) continue;

    const explicit = typeof item.server.repository?.subfolder === 'string'
      ? item.server.repository.subfolder.trim().replace(/^\/+|\/+$/g, '') : '';
    if (explicit.split('/').includes('..')) continue;
    const scope = MANUAL_SUBPATHS[id] ?? (explicit ? { subpath: explicit } : {});
    checked++;
    if (checked > MAX_CANDIDATE_CHECKS) {
      throw new Error(`Stopped after ${MAX_CANDIDATE_CHECKS} lazy ${lang} checks without filling the quota.`);
    }
    const sha = await resolveRemoteHead(url);
    if (!sha) continue;
    const dest = preparePinnedRepo({ id, url, commit: sha, ...scope });
    if (!dest) continue;
    const license = detectRepoLicense(dest, sha, scope.subpath);
    if (!license) continue;
    verified++;
    seenRepos.add(url.toLowerCase());
    seenIds.add(id);
    const candidate = {
      id, url, commit: sha, ...scope, license,
      selectionReason: `MCP Registry (${lang}) seeded sample (rank ${item.rank.slice(0, 12)}, verified ${license} license)`
    };
    if (random.length < stratum1Target) {
      random.push(candidate);
      continue;
    }
    const sinks = scanRepoSinksPlainText(dest, candidate, lang);
    if (!hasStrongSink(sinks, lang)) continue;
    enriched.push({
      ...candidate,
      matchedSinks: sinks,
      selectionReason: `${candidate.selectionReason}; plain-text sinks: ${sinks.join(', ')}`
    });
    console.error(`${lang} sink-enriched ${enriched.length}/${stratum2Target}: ${id}`);
  }

  if (random.length !== stratum1Target || enriched.length !== stratum2Target) {
    throw new Error(`Incomplete ${lang} sample: ${random.length}/${stratum1Target} random and ${enriched.length}/${stratum2Target} sink-enriched.`);
  }
  const stratum1 = pinnedStratum1 ? random : assignStratumSplits(random, 'random-registry');
  const stratum2 = assignStratumSplits(enriched, 'sink-enriched');
  return {
    totalCandidates: candidates.length,
    checkedAfterStart: checked,
    verifiedAfterStart: verified,
    stratum1Count: stratum1.length,
    stratum2Count: stratum2.length,
    servers: [...stratum1, ...stratum2]
  };
}

export async function runSelect({
  snapshotPath = path.join(here, 'registry-snapshot.json'),
  fromSnapshot = false,
  refreshSinkEnriched = false,
  seed = FIXED_SEED
} = {}) {
  mkdirSync(cacheDir, { recursive: true });
  if (refreshSinkEnriched && !fromSnapshot) {
    throw new Error('--refresh-sink-enriched requires the original snapshot via --from-snapshot.');
  }
  const snapshot = fromSnapshot
    ? JSON.parse(readFileSync(snapshotPath, 'utf8'))
    : await fetchRegistrySnapshot();

  if (!fromSnapshot) {
    writeFileSync(snapshotPath, JSON.stringify(snapshot, null, 2) + '\n', 'utf8');
  }
  // The snapshot is large and is not committed (see .gitignore); manifests record its hash instead.
  const snapshotBytes = readFileSync(snapshotPath);
  const snapshotRecord = {
    snapshotFile: 'bench/registry-snapshot.json',
    snapshotCommitted: false,
    snapshotSha256: createHash('sha256').update(snapshotBytes).digest('hex'),
    snapshotBytes: snapshotBytes.length,
    snapshotFetchedAt: snapshot.fetchedAt
  };

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

  const pinned = filename => {
    if (!refreshSinkEnriched) return undefined;
    const m = JSON.parse(readFileSync(path.join(here, filename), 'utf8'));
    if (m.seed !== seed || m.snapshotSha256 !== snapshotRecord.snapshotSha256 ||
        m.snapshotBytes !== snapshotRecord.snapshotBytes || m.snapshotFetchedAt !== snapshotRecord.snapshotFetchedAt) {
      throw new Error(`Snapshot or seed does not match ${filename}; refusing to modify frozen manifests.`);
    }
    return m.servers.filter(s => s.stratum === 'random-registry');
  };
  const tsPinned = pinned('manifest.json');
  const pyPinned = pinned('python-manifest.json');
  const [tsResult, pyResult] = await Promise.all([
    selectLanguageStrata(tsCandidates, 'ts', 40, 15, seed, tsPinned),
    selectLanguageStrata(pyCandidates, 'py', 20, 10, seed, pyPinned)
  ]);

  const samplingRule = `Full MCP Registry snapshot (latest active entries, public GitHub, verified OSI-approved license, excluding Vambrace fixtures and typescript-sdk). Stratum 1 (random-registry): first 40 TS / 20 Python sorted by sha256("${seed}:<lang>:<registryName>:<repoUrl>"). Stratum 2 (sink-enriched): continue after Stratum 1 in seeded order and stop at 15 TS / 10 Python whose source matches at least one strong token via plain-text search (TS: exec, execSync, child_process, spawn with shell, writeFile, unlink; Python: subprocess, os.system). Weaker matches may be recorded but do not qualify a server. Both strata split 60/40 by server.`;

  const tsManifest = {
    schemaVersion: 1,
    seed,
    splitBy: 'server',
    splitRatio: { dev: DEV_RATIO, test: Number((1 - DEV_RATIO).toFixed(2)) },
    samplingRule,
    ...snapshotRecord,
    note: 'Real-world TypeScript/JavaScript MCP servers sampled across random-registry and sink-enriched strata. Test-split labels remain outside this repository.',
    servers: tsResult.servers
  };

  const pyManifest = {
    schemaVersion: 1,
    seed,
    splitBy: 'server',
    splitRatio: { dev: DEV_RATIO, test: Number((1 - DEV_RATIO).toFixed(2)) },
    samplingRule,
    ...snapshotRecord,
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
      checkedAfterStart: tsResult.checkedAfterStart,
      verifiedAfterStart: tsResult.verifiedAfterStart,
      randomRegistry: tsResult.stratum1Count,
      sinkEnriched: tsResult.stratum2Count,
      dev: tsResult.servers.filter(s => s.split === 'dev').length,
      test: tsResult.servers.filter(s => s.split === 'test').length
    },
    python: {
      candidates: pyResult.totalCandidates,
      checkedAfterStart: pyResult.checkedAfterStart,
      verifiedAfterStart: pyResult.verifiedAfterStart,
      randomRegistry: pyResult.stratum1Count,
      sinkEnriched: pyResult.stratum2Count,
      dev: pyResult.servers.filter(s => s.split === 'dev').length,
      test: pyResult.servers.filter(s => s.split === 'test').length
    }
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const out = await runSelect({ fromSnapshot: args.includes('--from-snapshot'), refreshSinkEnriched: args.includes('--refresh-sink-enriched') });
  console.log(JSON.stringify(out, null, 2));
}
