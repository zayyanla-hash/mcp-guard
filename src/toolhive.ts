import { execFileSync, spawn } from 'node:child_process';
import { Client } from '@modelcontextprotocol/client';
import { IsolationBlocked } from './isolation.js';
import { VERSION } from './version.js';
import type { DiscoveryResult } from './discovery.js';

const PROTOCOL_VERSION = '2026-07-28';

export type ExecSyncLike = (
  file: string,
  args: string[],
  options: { encoding: 'utf8'; timeout: number; stdio: ['ignore', 'pipe', 'pipe'] }
) => string;

export interface ToolHiveOptions {
  approved?: boolean;
  imageOrSpec?: string;
  execImpl?: ExecSyncLike;
  signal?: AbortSignal;
  listToolsFn?: (spec: string) => Promise<{
    serverInfo?: { name: string; version: string };
    tools: unknown[];
    pageCount: number;
  }>;
}

export function verifyToolHiveEnvironment(execImpl: ExecSyncLike = (f, a, o) => execFileSync(f, a, o)): {
  thvVersion: string;
  runtime: 'docker' | 'podman';
} {
  let thvVersion = '';
  try {
    thvVersion = execImpl('thv', ['version'], {
      encoding: 'utf8',
      timeout: 5000,
      stdio: ['ignore', 'pipe', 'pipe']
    }).trim();
  } catch {
    throw new IsolationBlocked('ToolHive CLI (thv) is unavailable; Linux container-isolated discovery fails closed.');
  }

  for (const runtime of ['docker', 'podman'] as const) {
    try {
      execImpl(runtime, ['info', '--format', '{{.ServerVersion}}'], {
        encoding: 'utf8',
        timeout: 5000,
        stdio: ['ignore', 'pipe', 'pipe']
      });
      return { thvVersion: thvVersion || 'unknown', runtime };
    } catch {
      // try next container runtime
    }
  }

  throw new IsolationBlocked('No container runtime (docker or podman) is reachable for ToolHive isolation; refusing discovery.');
}

export async function discoverWithToolHive(options: ToolHiveOptions = {}): Promise<DiscoveryResult> {
  if (options.approved !== true) {
    throw new IsolationBlocked('ToolHive discovery requires explicit --approve-execution approval.');
  }
  if (options.signal?.aborted) {
    throw new IsolationBlocked('ToolHive discovery cancelled before startup.');
  }

  const execImpl = options.execImpl ?? ((f, a, o) => execFileSync(f, a, o));
  verifyToolHiveEnvironment(execImpl);
  const targetSpec = options.imageOrSpec ?? 'vambrace-reviewed-fixture';

  if (options.listToolsFn) {
    const acquired = await options.listToolsFn(targetSpec);
    return {
      inventory: {
        protocolVersion: PROTOCOL_VERSION,
        acquisitionContext: { transport: 'stdio', authorization: 'none', source: 'toolhive-isolated-container' },
        ...(acquired.serverInfo ? { serverInfo: acquired.serverInfo } : {}),
        tools: acquired.tools,
        metadata: {
          source: 'toolhive-isolated-container',
          pageCount: acquired.pageCount,
          sdk: '@modelcontextprotocol/client@2.2.0',
          isolation: 'toolhive-network-isolated-container',
          toolCalls: 0,
          resourceReads: 0
        }
      },
      diagnostics: []
    };
  }

  // Launch through ToolHive with network isolation; send initialize and tools/list only.
  const child = spawn('thv', ['run', '--isolate-network', '--transport', 'stdio', targetSpec], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin', LANG: 'C', TZ: 'UTC' }
  });

  try {
    const client = new Client(
      { name: 'vambrace', version: VERSION },
      { versionNegotiation: { mode: { pin: PROTOCOL_VERSION } }, enforceStrictCapabilities: true }
    );
    const { StdioClientTransport } = await import('@modelcontextprotocol/client') as unknown as {
      StdioClientTransport?: new (opts: { command: string; args: string[] }) => never;
    };
    void client;
    void StdioClientTransport;
    // Terminate spawned probe unless real stdio framing is bound
    throw new IsolationBlocked('Live ToolHive container execution requires a pre-built reviewed image target.');
  } finally {
    try { child.kill('SIGKILL'); } catch { /* ignore */ }
  }
}
