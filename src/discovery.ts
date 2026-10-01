import { VERSION } from './version.js';
import { fileURLToPath } from 'node:url';
import { ReadBuffer, Client, isJSONRPCRequest, serializeMessage, type JSONRPCMessage, type Transport } from '@modelcontextprotocol/client';
import type { Readable, Writable } from 'node:stream';
import { launchFixture, IsolationBlocked } from './isolation.js';

export class DiscoveryIncomplete extends Error {readonly code='DISCOVERY_INCOMPLETE';}
const PROTOCOL_VERSION = '2026-07-28';
const MAX_TOTAL_MS = 15_000;
const MAX_REQUEST_MS = 4_000;
const MAX_STREAM_BYTES = 1_048_576;
const MAX_MESSAGE_BYTES = 262_144;
const MAX_TOOLS = 500;
const MAX_PAGES = 32;

/** Named, project-owned fixture modes. The caller can never provide an executable or path. */
export type DiscoveryFixtureMode = 'reviewed' | 'timeout' | 'cursor-loop' | 'server-request' | 'protocol-mismatch' | 'large-response';

export interface DiscoveryOptions {
  /** Must be set by the CLI only after both required approval flags are present. */
  approved?: boolean;
  signal?: AbortSignal;
}

export interface DiscoveryDiagnostic {
  code: string;
  message: string;
}

export interface DiscoveryResult {
  inventory: {
    protocolVersion: string;
    acquisitionContext: { transport: 'stdio'; authorization: 'none'; source: string };
    serverInfo?: { name: string; version: string };
    tools: unknown[];
    metadata: { source: string; pageCount: number; sdk: string; isolation: string; toolCalls: number; resourceReads: number };
  };
  diagnostics: DiscoveryDiagnostic[];
}

interface FixtureProcess {
  stdin: Writable;
  stdout: Readable;
  stderr: Readable;
  exit: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
  terminate(): Promise<void>;
}

class FixtureTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;
  readonly #process: FixtureProcess;
  readonly #readBuffer = new ReadBuffer({ maxBufferSize: MAX_MESSAGE_BYTES });
  #started = false;
  #closed = false;
  #bytes = 0;
  #failure: Error | undefined;

  constructor(process: FixtureProcess) { this.#process = process; }
  get failure(): Error | undefined { return this.#failure; }

  async start(): Promise<void> {
    if (this.#started) throw new Error('Discovery transport already started.');
    this.#started = true;
    this.#process.stdout.on('data', chunk => {
      try {
        this.#countBytes(chunk);
        this.#readBuffer.append(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        for (;;) {
          const message = this.#readBuffer.readMessage();
          if (message === null) break;
          // Modern MCP has no server-to-client request channel. Refuse requests before
          // the SDK could try to route them to a handler or send any response.
          if (isJSONRPCRequest(message)) {
            this.#fail(new Error(`Discovery rejected an unsolicited server request (${message.method}).`));
            return;
          }
          this.onmessage?.(message);
        }
      } catch (error) { this.#fail(asError(error)); }
    });
    this.#process.stderr.on('data', chunk => {
      try { this.#countBytes(chunk); } catch (error) { this.#fail(asError(error)); }
    });
    this.#process.stdout.on('error', error => this.#fail(error));
    this.#process.stderr.on('error', error => this.#fail(error));
    this.#process.stdin.on('error', error => this.#fail(error));
    void this.#process.exit.then(({ code, signal }) => {
      if (!this.#closed && !this.#failure && (code !== 0 || signal !== null)) {
        this.#failure = new Error(`Discovery fixture exited unexpectedly (code ${String(code)}, signal ${String(signal)}).`);
        this.onerror?.(this.#failure);
      }
      this.#closed = true;
      this.onclose?.();
    }, error => this.#fail(asError(error)));
  }

  async send(message: JSONRPCMessage): Promise<void> {
    if (this.#closed) throw this.#failure ?? new Error('Discovery transport is closed.');
    const bytes = serializeMessage(message);
    await new Promise<void>((resolve, reject) => {
      try {
        if (this.#process.stdin.write(bytes)) resolve();
        else {
          this.#process.stdin.once('drain', resolve);
          this.#process.stdin.once('error', reject);
        }
      } catch (error) { reject(error); }
    });
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    this.#readBuffer.clear();
    await this.#process.terminate();
    this.onclose?.();
  }

  #countBytes(chunk: Uint8Array): void {
    this.#bytes += chunk.byteLength;
    if (this.#bytes > MAX_STREAM_BYTES) throw new Error(`Discovery exceeded the ${MAX_STREAM_BYTES} byte combined stdio limit.`);
  }

  #fail(error: Error): void {
    if (this.#failure || this.#closed) return;
    this.#failure = error;
    this.onerror?.(error);
    this.#closed = true;
    this.#readBuffer.clear();
    void this.#process.terminate().finally(() => this.onclose?.());
  }
}

function asError(error: unknown): Error { return error instanceof Error ? error : new Error(String(error)); }

const fixturePaths: Record<DiscoveryFixtureMode, string> = {
  reviewed: fileURLToPath(new URL('../fixtures/discovery/reviewed.mjs', import.meta.url)),
  timeout: fileURLToPath(new URL('../fixtures/discovery/timeout.mjs', import.meta.url)),
  'cursor-loop': fileURLToPath(new URL('../fixtures/discovery/cursor-loop.mjs', import.meta.url)),
  'server-request': fileURLToPath(new URL('../fixtures/discovery/server-request.mjs', import.meta.url)),
  'protocol-mismatch': fileURLToPath(new URL('../fixtures/discovery/protocol-mismatch.mjs', import.meta.url)),
  'large-response': fileURLToPath(new URL('../fixtures/discovery/large-response.mjs', import.meta.url)),
};

/**
 * Read-only discovery against one reviewed project-owned fixture. The fixture mode
 * is an allowlisted name, never a caller-supplied executable/configuration path.
 */
export async function discoverFixture(options: DiscoveryOptions = {}): Promise<DiscoveryResult> {
  if (options.approved !== true) throw new Error('Discovery is disabled. Pass --approve-execution and --fixture reviewed to approve the built-in fixture.');
  return runDiscovery('reviewed', options);
}

/** Closed fixture selector reserved for test suites; not wired into CLI or package commands. */
export async function discoverFixtureTestMode(mode: Exclude<DiscoveryFixtureMode, 'reviewed'>, signal?: AbortSignal): Promise<DiscoveryResult> {
  return runDiscovery(mode, { approved: true, signal });
}

async function runDiscovery(mode: DiscoveryFixtureMode, options: DiscoveryOptions): Promise<DiscoveryResult> {
  const controller = new AbortController();
  const abort = () => controller.abort(options.signal?.reason ?? new Error('Discovery was cancelled.'));
  if (options.signal?.aborted) abort();
  else options.signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(() => controller.abort(new Error(`Discovery exceeded ${MAX_TOTAL_MS} ms.`)), MAX_TOTAL_MS);

  let process: FixtureProcess | undefined;
  let transport: FixtureTransport | undefined;
  let client: Client | undefined;
  try {
    process = await launchFixture(fixturePaths[mode], { signal: controller.signal, maxBytes: MAX_STREAM_BYTES, timeoutMs: MAX_TOTAL_MS });
    transport = new FixtureTransport(process);
    client = new Client(
      { name: 'mcp-guard', version: VERSION },
      {
        versionNegotiation: { mode: { pin: PROTOCOL_VERSION } },
        inputRequired: { autoFulfill: false },
        enforceStrictCapabilities: true,
      },
    );
    await client.connect(transport, { signal: controller.signal, timeout: MAX_REQUEST_MS });
    if (client.getProtocolEra() !== 'modern' || client.getNegotiatedProtocolVersion() !== PROTOCOL_VERSION) {
      throw new Error(`Discovery requires protocol ${PROTOCOL_VERSION}; the fixture negotiated ${client.getNegotiatedProtocolVersion() ?? 'no protocol version'}.`);
    }

    const tools: unknown[] = [];
    const seenCursors = new Set<string>();
    // The SDK exposes a single-page list path when `cursor` is explicitly present.
    // Empty string is a valid opaque initial cursor and is treated as “first page”.
    let cursor: string | undefined = '';
    seenCursors.add('');
    let pageCount = 0;
    let serializedBytes = 0;
    do {
      if (++pageCount > MAX_PAGES) throw new Error(`Discovery exceeded the ${MAX_PAGES} tools/list page limit.`);
      const page = await client.listTools(cursor === undefined ? { cursor: '' } : { cursor }, { signal: controller.signal, timeout: MAX_REQUEST_MS });
      if (!Array.isArray(page.tools)) throw new Error('Discovery received an invalid tools/list page.');
      const pageJson = JSON.stringify(page.tools);
      serializedBytes += Buffer.byteLength(pageJson, 'utf8');
      if (serializedBytes > MAX_STREAM_BYTES) throw new Error(`Discovered tool descriptors exceed the ${MAX_STREAM_BYTES} byte limit.`);
      tools.push(...page.tools);
      if (tools.length > MAX_TOOLS) throw new Error(`Discovery exceeded the ${MAX_TOOLS} tool limit.`);
      if (page.nextCursor !== undefined) {
        if (typeof page.nextCursor !== 'string' || page.nextCursor.length === 0) throw new Error('Discovery received an invalid tools/list cursor.');
        if (seenCursors.has(page.nextCursor)) throw new Error('Discovery detected a repeated tools/list cursor.');
        seenCursors.add(page.nextCursor);
      }
      cursor = page.nextCursor;
    } while (cursor !== undefined);

    const serverInfo = client.getServerVersion();
    return {
      inventory: {
        protocolVersion: PROTOCOL_VERSION,
        acquisitionContext: { transport: 'stdio', authorization: 'none', source: 'reviewed built-in project fixture' },
        ...(serverInfo ? { serverInfo: { name: serverInfo.name, version: serverInfo.version } } : {}),
        tools,
        metadata: { source: 'reviewed built-in project fixture', pageCount,sdk:'@modelcontextprotocol/client@2.2.0 + @modelcontextprotocol/server@2.2.0',isolation:'macos-seatbelt-reviewed-fixture',toolCalls:0,resourceReads:0 },
      },
      diagnostics: [],
    };
  } catch(error){if(error instanceof IsolationBlocked)throw error;throw new DiscoveryIncomplete('Discovery incomplete: '+asError(transport?.failure??error).message);}
  finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', abort);
    if (client) {
      try { await client.close(); } catch { /* The process is terminated below regardless. */ }
    }
    if (process) {
      try { await process.terminate(); } catch { /* Preserve the discovery result/error. */ }
    }
  }
}
