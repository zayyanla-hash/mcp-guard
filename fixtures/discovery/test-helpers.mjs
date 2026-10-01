import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';

const TEST_TOOL = {
  name: 'testLookup',
  description: 'A read-only fixture descriptor used by MCP Guard discovery tests.',
  inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] },
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
};

/**
 * A narrow adversarial transport decorator around the official SDK stdio transport.
 * It uses SDK message objects and framing; no arbitrary client or server method is run.
 */
export class DiscoveryTestTransport {
  #inner = new StdioServerTransport();
  #mode;
  #requestMethods = new Map();
  onclose;
  onerror;
  onmessage;

  constructor(mode) { this.#mode = mode; }

  async start() {
    this.#inner.onclose = () => this.onclose?.();
    this.#inner.onerror = error => this.onerror?.(error);
    this.#inner.onmessage = message => {
      if (this.#mode === 'server-request' && message.method === 'server/discover') {
        // Inject a valid but forbidden server-to-client sampling request through the SDK transport.
        void this.#inner.send({ jsonrpc: '2.0', id: 'fixture-request-1', method: 'sampling/createMessage', params: { messages: [], maxTokens: 1 } });
      }
      if (this.#mode === 'cursor-loop' && message.method === 'tools/list' && message.params?.cursor === 'repeat') {
        // Reply using the SDK serializer and a schema-valid page with the same next cursor.
        void this.#inner.send({ jsonrpc: '2.0', id: message.id, result: { resultType: 'complete', ttlMs: 0, cacheScope: 'private', tools: [TEST_TOOL], nextCursor: 'repeat' } });
        return;
      }
      if (message.method && message.id !== undefined) this.#requestMethods.set(String(message.id), message.method);
      this.onmessage?.(message);
    };
    await this.#inner.start();
  }

  async send(message) {
    if (this.#mode === 'cursor-loop' && message.id !== undefined && this.#requestMethods.get(String(message.id)) === 'tools/list' && message.result) {
      this.#requestMethods.delete(String(message.id));
      const page = { ...message, result: { ...message.result, nextCursor: 'repeat' } };
      return this.#inner.send(page);
    }
    return this.#inner.send(message);
  }

  close() { return this.#inner.close(); }
}
