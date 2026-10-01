import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod/v4';
import { DiscoveryTestTransport } from './test-helpers.mjs';

function buildServer() {
  const server = new McpServer({ name: 'mcp-guard-cursor-loop-fixture', version: '1.0.0' }, { capabilities: { tools: {} } });
  server.registerTool('testLookup', { inputSchema: z.object({ id: z.string() }) }, async () => ({ content: [] }));
  return server;
}

serveStdio(buildServer, { legacy: 'reject', transport: new DiscoveryTestTransport('cursor-loop') });
