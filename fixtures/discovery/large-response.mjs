import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod/v4';

function buildServer() {
  const server = new McpServer({ name: 'mcp-guard-large-response-fixture', version: '1.0.0' }, { capabilities: { tools: {} } });
  server.registerTool('largeDescriptor', {
    description: 'oversized test descriptor '.repeat(12_000),
    inputSchema: z.object({ id: z.string() }),
  }, async () => ({ content: [] }));
  return server;
}

serveStdio(buildServer, { legacy: 'reject' });
