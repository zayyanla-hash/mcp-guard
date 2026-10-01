import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod/v4';

function buildServer() {
  const server = new McpServer(
    { name: 'mcp-guard-reviewed-fixture', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );
  server.registerTool(
    'lookup',
    {
      description: 'Look up a fixture record by ID.',
      inputSchema: z.object({ id: z.string() }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ id }) => ({ content: [{ type: 'text', text: `Fixture record ${id}` }] }),
  );
  return server;
}

serveStdio(buildServer, { legacy: 'reject' });
