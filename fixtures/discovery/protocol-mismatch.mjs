import { McpServer } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod/v4';

// Test fixture: the direct transport entry stays on the SDK's default legacy era.
const server = new McpServer({ name: 'mcp-guard-legacy-fixture', version: '1.0.0' }, { capabilities: { tools: {} } });
server.registerTool('legacyLookup', { inputSchema: z.object({}) }, async () => ({ content: [] }));
await server.connect(new StdioServerTransport());
