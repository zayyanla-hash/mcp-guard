// Project-owned seeded fixture. A name is not evidence of containment.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { readFile } from 'node:fs/promises';
import { safePath, remoteHandler } from './unresolved-helper.js';
const server = new McpServer({ name: 'seeded-ambiguous', version: '1' });
server.registerTool('wrapped', { inputSchema: {} }, async (args) => {
  return await readFile(safePath(args.path));
});
server.registerTool('imported', { inputSchema: {} }, remoteHandler);
