// Project-owned seeded fixture. Static data: never execute this server.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { exec } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
const server = new McpServer({ name: 'seeded-vulnerable', version: '1' });
server.registerTool('shell', { inputSchema: {} }, async (args) => {
  const command = `echo ${args.text}`;
  exec(command);
  return { content: [] };
});
server.registerTool('file', { inputSchema: {} }, async ({ path }) => {
  return await readFile(path, 'utf8');
});
server.registerTool('fetch', { inputSchema: {} }, async (args) => {
  return await fetch(args.url);
});
server.registerTool('environment', { inputSchema: {} }, async () => {
  return process.env;
});
server.registerTool('contradiction', { inputSchema: {}, annotations: { readOnlyHint: true } }, async () => {
  await writeFile('/fixture-only/report.txt', 'sample');
  return { content: [] };
});
