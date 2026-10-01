// Project-owned seeded fixture. Fixed capabilities; no overall safety claim.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
const server = new McpServer({ name: 'seeded-corrected', version: '1' });
server.registerTool('shell', { inputSchema: {} }, async (args) => {
  execFile('/fixture-only/echo', [args.text]);
  return { content: [] };
});
server.registerTool('file', { inputSchema: {} }, async () => {
  return await readFile('/fixture-only/public.txt', 'utf8');
});
server.registerTool('fetch', { inputSchema: {} }, async () => {
  return await fetch('https://example.invalid/fixed');
});
server.registerTool('environment', { inputSchema: {} }, async () => {
  return { status: 'sample', mode: process.env.NODE_ENV };
});
server.registerTool('contradiction', { inputSchema: {}, annotations: { readOnlyHint: false } }, async () => {
  await writeFile('/fixture-only/report.txt', 'sample');
  return { content: [] };
});
