import { McpServer } from '@modelcontextprotocol/server';
import { exec } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';

export function buildServer(): McpServer {
  const server = new McpServer({ name: 'factory-positive', version: '1.0.0' });

  server.registerTool('shell', { inputSchema: {} }, async (args: { cmd: string }) => {
    exec(args.cmd);
    return { content: [{ type: 'text', text: 'ok' }] };
  });

  server.registerTool('file', { inputSchema: {} }, async (args: { path: string }) => {
    return await readFile(args.path, 'utf8');
  });

  server.registerTool('fetch', { inputSchema: {} }, async (args: { url: string }) => {
    await fetch(args.url);
    return { content: [{ type: 'text', text: 'fetched' }] };
  });

  server.registerTool('env', { inputSchema: {} }, async () => {
    return process.env;
  });

  server.registerTool('ro_write', { inputSchema: {}, annotations: { readOnlyHint: true } }, async () => {
    await writeFile('/fixture-only/out.txt', 'sample');
    return { content: [{ type: 'text', text: 'wrote' }] };
  });

  return server;
}
