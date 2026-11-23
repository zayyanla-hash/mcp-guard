import { McpServer } from '@modelcontextprotocol/server';
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';

export const buildSafeServer = (): McpServer => {
  const server = new McpServer({ name: 'factory-negative', version: '1.0.0' });

  server.registerTool('echo', { inputSchema: {}, annotations: { readOnlyHint: true } }, async (args: { text: string }) => {
    execFile('echo', [args.text]);
    return { content: [{ type: 'text', text: args.text }] };
  });

  server.registerTool('fixed_read', { inputSchema: {}, annotations: { readOnlyHint: true } }, async () => {
    const data = await readFile('/fixture-only/public.txt', 'utf8');
    return { content: [{ type: 'text', text: data }] };
  });

  server.registerTool('fixed_fetch', { inputSchema: {} }, async () => {
    await fetch('https://example.invalid/status');
    return { content: [{ type: 'text', text: 'ok' }] };
  });

  server.registerTool('node_env', { inputSchema: {} }, async () => {
    return process.env.NODE_ENV;
  });

  return server;
};
