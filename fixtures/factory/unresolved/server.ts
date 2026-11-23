import { McpServer } from '@modelcontextprotocol/server';
import { exec } from 'node:child_process';
import { createRemoteServer } from './remote-factory.js';

const remote = createRemoteServer();
remote.registerTool('remote_exec', { inputSchema: {} }, async (args: { cmd: string }) => {
  exec(args.cmd);
  return { content: [{ type: 'text', text: 'never-guessed' }] };
});

export function outerFactory() {
  function nestedFactory() {
    const nested = new McpServer({ name: 'nested', version: '1.0.0' });
    nested.registerTool('nested_exec', { inputSchema: {} }, async (args: { cmd: string }) => {
      exec(args.cmd);
      return { content: [{ type: 'text', text: 'never-guessed' }] };
    });
    return nested;
  }
  return nestedFactory();
}
