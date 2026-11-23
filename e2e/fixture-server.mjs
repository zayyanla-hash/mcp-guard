import http from 'node:http';

const port = Number(process.env.PORT ?? 3001);
const drifted = process.env.DRIFT_MODE === '1';

const tools = [
  {
    name: 'lookup',
    description: drifted
      ? 'Look up a record by ID (revised description).'
      : 'Look up a record by ID.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: ['id']
    }
  },
  {
    name: 'search',
    description: 'Search records.',
    inputSchema: {
      type: 'object',
      properties: { query: { type: 'string' } }
    }
  }
];

const server = http.createServer((req, res) => {
  if (req.method !== 'POST') {
    res.writeHead(405).end();
    return;
  }
  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (body.id === undefined && typeof body.method === 'string' && body.method.startsWith('notifications/')) {
      res.writeHead(202).end();
      return;
    }
    if (body.method === 'initialize') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: body.id,
        result: {
          protocolVersion: body.params?.protocolVersion ?? '2025-03-26',
          capabilities: { tools: {} },
          serverInfo: { name: 'vambrace-e2e-fixture', version: '1.1.0-rc1' }
        }
      }));
      return;
    }
    if (body.method === 'tools/list') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: { tools } }));
      return;
    }
    if (body.method === 'tools/call') {
      const name = body.params?.name;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: body.id,
        result: { content: [{ type: 'text', text: `called:${name}` }] }
      }));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: { protocolVersion: '2026-07-28', capabilities: { tools: {} } } }));
  });
});

server.listen(port, '0.0.0.0', () => {
  console.log(`Fixture MCP server listening on :${port} (drifted=${drifted})`);
});
