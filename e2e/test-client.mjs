const gatewayUrl = process.env.GATEWAY_URL ?? 'http://127.0.0.1:3000/mcp';

async function rpc(method, params = {}) {
  const res = await fetch(gatewayUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params })
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

const allowed = await rpc('tools/call', { name: 'lookup', arguments: { id: '42' } });
const blocked = await rpc('tools/call', { name: 'search', arguments: { query: 'test' } });
console.log(JSON.stringify({ allowed, blocked }, null, 2));
if (allowed.status !== 200 || blocked.status === 200 && !blocked.body?.error) {
  process.exitCode = 1;
}
