const gatewayUrl = process.env.GATEWAY_URL ?? 'http://127.0.0.1:3000/mcp';

let sessionId = null;
let nextId = 1;

function parseBody(contentType, rawText) {
  if (!rawText.trim()) return null;
  if (contentType.includes('text/event-stream')) {
    const events = rawText
      .split(/\r?\n/)
      .filter(line => line.startsWith('data:'))
      .map(line => line.slice(5).trim())
      .filter(Boolean);
    for (let i = events.length - 1; i >= 0; i--) {
      try {
        return JSON.parse(events[i]);
      } catch { /* continue */ }
    }
    return { raw: rawText };
  }
  try {
    return JSON.parse(rawText);
  } catch {
    return { raw: rawText };
  }
}

async function postWithRetry(payload, isNotification = false) {
  let lastErr;
  for (let attempt = 0; attempt < 20; attempt++) {
    try {
      const headers = {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream'
      };
      if (sessionId) headers['mcp-session-id'] = sessionId;
      const res = await fetch(gatewayUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload)
      });
      const sid = res.headers.get('mcp-session-id');
      if (sid) sessionId = sid;
      const rawText = await res.text();
      return {
        status: res.status,
        body: isNotification && !rawText.trim() ? null : parseBody(res.headers.get('content-type') ?? '', rawText)
      };
    } catch (err) {
      lastErr = err;
      await new Promise(r => setTimeout(r, 250));
    }
  }
  throw lastErr;
}

const rpc = (method, params = {}) => postWithRetry({ jsonrpc: '2.0', id: nextId++, method, params });
const notify = (method, params = {}) => postWithRetry({ jsonrpc: '2.0', method, params }, true);

const initialized = await rpc('initialize', {
  protocolVersion: '2025-03-26',
  capabilities: {},
  clientInfo: { name: 'vambrace-e2e', version: '1.1.0-rc1' }
});
const notifyRes = await notify('notifications/initialized', {});
const allowed = await rpc('tools/call', { name: 'lookup', arguments: { id: '42' } });
const blocked = await rpc('tools/call', { name: 'search', arguments: { query: 'test' } });

console.log(JSON.stringify({ initialized, notifyStatus: notifyRes.status, allowed, blocked }, null, 2));

const initOk = initialized.status === 200 && !initialized.body?.error && Boolean(initialized.body?.result?.serverInfo);
const notifyOk = notifyRes.status >= 200 && notifyRes.status < 300;
const allowedOk = allowed.status === 200 && !allowed.body?.error && JSON.stringify(allowed.body).includes('called:lookup');
const blockedOk = blocked.status !== 200 || Boolean(blocked.body?.error);
if (!initOk || !notifyOk || !allowedOk || !blockedOk) {
  process.exitCode = 1;
}
