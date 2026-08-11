const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { createProxy } = require('../dist/proxy');

async function listen(options = {}) {
  const calls = [];
  const broker = {
    async openSession(...args) {
      calls.push({ operation: 'open', args });
      return {
        id: 'a'.repeat(32),
        protocol: 'ftps',
        host: 'gateway.example.com',
        port: 21210,
        username: 'cg-user',
        password: 'ephemeral-password',
        tlsMode: 'explicit',
        accessMode: 'read_only',
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      };
    },
    async closeSession(id) {
      calls.push({ operation: 'close', id });
      return options.closeMissing !== true;
    },
  };
  const config = {
    server: { port: 0, agentKey: 'agent-key' },
    services: {},
    admin: { enabled: false, pin: '', allowedIPs: [], strictMode: true },
    security: { allowedUpstreams: [], blockPrivateIPs: true, followRedirects: false, maxPayloadLogSize: 10240 },
    proxy: { enabled: false, caDir: './data/ca', discovery: false, discoveryPolicy: 'block' },
    transparentProxy: { enabled: false, httpPort: 8080, httpsPort: 8443 },
    ftpGateway: { allowInsecureHttpApi: true },
  };
  const approval = { getStatus: () => ({}) };
  const audit = {
    getRecentRequests: () => [],
    getRecentFtpSessions: () => options.ftpAudit || [],
  };
  const server = http.createServer(createProxy(config, approval, audit, undefined, broker));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: server.address().port, calls };
}

async function close(server) {
  await new Promise((resolve) => server.close(resolve));
}

test('FTP lease endpoint authenticates, validates the exact body, and returns no-store credentials', async () => {
  const h = await listen();
  try {
    const unauthenticated = await fetch(`http://127.0.0.1:${h.port}/__ftp/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ service: 'files' }),
    });
    assert.equal(unauthenticated.status, 401);
    assert.equal(h.calls.length, 0);

    const invalid = await fetch(`http://127.0.0.1:${h.port}/__ftp/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-clawguard-key': 'agent-key' },
      body: JSON.stringify({ service: 'files', target: 'attacker.example' }),
    });
    assert.equal(invalid.status, 400);
    assert.equal(invalid.headers.get('cache-control'), 'no-store');
    assert.equal(h.calls.length, 0);

    const response = await fetch(`http://127.0.0.1:${h.port}/__ftp/session`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-clawguard-key': 'agent-key',
        'x-clawguard-user': 'integration-agent',
        'x-clawguard-reason': 'upload release',
      },
      body: JSON.stringify({ service: 'files' }),
    });
    assert.equal(response.status, 201);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal((await response.json()).password, 'ephemeral-password');
    assert.equal(h.calls.length, 1);
    assert.equal(h.calls[0].args[0], 'files');
    assert.equal(h.calls[0].args[2].user, 'integration-agent');
    assert.equal(h.calls[0].args[2].reason, 'upload release');
  } finally {
    await close(h.server);
  }
});

test('FTP lease endpoint revokes only syntactically valid session ids', async () => {
  const h = await listen();
  try {
    const bad = await fetch(`http://127.0.0.1:${h.port}/__ftp/session/not-valid`, {
      method: 'DELETE', headers: { 'x-clawguard-key': 'agent-key' },
    });
    assert.equal(bad.status, 400);
    assert.equal(h.calls.length, 0);

    const id = 'b'.repeat(32);
    const response = await fetch(`http://127.0.0.1:${h.port}/__ftp/session/${id}`, {
      method: 'DELETE', headers: { 'x-clawguard-key': 'agent-key' },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(h.calls, [{ operation: 'close', id }]);
  } finally {
    await close(h.server);
  }
});

test('FTP audit metadata never exposes the lease revocation capability', async () => {
  const h = await listen({
    ftpAudit: [{
      id: 'c'.repeat(32),
      service: 'files',
      protocol: 'ftps',
      outcome: 'active',
      clientIp: '192.0.2.10',
    }],
  });
  try {
    const response = await fetch(`http://127.0.0.1:${h.port}/__audit/ftp`, {
      headers: { 'x-clawguard-key': 'agent-key' },
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.deepEqual(await response.json(), [{
      service: 'files',
      protocol: 'ftps',
      outcome: 'active',
      clientIp: '192.0.2.10',
    }]);
  } finally {
    await close(h.server);
  }
});
