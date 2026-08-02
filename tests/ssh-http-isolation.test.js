const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { createProxy, __resolveServiceByHostForTests } = require('../dist/proxy');
const { __resolveServiceByHostnameForTests } = require('../dist/mitm-proxy');

function protocolCollisionServices() {
  return {
    sshFirst: {
      protocol: 'ssh',
      upstream: 'ssh://shared.example.com:22',
      hostnames: ['shared.example.com'],
      auth: { type: 'plugin' },
      policy: { default: 'require_approval' },
      ssh: { knownHostKey: 'ssh-ed25519 AAAATEST', allowPrivateTarget: false },
    },
    httpSecond: {
      protocol: 'http',
      upstream: 'https://shared.example.com',
      hostnames: ['shared.example.com'],
      auth: { type: 'bearer', token: 'http-secret' },
      policy: { default: 'require_approval' },
    },
  };
}

test('MITM and host resolvers skip SSH services on a shared hostname', () => {
  const services = protocolCollisionServices();
  assert.equal(__resolveServiceByHostnameForTests('shared.example.com', services).name, 'httpSecond');
  assert.equal(__resolveServiceByHostForTests('shared.example.com:443', services).name, 'httpSecond');

  delete services.httpSecond;
  assert.equal(__resolveServiceByHostnameForTests('shared.example.com', services), null);
  assert.equal(__resolveServiceByHostForTests('shared.example.com:443', services), null);
});

test('HTTP proxy rejects SSH services before auth plugin, approval, audit, or forwarding', async () => {
  let authReads = 0;
  let approvalCalls = 0;
  let auditCalls = 0;

  const sshService = {
    protocol: 'ssh',
    upstream: 'ssh://127.0.0.1:1',
    policy: { default: 'require_approval' },
    ssh: { knownHostKey: 'ssh-ed25519 AAAATEST', allowPrivateTarget: true },
  };
  Object.defineProperty(sshService, 'auth', {
    enumerable: true,
    get() {
      authReads++;
      throw new Error('HTTP path touched SSH credential plugin configuration');
    },
  });

  const config = {
    server: { port: 0, agentKey: 'agent-key' },
    services: { 'production-ssh': sshService },
    admin: { enabled: false, pin: '', allowedIPs: [], strictMode: true },
    audit: { type: 'sqlite', path: ':memory:', logPayload: false },
    security: {
      allowedUpstreams: [], blockPrivateIPs: true, followRedirects: false, maxPayloadLogSize: 10240,
    },
    proxy: { enabled: false, caDir: './data/ca', discovery: false, discoveryPolicy: 'block' },
    transparentProxy: { enabled: false, httpPort: 8080, httpsPort: 8443 },
  };
  const approvalManager = {
    getStatus: () => ({}),
    async checkApproval() {
      approvalCalls++;
      throw new Error('HTTP path requested approval for SSH service');
    },
  };
  const audit = {
    getRecentRequests: () => [],
    logRequest() {
      auditCalls++;
      throw new Error('HTTP path audited SSH as an HTTP request');
    },
  };

  const server = http.createServer(createProxy(config, approvalManager, audit));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  try {
    const res = await fetch(`http://127.0.0.1:${port}/production-ssh/anything`, {
      headers: { 'x-clawguard-key': 'agent-key', connection: 'close' },
    });
    assert.equal(res.status, 404);
    assert.deepEqual(await res.json(), {
      error: 'SSH services are not available over the HTTP proxy',
    });
    assert.equal(authReads, 0);
    assert.equal(approvalCalls, 0);
    assert.equal(auditCalls, 0);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
