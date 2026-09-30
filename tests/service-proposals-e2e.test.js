const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const yaml = require('js-yaml');
const { createProxy } = require('../dist/proxy');
const { AuditLogger } = require('../dist/audit');
const { restoreProposalUpstreams } = require('../dist/service-proposals');
const { DEFAULT_SSH_BROKER, DEFAULT_FTP_GATEWAY } = require('../dist/config');

const credential = { $clawguard: 'credential' };
const hostKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC';
const agent = { 'X-ClawGuard-Key': 'test-agent', 'X-ClawGuard-User': 'Agent for Fabio', 'X-ClawGuard-Reason': 'Add requested service' };
const owner = { 'X-ClawGuard-Pin': 'test-owner' };
const manager = { checkApproval: async () => true, getStatus: () => [], getActiveCount: () => 0 };

function makeConfig() {
  return {
    server: { port: 0, agentKey: 'test-agent' },
    admin: { enabled: true, strictMode: false, pin: 'test-owner', allowedIPs: ['127.0.0.1'] },
    security: { allowedUpstreams: ['existing.example.com'], blockPrivateIPs: true, followRedirects: false, maxPayloadLogSize: 1024 },
    audit: { logPayload: true }, services: {},
    sshBroker: { ...DEFAULT_SSH_BROKER, enabled: true },
    ftpGateway: { ...DEFAULT_FTP_GATEWAY, enabled: true, allowInsecureHttpApi: true },
  };
}

function service(upstream = 'https://lombax.it') {
  return { protocol: 'http', upstream, auth: { type: 'bearer', token: credential },
    http: { allowedMethods: ['GET', 'POST', 'PUT'] }, policy: { default: 'require_approval' } };
}

async function listen(server) {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

async function withGateway(fn, config = makeConfig(), dbPath = ':memory:') {
  const audit = new AuditLogger(dbPath);
  restoreProposalUpstreams(config, audit);
  const server = http.createServer(createProxy(config, manager, audit));
  const base = await listen(server);
  const request = async (url, method = 'GET', body, headers = agent) => {
    const res = await fetch(base + url, { method, headers: { ...headers, 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: res.status, body: await res.json(), headers: res.headers };
  };
  try { await fn({ request, config, audit, base }); }
  finally { await new Promise((resolve) => server.close(resolve)); audit.close(); }
}

async function submit(request, name = 'lombax', config = service()) {
  const result = await request('/__proposals/services', 'POST', { name, config });
  assert.equal(result.status, 202, JSON.stringify(result.body));
  assert.equal(result.body.activated, false);
  return result.body.id;
}

test('HTTP proposal stays inert until the owner supplies credentials and allows the domain; status never leaks secrets', async () => {
  let hits = 0;
  let received;
  const upstream = http.createServer((req, res) => {
    hits++; received = req.headers.authorization;
    res.setHeader('content-type', 'application/json'); res.end('{"ok":true}');
  });
  const upstreamUrl = await listen(upstream);
  try {
    await withGateway(async ({ request, config, audit }) => {
      const proposalService = service(upstreamUrl);
      proposalService.http.allowPrivateTarget = true;
      const id = await submit(request, 'lombax', proposalService);
      assert.deepEqual(config.security.allowedUpstreams, ['existing.example.com']);
      assert.equal(config.services.lombax, undefined);
      assert.equal((await request('/lombax/')).status, 404);
      assert.equal(hits, 0);
      assert.deepEqual(audit.getServiceOverrides(), {});
      assert.equal((await request('/__admin/api/service-proposals')).status, 401);
      assert.equal((await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', {})).status, 401);
      const pending = await request('/__admin/api/service-proposals', 'GET', undefined, owner);
      assert.equal(pending.body[0].requestUser, 'Agent for Fabio');
      assert.equal(pending.body[0].requestReason, 'Add requested service');
      const missing = await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', { allowUpstreams: true }, owner);
      assert.equal(missing.status, 400);
      const domainMissing = await request(`/__admin/api/service-proposals/${id}/approve`, 'POST',
        { credentials: { '/auth/token': { value: 'OWNER-ONLY-TEST-TOKEN' } } }, owner);
      assert.equal(domainMissing.status, 400);
      const approval = await request(`/__admin/api/service-proposals/${id}/approve`, 'POST',
        { allowUpstreams: true, credentials: { '/auth/token': { value: 'OWNER-ONLY-TEST-TOKEN' } } }, owner);
      assert.equal(approval.status, 200, JSON.stringify(approval.body));
      const call = await request('/lombax/');
      assert.equal(call.status, 200);
      assert.equal(received, 'Bearer OWNER-ONLY-TEST-TOKEN');
      const denied = await request('/lombax/', 'DELETE');
      assert.equal(denied.status, 405);
      assert.equal(denied.headers.get('allow'), 'GET, POST, PUT');
      assert.equal(hits, 1);
      const status = await request(`/__proposals/services/${id}`);
      assert.equal(status.body.status, 'approved');
      for (const data of [status.body, (await request('/__admin/api/service-proposals', 'GET', undefined, owner)).body,
        (await request('/__admin/api/credential-sources', 'GET', undefined, owner)).body, audit.getRecentRequests()]) {
        assert.equal(JSON.stringify(data).includes('OWNER-ONLY-TEST-TOKEN'), false);
      }
      assert.equal((await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', {}, owner)).status, 409);
    });
  } finally { await new Promise((resolve) => upstream.close(resolve)); }
});

test('proposal API validates supported HTTP auth modes and SSH/FTP/FTPS without activating plugins', async () => {
  await withGateway(async ({ request, config }) => {
    const variants = [
      { type: 'header', headerName: 'X-Api-Key', token: credential },
      { type: 'query', paramName: 'key', token: credential },
      { type: 'basic', username: 'fabio', password: credential },
      { type: 'url', username: 'fabio', password: credential },
      { type: 'body_json', fields: { access_token: credential } },
      { type: 'oauth2_client_credentials', tokenPath: '/oauth/token', clientId: credential, clientSecret: credential },
      { type: 'oauth2_authorization_code', authorizeUrl: 'https://auth.example.com/authorize',
        tokenUrl: 'https://auth.example.com/token', redirectUri: 'http://localhost/callback', scopes: ['read'], clientId: credential },
      { type: 'plugin', pluginPath: 'aws-sigv4', pluginConfig: { accessKeyId: credential,
        secretAccessKey: credential, region: 'eu-west-1', service: 'cloudtrail' } },
    ];
    for (const [index, auth] of variants.entries()) await submit(request, `http-${index}`, { ...service(), auth });
    for (const protocol of ['ssh', 'ftp', 'ftps']) {
      const doc = { protocol, upstream: `${protocol}://server.example.com:${protocol === 'ssh' ? 22 : 21}`,
        auth: { type: 'plugin', pluginPath: protocol === 'ssh' ? 'ssh-agent-key' : 'ftp-password',
          pluginConfig: { username: 'deploy', [protocol === 'ssh' ? 'privateKey' : 'password']: credential } },
        policy: { default: 'require_approval' },
        [protocol === 'ssh' ? 'ssh' : 'ftp']: { allowPrivateTarget: false,
          ...(protocol === 'ssh' ? { knownHostKey: { $clawguard: 'input' } } : protocol === 'ftps' ? { tlsMode: 'explicit' } : {}) } };
      await submit(request, protocol, doc);
    }
    assert.deepEqual(config.services, {});
  });
});

test('invalid, credential-bearing, unsafe, and oversized proposals are rejected without changing services', async () => {
  await withGateway(async ({ request, config, base }) => {
    const invalid = [
      { ...service(), auth: { type: 'bearer', token: 'REAL-CREDENTIAL-MUST-BE-REJECTED' } },
      { ...service(), upstream: 'https://user:password@lombax.it' },
      { ...service(), upstream: 'https://lombax.it?token=secret' },
      { ...service(), auth: { type: 'plugin', pluginPath: '/tmp/agent-code.js', pluginConfig: {} } },
      { ...service(), auth: { type: 'bearer', token: '${file:/etc/password}' } },
      { ...service(), auth: { type: 'bearer', token: { $clawguard: 'keep-secret' } } },
      { ...service(), policy: { default: 'allow-anything' } },
      { ...service(), http: { allowedMethods: ['get'] } },
      { ...service(), http: { methods: ['GET'] } },
      { ...service(), auth: { type: 'plugin', pluginPath: 'aws-sigv4', pluginConfig: {
        accessKeyId: credential, secretAccessKey: credential, region: 'vault:secret/region#token', service: 'cloudtrail' } } },
      { ...service(), upstream: 'http://127.0.0.1' },
      { ...service(), protocol: 'sftp' },
      JSON.parse('{"auth":{"type":"bearer","token":{"$clawguard":"credential"}},"upstream":"https://lombax.it","__proto__":{"polluted":true}}'),
    ];
    for (const doc of invalid) {
      const response = await request('/__proposals/services', 'POST', { name: 'invalid', config: doc });
      assert.equal(response.status, 400, JSON.stringify(response.body));
      assert.equal(JSON.stringify(response.body).includes('REAL-CREDENTIAL-MUST-BE-REJECTED'), false);
    }
    assert.equal((await request('/__proposals/services', 'POST', { name: 'new', config: service() }, {})).status, 401);
    const raw = await fetch(base + '/__proposals/services', { method: 'POST', headers: agent, body: '{bad json' });
    assert.equal(raw.status, 400);
    assert.equal((await request('/__proposals/services', 'POST', { name: 'large', config: service(), extra: 'a'.repeat(65536) })).status, 400);
    assert.deepEqual(config.services, {});
    assert.equal({}.polluted, undefined);
  });
});

test('owner can reuse a managed token without exposing it; arbitrary source paths are refused', async () => {
  const config = makeConfig();
  config.services.existing = { ...service('https://existing.example.com'), auth: { type: 'bearer', token: 'MANAGED-SECRET' } };
  await withGateway(async ({ request, config }) => {
    const id = await submit(request);
    const sources = await request('/__admin/api/credential-sources', 'GET', undefined, owner);
    assert.equal(JSON.stringify(sources.body).includes('MANAGED-SECRET'), false);
    const bad = await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', { allowUpstreams: true,
      credentials: { '/auth/token': { service: 'existing', path: '/upstream' } } }, owner);
    assert.equal(bad.status, 400);
    const good = await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', { allowUpstreams: true,
      credentials: { '/auth/token': { service: 'existing', path: '/auth/token' } } }, owner);
    assert.equal(good.status, 200, JSON.stringify(good.body));
    assert.equal(config.services.lombax.auth.token, 'MANAGED-SECRET');
  }, config);
});

test('SSH and FTP credentials selected in the UI are resolved only by the server', async () => {
  const config = makeConfig();
  config.services.keySource = { protocol: 'ssh', upstream: 'ssh://127.0.0.1:22',
    auth: { type: 'plugin', pluginPath: 'ssh-agent-key', pluginConfig: { username: 'deploy', privateKey: 'TEST-ONLY-PRIVATE-KEY' } },
    policy: { default: 'require_approval' }, ssh: { allowPrivateTarget: true, knownHostKey: hostKey } };
  await withGateway(async ({ request, config }) => {
    const ssh = { ...config.services.keySource, upstream: 'ssh://127.0.0.1:2222',
      auth: { type: 'plugin', pluginPath: 'ssh-agent-key', pluginConfig: { username: 'deploy', privateKey: credential } },
      ssh: { allowPrivateTarget: true, knownHostKey: { $clawguard: 'input' } } };
    const id = await submit(request, 'new-ssh', ssh);
    const result = await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', { allowUpstreams: true,
      credentials: { '/auth/pluginConfig/privateKey': { service: 'keySource', path: '/auth/pluginConfig/privateKey' } },
      inputs: { '/ssh/knownHostKey': hostKey } }, owner);
    assert.equal(result.status, 200, JSON.stringify(result.body));
    assert.equal(config.services['new-ssh'].auth.pluginConfig.privateKey, 'TEST-ONLY-PRIVATE-KEY');
    for (const protocol of ['ftp', 'ftps']) {
      const doc = { protocol, upstream: `${protocol}://127.0.0.1:21`,
        auth: { type: 'plugin', pluginPath: 'ftp-password', pluginConfig: { username: 'deploy', password: credential } },
        policy: { default: 'require_approval' }, ftp: { allowPrivateTarget: true,
          ...(protocol === 'ftps' ? { tlsMode: 'explicit' } : {}) } };
      const ftpId = await submit(request, `new-${protocol}`, doc);
      const approved = await request(`/__admin/api/service-proposals/${ftpId}/approve`, 'POST', {
        credentials: { '/auth/pluginConfig/password': { value: 'TEST-ONLY-FTP-PASSWORD' } } }, owner);
      assert.equal(approved.status, 200, JSON.stringify(approved.body));
      assert.equal(config.services[`new-${protocol}`].auth.pluginConfig.password, 'TEST-ONLY-FTP-PASSWORD');
    }
    const queue = await request('/__admin/api/service-proposals', 'GET', undefined, owner);
    assert.equal(JSON.stringify(queue.body).includes('TEST-ONLY-PRIVATE-KEY'), false);
    assert.equal(JSON.stringify(queue.body).includes('TEST-ONLY-FTP-PASSWORD'), false);
  }, config);
});

test('rejection is terminal, duplicates are idempotent, and strict mode blocks activation', async () => {
  await withGateway(async ({ request, config }) => {
    const id = await submit(request);
    const retry = await request('/__proposals/services', 'POST', { name: 'lombax', config: service() });
    assert.equal(retry.status, 200); assert.equal(retry.body.id, id);
    assert.equal((await request('/__proposals/services', 'POST', { name: 'lombax', config: service('https://other.example.com') })).status, 409);
    config.admin.strictMode = true;
    assert.equal((await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', {}, owner)).status, 403);
    assert.equal((await request(`/__admin/api/service-proposals/${id}/reject`, 'POST', {}, owner)).status, 200);
    config.admin.strictMode = false;
    assert.equal((await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', {}, owner)).status, 409);
    assert.equal((await request(`/__proposals/services/${id}`)).body.status, 'rejected');
    assert.deepEqual(config.services, {});
    config.admin.allowedIPs = ['192.0.2.1'];
    assert.equal((await request('/__admin/api/service-proposals', 'GET', undefined, owner)).status, 403);
  });
});

test('pending proposals and approved upstreams/services survive a database reopen; strict mode ignores overrides', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clawguard-proposals-'));
  const dbPath = path.join(dir, 'audit.db');
  let pendingId;
  try {
    await withGateway(async ({ request }) => {
      pendingId = await submit(request, 'pending');
      const id = await submit(request, 'approved');
      const approved = await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', { allowUpstreams: true,
        credentials: { '/auth/token': { value: 'PERSISTED-TEST-SECRET' } } }, owner);
      assert.equal(approved.status, 200);
    }, makeConfig(), dbPath);
    await withGateway(async ({ request, config, audit }) => {
      assert.equal((await request(`/__proposals/services/${pendingId}`)).body.status, 'pending');
      assert.equal(config.security.allowedUpstreams.includes('lombax.it'), true);
      assert.equal(audit.getServiceOverrides().approved.auth.token, 'PERSISTED-TEST-SECRET');
      assert.equal(audit.getServiceProposals().some(row => JSON.stringify(row).includes('PERSISTED-TEST-SECRET')), false);
    }, makeConfig(), dbPath);
    const strict = makeConfig(); strict.admin.strictMode = true;
    await withGateway(async ({ config }) => {
      assert.deepEqual(config.security.allowedUpstreams, ['existing.example.com']);
    }, strict, dbPath);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('failed credential plugin initialization leaves the proposal pending and hides error secrets', async () => {
  await withGateway(async ({ request, config }) => {
    const doc = { protocol: 'ftp', upstream: 'ftp://127.0.0.1:21',
      auth: { type: 'plugin', pluginPath: 'ftp-password', pluginConfig: { username: 'deploy', password: credential } },
      policy: { default: 'require_approval' }, ftp: { allowPrivateTarget: true } };
    const id = await submit(request, 'broken-ftp', doc);
    const result = await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', { allowUpstreams: true,
      credentials: { '/auth/pluginConfig/password': { value: 'SECRET\nINVALID' } } }, owner);
    assert.equal(result.status, 400);
    assert.equal(JSON.stringify(result.body).includes('SECRET'), false);
    assert.equal((await request(`/__proposals/services/${id}`)).body.status, 'pending');
    assert.equal(config.services['broken-ftp'], undefined);
    assert.deepEqual(config.security.allowedUpstreams, ['existing.example.com']);
  });
});

test('simultaneous owner approvals activate a proposal exactly once', async () => {
  await withGateway(async ({ request, audit }) => {
    const id = await submit(request);
    const body = { allowUpstreams: true, credentials: { '/auth/token': { value: 'TEST-TOKEN' } } };
    const results = await Promise.all([
      request(`/__admin/api/service-proposals/${id}/approve`, 'POST', body, owner),
      request(`/__admin/api/service-proposals/${id}/approve`, 'POST', body, owner),
    ]);
    assert.deepEqual(results.map(result => result.status).sort(), [200, 409]);
    assert.equal(audit.getServiceProposals().filter(row => row.status === 'approved').length, 1);
    assert.equal(Object.keys(audit.getServiceOverrides()).length, 1);
  });
});

test('approved HTTP service remains usable after starting the real ClawGuard entry point against the persisted database', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clawguard-process-'));
  const dbPath = path.join(dir, 'audit.db');
  const upstream = http.createServer((req, res) => {
    assert.equal(req.headers.authorization, 'Bearer RESTART-TEST-TOKEN');
    res.setHeader('content-type', 'application/json'); res.end('{"restored":true}');
  });
  const upstreamUrl = await listen(upstream);
  let child;
  try {
    await withGateway(async ({ request }) => {
      const doc = service(upstreamUrl); doc.http.allowPrivateTarget = true;
      const id = await submit(request, 'restored', doc);
      assert.equal((await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', {
        allowUpstreams: true, credentials: { '/auth/token': { value: 'RESTART-TEST-TOKEN' } },
      }, owner)).status, 200);
    }, makeConfig(), dbPath);
    const reservation = http.createServer();
    const base = await listen(reservation);
    const port = reservation.address().port;
    await new Promise(resolve => reservation.close(resolve));
    const configPath = path.join(dir, 'test.yaml');
    fs.writeFileSync(configPath, yaml.dump({
      server: { port, agentKey: 'test-agent' },
      admin: { enabled: true, strictMode: false, pin: 'test-owner', allowedIPs: ['127.0.0.1'] },
      services: { existing: { upstream: 'https://existing.example.com',
        auth: { type: 'bearer', token: 'TEST-ONLY' }, policy: { default: 'require_approval' } } },
      security: { allowedUpstreams: ['existing.example.com'], blockPrivateIPs: true },
      audit: { path: dbPath, logPayload: false },
    }));
    child = spawn(process.execPath, [path.resolve(__dirname, '../dist/index.js')], {
      cwd: dir, env: { ...process.env, CLAWGUARD_CONFIG: configPath }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', data => { output += data; });
    child.stderr.on('data', data => { output += data; });
    let ready = false;
    for (let attempt = 0; attempt < 80; attempt++) {
      if (child.exitCode !== null) throw new Error('ClawGuard exited: ' + output);
      try {
        const status = await fetch(base + '/__status', { headers: agent });
        if (status.ok) { ready = true; break; }
      } catch { /* wait for the test process listener */ }
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.equal(ready, true, output);
    const result = await fetch(base + '/restored/', { headers: agent });
    assert.equal(result.status, 200, output);
    assert.deepEqual(await result.json(), { restored: true });
    assert.equal((await fetch(base + '/restored/', { method: 'DELETE', headers: agent })).status, 405);
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise(resolve => child.once('exit', resolve));
    }
    await new Promise(resolve => upstream.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
