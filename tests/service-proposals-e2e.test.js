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
const manager = { checkApproval: async () => true, getStatus: () => [], getActiveCount: () => 0, revokeApproval: () => true };

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

async function withGateway(fn, config = makeConfig(), dbPath = ':memory:', managerFactory = () => manager) {
  const audit = new AuditLogger(dbPath);
  restoreProposalUpstreams(config, audit);
  const server = http.createServer(createProxy(config, managerFactory(audit), audit));
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
      { type: 'bearer', token: credential, dummyToken: 'dummy' },
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

test('owner can select first-use trust on an existing SSH proposal without a host key, or supply a verified key', async () => {
  await withGateway(async ({ request, config, audit }) => {
    const ssh = { protocol: 'ssh', upstream: 'ssh://127.0.0.1:22',
      auth: { type: 'plugin', pluginPath: 'ssh-agent-key', pluginConfig: { username: 'root', privateKey: credential } },
      policy: { default: 'require_approval' }, ssh: { allowPrivateTarget: true, knownHostKey: { $clawguard: 'input' } } };
    const id = await submit(request, 'first-use', ssh);
    const approved = await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', {
      sshTrustOnFirstUse: true, allowUpstreams: true,
      credentials: { '/auth/pluginConfig/privateKey': { value: 'TEST-ONLY-KEY' } },
    }, owner);
    assert.equal(approved.status, 200, JSON.stringify(approved.body));
    assert.equal(config.services['first-use'].ssh.trustOnFirstUse, true);
    assert.equal(config.services['first-use'].ssh.knownHostKey, undefined);
    assert.equal(audit.getSshHostIdentity('first-use', ssh.upstream), undefined, 'approval does not contact the upstream');
    const proposedTofu = { ...ssh, ssh: { allowPrivateTarget: true, trustOnFirstUse: true } };
    const pinnedId = await submit(request, 'pinned', proposedTofu);
    assert.equal((await request(`/__admin/api/service-proposals/${pinnedId}/approve`, 'POST', {
      sshTrustOnFirstUse: false, inputs: { '/ssh/knownHostKey': hostKey },
      credentials: { '/auth/pluginConfig/privateKey': { value: 'TEST-ONLY-KEY' } },
    }, owner)).status, 200);
    assert.equal(config.services.pinned.ssh.knownHostKey, hostKey);
    assert.equal(config.services.pinned.ssh.trustOnFirstUse, undefined);
    const invalid = await request('/__proposals/services', 'POST', { name: 'conflicting',
      config: { ...ssh, ssh: { allowPrivateTarget: true, trustOnFirstUse: true, knownHostKey: hostKey } } });
    assert.equal(invalid.status, 400);
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

async function activate(request, name, doc) {
  const id = await submit(request, name, doc);
  const result = await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', {
    allowUpstreams: true, credentials: { '/auth/token': { value: 'CURRENT-TEST-SECRET' } },
  }, owner);
  assert.equal(result.status, 200, JSON.stringify(result.body));
}

test('partial update preserves credentials and omitted fields, shows a safe diff, and activates only after owner approval', async () => {
  const upstream = http.createServer((req, res) => {
    assert.equal(req.headers.authorization, 'Bearer CURRENT-TEST-SECRET');
    res.setHeader('content-type', 'application/json'); res.end('{"ok":true}');
  });
  const upstreamUrl = await listen(upstream);
  try {
    await withGateway(async ({ request, config, audit }) => {
      const initial = service(upstreamUrl); initial.http = { allowedMethods: ['GET'], allowPrivateTarget: true };
      await activate(request, 'lombax', initial);
      const blocked = await request('/lombax/resource', 'POST', {});
      assert.equal(blocked.status, 405);
      assert.equal(blocked.body.proposalEndpoint, '/__proposals/services');
      assert.deepEqual(blocked.body.allowedMethods, ['GET']);
      const patch = { http: { allowedMethods: ['GET', 'POST'] } };
      const id = await submit(request, 'lombax', patch);
      assert.equal((await request(`/__proposals/services/${id}`)).body.operation, 'update');
      assert.equal((await request('/lombax/resource', 'POST', {})).status, 405);
      assert.equal((await request('/lombax/resource')).status, 200);
      assert.equal((await request('/__proposals/services', 'POST', { name: 'lombax', config: patch })).body.id, id);
      assert.equal((await request('/__proposals/services', 'POST', { name: 'lombax', config: { http: { allowedMethods: ['POST'] } } })).status, 409);
      const queue = await request('/__admin/api/service-proposals', 'GET', undefined, owner);
      const proposed = queue.body.find(item => item.id === id);
      assert.deepEqual(proposed.changes, [{ path: '/http/allowedMethods', before: ['GET'], after: ['GET', 'POST'] }]);
      assert.equal(proposed.requirements[0].reusable, true);
      assert.equal(proposed.credentialContextChanged, false);
      assert.ok(!JSON.stringify(queue.body).includes('CURRENT-TEST-SECRET'));
      assert.equal((await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', {})).status, 401);
      assert.equal((await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', {}, owner)).status, 200);
      assert.equal((await request('/lombax/resource', 'POST', {})).status, 200);
      assert.equal(config.services.lombax.http.allowPrivateTarget, true);
      assert.equal(config.services.lombax.policy.default, 'require_approval');
      assert.equal(config.services.lombax.auth.token, 'CURRENT-TEST-SECRET');
      const unchanged = await request('/__proposals/services', 'POST', { name: 'lombax', config: patch });
      assert.equal(unchanged.status, 200); assert.equal(unchanged.body.status, 'unchanged');
      assert.equal(unchanged.body.id, undefined);
      const removal = await submit(request, 'lombax', { http: { allowedMethods: ['POST'] } });
      assert.equal((await request(`/__admin/api/service-proposals/${removal}/approve`, 'POST', {}, owner)).status, 200);
      assert.equal((await request('/lombax/resource')).status, 405);
      assert.equal((await request('/lombax/resource', 'POST', {})).status, 200);
      assert.ok(!JSON.stringify(audit.getServiceProposals()).includes('CURRENT-TEST-SECRET'));
      assert.equal((await request('/__proposals/services', 'POST', { name: 'lombax', config: { auth: { token: 'FORBIDDEN-SECRET' } } })).status, 400);
    });
  } finally { await new Promise(resolve => upstream.close(resolve)); }
});

test('manual edits, credential rotation and delete/recreate invalidate pending updates', async () => {
  await withGateway(async ({ request, config }) => {
    const initial = service('https://existing.example.com'); initial.http.allowedMethods = ['GET'];
    await activate(request, 'lombax', initial);
    for (const change of ['edit', 'credentials', 'recreate']) {
      const id = await submit(request, 'lombax', { http: { allowedMethods: ['GET', 'POST'] } });
      if (change === 'recreate') {
        const copy = structuredClone(config.services.lombax);
        assert.equal((await request('/__admin/api/services/lombax', 'DELETE', undefined, owner)).status, 200);
        assert.equal((await request('/__admin/api/services', 'POST', { name: 'lombax', config: copy }, owner)).status, 200);
      } else {
        const patch = change === 'edit' ? { http: { noCheckCertificate: true } } : { auth: { token: 'ROTATED-TEST-SECRET' } };
        assert.equal((await request('/__admin/api/services/lombax', 'PUT', { config: patch }, owner)).status, 200);
      }
      assert.equal((await request(`/__proposals/services/${id}`)).body.status, 'stale');
      assert.equal((await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', {}, owner)).status, 409);
      assert.deepEqual(config.services.lombax.http.allowedMethods, ['GET']);
    }
    const fresh = await submit(request, 'lombax', { http: { allowedMethods: ['GET', 'POST'] } });
    assert.equal((await request(`/__admin/api/service-proposals/${fresh}/approve`, 'POST', {}, owner)).status, 200);
  });
});

test('credential reuse across destination changes requires owner confirmation; new credential slots require owner input', async () => {
  await withGateway(async ({ request, config }) => {
    await activate(request, 'lombax', service('https://existing.example.com'));
    const id = await submit(request, 'lombax', { upstream: 'https://different.example.com' });
    const denied = await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', { allowUpstreams: true }, owner);
    assert.equal(denied.status, 400); assert.match(denied.body.error, /Confirm reuse/);
    assert.equal(config.services.lombax.upstream, 'https://existing.example.com');
    assert.equal((await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', { allowUpstreams: true, confirmCredentialReuse: true }, owner)).status, 200);
    assert.equal(config.services.lombax.auth.token, 'CURRENT-TEST-SECRET');
    const newSlot = await submit(request, 'lombax', { auth: { type: 'basic', username: 'deploy', password: credential } });
    assert.equal((await request(`/__admin/api/service-proposals/${newSlot}/approve`, 'POST', { confirmCredentialReuse: true }, owner)).status, 400);
    assert.equal((await request(`/__admin/api/service-proposals/${newSlot}/approve`, 'POST', {
      confirmCredentialReuse: true, credentials: { '/auth/password': { value: 'NEW-TEST-PASSWORD' } },
    }, owner)).status, 200);
    assert.equal(config.services.lombax.auth.password, 'NEW-TEST-PASSWORD');
  });
});

test('unchanged revisions survive reopen; YAML changes invalidate pending updates', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-proposal-update-'));
  const db = path.join(dir, 'audit.db');
  let saved, id;
  try {
    await withGateway(async ({ request, config }) => {
      const initial = service('https://existing.example.com'); initial.http.allowedMethods = ['GET'];
      await activate(request, 'lombax', initial);
      id = await submit(request, 'lombax', { http: { allowedMethods: ['GET', 'POST'] } });
      saved = structuredClone(config);
    }, makeConfig(), db);
    await withGateway(async ({ request, config }) => {
      assert.equal((await request(`/__proposals/services/${id}`)).body.status, 'pending');
      assert.equal((await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', {}, owner)).status, 200);
      id = await submit(request, 'lombax', { http: { allowedMethods: ['GET', 'POST', 'PUT'] } });
      saved = structuredClone(config);
    }, saved, db);
    saved.services.lombax.upstream = 'https://changed-via-yaml.example.com';
    await withGateway(async ({ request }) => {
      assert.equal((await request(`/__proposals/services/${id}`)).body.status, 'stale');
      assert.equal((await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', {}, owner)).status, 409);
    }, saved, db);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

async function withPluginGateway(run) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-proposal-plugin-'));
  const pluginPath = path.join(dir, 'plugin.cjs');
  const pluginName = path.basename(dir);
  fs.writeFileSync(pluginPath, `let gate; let entered = false;
    exports.pause = promise => { gate = promise; entered = false; };
    exports.entered = () => entered;
    exports.createPlugin = () => ({ name: ${JSON.stringify(pluginName)},
      async init(_dir, config) { entered = true; if (gate) await gate; gate = undefined;
        if (config.token === 'INVALID-TEST-SECRET') throw Error(config.token);
        this.token = config.token; },
      async rewriteRequest(ctx) { return { headers: { ...ctx.headers, authorization: 'Bearer ' + this.token }, body: ctx.body }; }
    });`);
  let received;
  const upstream = http.createServer((req, res) => {
    received = req.headers.authorization; res.setHeader('content-type', 'application/json'); res.end('{"ok":true}');
  });
  const url = await listen(upstream);
  const config = makeConfig(); config.security.allowedUpstreams.push('127.0.0.1');
  try {
    await withGateway(async f => {
      const doc = { ...service(url), auth: { type: 'plugin', pluginPath, pluginConfig: { token: 'OLD-TEST-SECRET', enabled: true } },
        http: { allowedMethods: ['GET'], allowPrivateTarget: true } };
      assert.equal((await f.request('/__admin/api/services', 'POST', { name: 'plugin-app', config: doc }, owner)).status, 200);
      await run({ ...f, plugin: require(pluginPath), received: () => received });
    }, config);
  } finally {
    await new Promise(resolve => upstream.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(path.resolve('data/plugins', pluginName), { recursive: true, force: true });
  }
}

test('failed initialization and database save preserve the old live plugin and leave update pending', async () => {
  await withPluginGateway(async ({ request, audit, received }) => {
    const id = await submit(request, 'plugin-app', { http: { allowedMethods: ['GET', 'POST'] } });
    const approve = value => request(`/__admin/api/service-proposals/${id}/approve`, 'POST', {
      credentials: { '/auth/pluginConfig/token': { value } },
    }, owner);
    const bad = await approve('INVALID-TEST-SECRET');
    assert.equal(bad.status, 400); assert.ok(!JSON.stringify(bad.body).includes('INVALID-TEST-SECRET'));
    assert.equal((await request('/plugin-app/')).status, 200); assert.equal(received(), 'Bearer OLD-TEST-SECRET');
    const save = audit.saveServiceOverride.bind(audit);
    audit.saveServiceOverride = () => { throw Error('simulated disk failure'); };
    try { assert.equal((await approve('NEW-TEST-SECRET')).status, 400); }
    finally { audit.saveServiceOverride = save; }
    assert.equal((await request(`/__proposals/services/${id}`)).body.status, 'pending');
    assert.equal((await request('/plugin-app/')).status, 200); assert.equal(received(), 'Bearer OLD-TEST-SECRET');
    assert.equal((await request('/plugin-app/', 'POST', {})).status, 405);
    assert.equal((await approve('NEW-TEST-SECRET')).status, 200);
    assert.equal((await request('/plugin-app/', 'POST', {})).status, 200); assert.equal(received(), 'Bearer NEW-TEST-SECRET');
  });
});

test('admin writes and proposal approvals reserve the alias while preparing a plugin', async () => {
  await withPluginGateway(async ({ request, plugin, received }) => {
    const id = await submit(request, 'plugin-app', { http: { allowedMethods: ['GET', 'POST'] } });
    let release;
    plugin.pause(new Promise(resolve => { release = resolve; }));
    const approval = request(`/__admin/api/service-proposals/${id}/approve`, 'POST', {
      credentials: { '/auth/pluginConfig/token': { value: 'NEW-TEST-SECRET' } },
    }, owner);
    try {
      for (let i = 0; i < 100 && !plugin.entered(); i++) await new Promise(resolve => setTimeout(resolve, 5));
      assert.ok(plugin.entered());
      assert.equal((await request('/plugin-app/')).status, 200); assert.equal(received(), 'Bearer OLD-TEST-SECRET');
      assert.equal((await request('/__admin/api/services/plugin-app', 'PUT', { config: { policy: { default: 'auto_approve' } } }, owner)).status, 409);
      assert.equal((await request('/__admin/api/services/plugin-app', 'DELETE', undefined, owner)).status, 409);
      assert.equal((await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', {}, owner)).status, 409);
    } finally { release(); }
    assert.equal((await approval).status, 200);
    const next = await submit(request, 'plugin-app', { http: { allowedMethods: ['GET'] } });
    plugin.pause(new Promise(resolve => { release = resolve; }));
    const manual = request('/__admin/api/services/plugin-app', 'PUT', { config: { auth: { pluginConfig: { token: 'MANUAL-TEST-SECRET' } } } }, owner);
    try {
      for (let i = 0; i < 100 && !plugin.entered(); i++) await new Promise(resolve => setTimeout(resolve, 5));
      assert.ok(plugin.entered());
      assert.equal((await request(`/__admin/api/service-proposals/${next}/approve`, 'POST', {}, owner)).status, 409);
    } finally { release(); }
    assert.equal((await manual).status, 200);
    assert.equal((await request(`/__proposals/services/${next}`)).body.status, 'stale');
  });
});

test('legacy proposal databases migrate without losing decisions and accept the stale status', async () => {
  const Database = require('better-sqlite3');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-proposal-migration-'));
  const filename = path.join(dir, 'audit.db');
  const db = new Database(filename);
  const old = { id: 'legacy-pending', name: 'legacy', config: service('https://existing.example.com'),
    status: 'pending', createdAt: new Date().toISOString(), decidedAt: null, clientIp: '127.0.0.1' };
  db.exec(`CREATE TABLE service_proposals (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, proposal_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approving', 'approved', 'rejected')),
    created_at TEXT NOT NULL, decided_at TEXT);
    CREATE UNIQUE INDEX idx_service_proposals_pending_name ON service_proposals(name) WHERE status IN ('pending','approving');`);
  for (const status of ['pending', 'approved', 'rejected']) {
    const row = { ...old, id: 'legacy-' + status, name: 'legacy-' + status, status };
    db.prepare('INSERT INTO service_proposals VALUES (?, ?, ?, ?, ?, NULL)').run(row.id, row.name, JSON.stringify(row), row.status, row.createdAt);
  }
  db.close();
  try {
    await withGateway(async ({ request, config }) => {
      for (const status of ['pending', 'approved', 'rejected']) {
        assert.equal((await request(`/__proposals/services/legacy-${status}`)).body.status, status);
      }
      config.services['legacy-pending'] = { ...service('https://existing.example.com'), auth: { type: 'bearer', token: 'TEST' } };
      assert.equal((await request('/__proposals/services/legacy-pending')).body.status, 'stale');
      const id = await submit(request, 'legacy-pending', { http: { allowedMethods: ['GET'] } });
      assert.equal((await request(`/__admin/api/service-proposals/${id}/approve`, 'POST', {}, owner)).status, 200);
    }, makeConfig(), filename);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('SSH, FTP and FTPS updates retain managed credentials and keep the previous service on failed initialization', async () => {
  const { getFtpCredentialPlugin } = require('../dist/ftp-credential-plugins/loader');
  await withGateway(async ({ request, config }) => {
    for (const protocol of ['ssh', 'ftp', 'ftps']) {
      const name = `update-${protocol}`;
      const field = protocol === 'ssh' ? 'privateKey' : 'password';
      const doc = { protocol, upstream: `${protocol}://127.0.0.1:${protocol === 'ssh' ? 22 : 21}`,
        auth: { type: 'plugin', pluginPath: protocol === 'ssh' ? 'ssh-agent-key' : 'ftp-password',
          pluginConfig: { username: 'deploy', [field]: credential } }, policy: { default: 'require_approval' },
        ...(protocol === 'ssh' ? { ssh: { allowPrivateTarget: true, knownHostKey: hostKey } }
          : { ftp: { allowPrivateTarget: true, root: 'initial', ...(protocol === 'ftps' ? { tlsMode: 'explicit' } : {}) } }) };
      const created = await submit(request, name, doc);
      const slot = '/auth/pluginConfig/' + field;
      assert.equal((await request(`/__admin/api/service-proposals/${created}/approve`, 'POST', {
        allowUpstreams: true, credentials: { [slot]: { value: 'TEST-ONLY-PROTOCOL-CREDENTIAL' } },
      }, owner)).status, 200);
      const patch = protocol === 'ssh' ? { upstream: 'ssh://127.0.0.1:2222' } : { ftp: { root: 'subset' } };
      const updated = await submit(request, name, patch);
      assert.equal((await request(`/__admin/api/service-proposals/${updated}/approve`, 'POST', { confirmCredentialReuse: true }, owner)).status, 200);
      assert.equal(config.services[name].auth.pluginConfig[field], 'TEST-ONLY-PROTOCOL-CREDENTIAL');
      if (protocol === 'ssh') {
        assert.equal(config.services[name].upstream, patch.upstream);
        assert.equal(config.services[name].ssh.knownHostKey, hostKey);
      } else {
        assert.equal(config.services[name].ftp.root, 'subset');
        const previous = getFtpCredentialPlugin(name);
        const broken = await submit(request, name, { ftp: { root: 'next' } });
        assert.equal((await request(`/__admin/api/service-proposals/${broken}/approve`, 'POST', {
          credentials: { [slot]: { value: 'INVALID\nPASSWORD' } },
        }, owner)).status, 400);
        assert.equal(config.services[name].ftp.root, 'subset');
        assert.equal(getFtpCredentialPlugin(name), previous);
      }
    }
  });
});
