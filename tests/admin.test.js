const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const { createAdminRouter } = require('../dist/admin');
const { DEFAULT_FTP_GATEWAY, DEFAULT_SSH_BROKER } = require('../dist/config');

function makeConfig(strictMode) {
  return {
    admin: {
      enabled: true,
      pin: '1234',
      strictMode,
      allowedIPs: ['127.0.0.1', '::1', '::ffff:127.0.0.1'],
    },
    services: {
      existing: {
        upstream: 'https://api.example.com',
        auth: { type: 'bearer', token: 'secret' },
        policy: { default: 'require_approval' },
      },
    },
    security: {
      allowedUpstreams: [
        'api.example.com', 'ssh.example.com', 'ssh2.example.com',
        'files.example.com', '192.168.88.3',
      ],
      blockPrivateIPs: true,
      followRedirects: false,
      maxPayloadLogSize: 10240,
    },
    sshBroker: { ...DEFAULT_SSH_BROKER, enabled: true },
    ftpGateway: { ...DEFAULT_FTP_GATEWAY, enabled: true, allowInsecureHttpApi: true },
  };
}

function makeSshService({ includeToken = true } = {}) {
  const auth = {
    type: 'plugin',
    pluginPath: 'ssh-agent-key',
    pluginConfig: {
      username: 'deploy',
      privateKey: 'PRIVATE_KEY_MUST_NEVER_LEAVE_ADMIN_API',
    },
  };
  if (includeToken) auth.token = 'unused';

  return {
    protocol: 'ssh',
    upstream: 'ssh://ssh.example.com:22',
    auth,
    policy: { default: 'require_approval' },
    ssh: {
      knownHostKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC',
      allowPrivateTarget: false,
    },
  };
}

function makeFtpService() {
  return {
    protocol: 'ftps',
    upstream: 'ftps://files.example.com:990',
    auth: {
      type: 'plugin',
      pluginPath: 'ftp-password',
      pluginConfig: { username: 'deploy', password: 'MUST_NOT_LEAVE_ADMIN_API' },
    },
    policy: { default: 'require_approval' },
    ftp: { allowPrivateTarget: false, tlsMode: 'implicit' },
  };
}

function makePrivateHttpService() {
  return {
    upstream: 'https://192.168.88.3',
    auth: {
      type: 'plugin',
      pluginPath: 'vmware-esxi',
      pluginConfig: { username: 'root', password: 'MUST_NOT_LEAVE_ADMIN_API' },
    },
    policy: { default: 'require_approval' },
    http: { allowPrivateTarget: true, noCheckCertificate: true },
  };
}

function fakeApprovalManager() {
  return {
    getActiveCount: () => 0,
    getStatus: () => ({}),
    revokeApproval: () => true,
    revokeAll: () => 0,
  };
}

function fakeAudit() {
  const calls = { saveServiceOverride: [], deleteServiceOverride: [] };
  return {
    calls,
    getDashboardStats: () => ({
      totalRequestsToday: 0,
      totalRequestsWeek: 0,
      activeApprovals: 0,
      configuredServices: 0,
      requestsByService: [],
      requestsByHour: [],
      approvalStats: { approved: 0, denied: 0, timeout: 0 },
      methodBreakdown: [],
      availableServices: [],
    }),
    saveServiceOverride: (name, config) => calls.saveServiceOverride.push({ name, config }),
    deleteServiceOverride: (name) => calls.deleteServiceOverride.push(name),
    getRecentApprovals: () => [],
    getRecentRequests: () => [],
    getPairedUsers: () => [],
  };
}

async function withAdminServer(config, fn) {
  const app = express();
  app.use(express.raw({ type: '*/*', limit: '1mb' }));
  const audit = fakeAudit();
  const runtime = {
    calls: { apply: [], remove: [] },
    apply: async (name, service) => {
      runtime.calls.apply.push({ name, service });
      return structuredClone(service);
    },
    remove: (name) => runtime.calls.remove.push(name),
  };
  app.use('/__admin', createAdminRouter(config, fakeApprovalManager(), audit, undefined, runtime));
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await fn(`http://127.0.0.1:${port}/__admin`, audit, runtime);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('admin strict mode blocks service override writes', async () => {
  const config = makeConfig(true);
  await withAdminServer(config, async (base, audit) => {
    const res = await fetch(`${base}/api/services`, {
      method: 'POST',
      headers: { 'x-clawguard-pin': '1234', 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'newsvc',
        config: {
          upstream: 'https://api.example.com',
          auth: { type: 'bearer', token: 'secret' },
          policy: { default: 'require_approval' },
        },
      }),
    });

    assert.equal(res.status, 403);
    assert.equal(audit.calls.saveServiceOverride.length, 0);
    assert.equal(config.services.newsvc, undefined);
  });
});

test('admin editable mode persists service overrides and updates runtime config', async () => {
  const config = makeConfig(false);
  await withAdminServer(config, async (base, audit) => {
    const serviceConfig = {
      upstream: 'https://api.example.com',
      auth: { type: 'bearer', token: 'secret' },
      policy: { default: 'require_approval' },
    };

    const res = await fetch(`${base}/api/services`, {
      method: 'POST',
      headers: { 'x-clawguard-pin': '1234', 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'newsvc', config: serviceConfig }),
    });

    assert.equal(res.status, 200);
    assert.equal(audit.calls.saveServiceOverride.length, 1);
    assert.deepEqual(config.services.newsvc, serviceConfig);
  });
});

test('admin duplicates an SSH service server-side without exposing its private key', async () => {
  const config = makeConfig(false);
  config.services['production-ssh'] = makeSshService({ includeToken: false });
  await withAdminServer(config, async (base, audit, runtime) => {
    const list = await fetch(`${base}/api/services`, {
      headers: { 'x-clawguard-pin': '1234' },
    });
    const raw = await list.text();
    const editable = JSON.parse(raw)['production-ssh'].editableConfig;
    assert.equal(raw.includes('PRIVATE_KEY_MUST_NEVER_LEAVE_ADMIN_API'), false);
    assert.deepEqual(editable.auth.pluginConfig.privateKey, { $clawguard: 'keep-secret' });
    editable.upstream = 'ssh://ssh2.example.com:22';

    const duplicate = await fetch(`${base}/api/services/production-ssh/duplicate`, {
      method: 'POST',
      headers: { 'x-clawguard-pin': '1234', 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'production-ssh-copy', config: editable }),
    });

    assert.equal(duplicate.status, 200, await duplicate.text());
    assert.equal(config.services['production-ssh-copy'].upstream, 'ssh://ssh2.example.com:22');
    assert.equal(
      config.services['production-ssh-copy'].auth.pluginConfig.privateKey,
      'PRIVATE_KEY_MUST_NEVER_LEAVE_ADMIN_API'
    );
    assert.equal(audit.calls.saveServiceOverride.length, 1);
    assert.equal(runtime.calls.apply.length, 1);
  });
});

test('admin full-document edit supports SSH fields and preserves marked secrets', async () => {
  const config = makeConfig(false);
  config.services['production-ssh'] = makeSshService({ includeToken: false });
  await withAdminServer(config, async (base, audit) => {
    const list = await fetch(`${base}/api/services`, {
      headers: { 'x-clawguard-pin': '1234' },
    });
    const editable = (await list.json())['production-ssh'].editableConfig;
    editable.upstream = 'ssh://ssh2.example.com:22';
    editable.ssh.allowPrivateTarget = true;
    editable.policy.default = 'auto_approve';

    const res = await fetch(`${base}/api/services/production-ssh`, {
      method: 'PUT',
      headers: { 'x-clawguard-pin': '1234', 'content-type': 'application/json' },
      body: JSON.stringify({ config: editable, replace: true }),
    });

    assert.equal(res.status, 200, await res.text());
    assert.equal(config.services['production-ssh'].upstream, 'ssh://ssh2.example.com:22');
    assert.equal(config.services['production-ssh'].ssh.allowPrivateTarget, true);
    assert.equal(config.services['production-ssh'].policy.default, 'auto_approve');
    assert.equal(
      config.services['production-ssh'].auth.pluginConfig.privateKey,
      'PRIVATE_KEY_MUST_NEVER_LEAVE_ADMIN_API'
    );
    assert.equal(audit.calls.saveServiceOverride.length, 1);
  });
});

test('admin duplicates FTP/FTPS services with every protocol field', async () => {
  const config = makeConfig(false);
  config.services.files = makeFtpService();
  await withAdminServer(config, async (base, audit) => {
    const list = await fetch(`${base}/api/services`, {
      headers: { 'x-clawguard-pin': '1234' },
    });
    const editable = (await list.json()).files.editableConfig;
    editable.ftp.root = 'archive';
    const res = await fetch(`${base}/api/services/files/duplicate`, {
      method: 'POST',
      headers: { 'x-clawguard-pin': '1234', 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'files-copy', config: editable }),
    });

    assert.equal(res.status, 200, await res.text());
    assert.equal(config.services['files-copy'].ftp.tlsMode, 'implicit');
    assert.equal(config.services['files-copy'].ftp.root, 'archive');
    assert.equal(config.services['files-copy'].auth.pluginConfig.password, 'MUST_NOT_LEAVE_ADMIN_API');
    assert.equal(audit.calls.saveServiceOverride.length, 1);
  });
});

test('admin can edit private-target HTTP services while redacting plugin config values', async () => {
  const config = makeConfig(false);
  config.services['vmware-esxi'] = makePrivateHttpService();

  await withAdminServer(config, async (base, audit) => {
    const list = await fetch(`${base}/api/services`, {
      headers: { 'x-clawguard-pin': '1234' },
    });
    const raw = await list.text();
    const editable = JSON.parse(raw)['vmware-esxi'].editableConfig;
    assert.equal(raw.includes('MUST_NOT_LEAVE_ADMIN_API'), false);
    editable.policy.default = 'auto_approve';

    const update = await fetch(`${base}/api/services/vmware-esxi`, {
      method: 'PUT',
      headers: { 'x-clawguard-pin': '1234', 'content-type': 'application/json' },
      body: JSON.stringify({ config: editable, replace: true }),
    });
    assert.equal(update.status, 200, await update.text());
    assert.equal(config.services['vmware-esxi'].policy.default, 'auto_approve');
    assert.equal(config.services['vmware-esxi'].auth.pluginConfig.password, 'MUST_NOT_LEAVE_ADMIN_API');
    assert.equal(audit.calls.saveServiceOverride.length, 1);
  });
});

test('admin GET exposes a complete redacted SSH document, never credential values', async () => {
  const config = makeConfig(false);
  config.services['production-ssh'] = makeSshService({ includeToken: false });

  await withAdminServer(config, async (base) => {
    const res = await fetch(`${base}/api/services`, {
      headers: { 'x-clawguard-pin': '1234' },
    });

    const raw = await res.text();
    const services = JSON.parse(raw);
    const service = services['production-ssh'];
    assert.equal(service.protocol, 'ssh');
    assert.equal(service.editableConfig.ssh.knownHostKey, config.services['production-ssh'].ssh.knownHostKey);
    assert.deepEqual(service.editableConfig.auth.pluginConfig.username, { $clawguard: 'keep-secret' });
    assert.deepEqual(service.editableConfig.auth.pluginConfig.privateKey, { $clawguard: 'keep-secret' });
    assert.equal(raw.includes('PRIVATE_KEY_MUST_NEVER_LEAVE_ADMIN_API'), false);
    assert.equal(raw.includes('deploy'), false);
  });
});

test('admin editable mode rejects unsupported service protocols', async () => {
  const config = makeConfig(false);
  await withAdminServer(config, async (base, audit) => {
    const res = await fetch(`${base}/api/services`, {
      method: 'POST',
      headers: { 'x-clawguard-pin': '1234', 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'invalid-protocol',
        config: {
          protocol: 'bogus',
          upstream: 'https://api.example.com',
          auth: { type: 'bearer', token: 'secret' },
          policy: { default: 'require_approval' },
        },
      }),
    });

    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /Unsupported service protocol/i);
    assert.equal(audit.calls.saveServiceOverride.length, 0);
    assert.equal(config.services['invalid-protocol'], undefined);
  });
});

test('admin malformed service documents return validation errors instead of crashing the route', async () => {
  const config = makeConfig(false);
  await withAdminServer(config, async (base, audit) => {
    const res = await fetch(`${base}/api/services`, {
      method: 'POST',
      headers: { 'x-clawguard-pin': '1234', 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'malformed',
        config: {
          upstream: null,
          http: { noCheckCertificate: true },
        },
      }),
    });

    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /service\.upstream|service\.auth|service\.policy/i);
    assert.equal(audit.calls.saveServiceOverride.length, 0);
  });
});

test('admin editable mode deletes SSH services and unloads their runtime plugin', async () => {
  const config = makeConfig(false);
  config.services['production-ssh'] = makeSshService();

  await withAdminServer(config, async (base, audit, runtime) => {
    const res = await fetch(`${base}/api/services/production-ssh`, {
      method: 'DELETE',
      headers: { 'x-clawguard-pin': '1234' },
    });

    assert.equal(res.status, 200);
    assert.equal(audit.calls.deleteServiceOverride.length, 1);
    assert.equal(config.services['production-ssh'], undefined);
    assert.deepEqual(runtime.calls.remove, ['production-ssh']);
  });
});

test('admin strict mode also blocks the duplicate endpoint', async () => {
  const config = makeConfig(true);
  config.services['production-ssh'] = makeSshService();
  await withAdminServer(config, async (base, audit) => {
    const res = await fetch(`${base}/api/services/production-ssh/duplicate`, {
      method: 'POST',
      headers: { 'x-clawguard-pin': '1234', 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'copy', config: makeSshService() }),
    });
    assert.equal(res.status, 403);
    assert.equal(audit.calls.saveServiceOverride.length, 0);
  });
});
