const test = require('node:test');
const assert = require('node:assert/strict');

const { DEFAULT_FTP_GATEWAY } = require('../dist/config');
const { FtpBroker, FtpBrokerError } = require('../dist/ftp-broker');

function config(overrides = {}) {
  const base = {
    server: { port: 9090, agentKey: 'agent-key' },
    services: {
      files: {
        protocol: 'ftp',
        upstream: 'ftp://files.example.com:21',
        auth: { type: 'plugin', pluginPath: 'ftp-password' },
        policy: { default: 'require_approval' },
        ftp: { allowPrivateTarget: false, root: 'dropbox' },
      },
    },
    security: { allowedUpstreams: ['files.example.com'], blockPrivateIPs: true },
    ftpGateway: {
      ...DEFAULT_FTP_GATEWAY,
      enabled: true,
      publicHost: 'gateway.example.com',
      approvalTimeoutMs: 5000,
      credentialTimeoutMs: 5000,
      sessionTtlSeconds: 60,
    },
  };
  return {
    ...base,
    ...overrides,
    services: { ...base.services, ...(overrides.services || {}) },
    ftpGateway: { ...base.ftpGateway, ...(overrides.ftpGateway || {}) },
  };
}

function audit() {
  const starts = [];
  const updates = [];
  const finals = [];
  return {
    starts, updates, finals,
    startFtpSession(entry) { starts.push(structuredClone(entry)); },
    updateFtpSession(id, update) { updates.push({ id, update: structuredClone(update) }); return true; },
    finalizeFtpSession(id, final) { finals.push({ id, final: structuredClone(final) }); return true; },
  };
}

function harness(options = {}) {
  const records = audit();
  const approvalCalls = [];
  const pluginCalls = [];
  const openCalls = [];
  const closeCalls = [];
  const approvalManager = {
    async checkFtpSessionApproval(...args) {
      approvalCalls.push(args);
      if (options.approve) return options.approve(...args);
      return options.approved === false ? false : (options.accessMode || 'read_write');
    },
  };
  const plugin = options.plugin === null ? undefined : {
    name: 'fake-ftp-plugin',
    async getCredentials(ctx) {
      pluginCalls.push(ctx.serviceName);
      if (options.getCredentials) return options.getCredentials(ctx);
      return { username: 'upstream-user', password: Buffer.from('real-upstream-password') };
    },
  };
  const gateway = {
    async openSession(request) {
      openCalls.push(structuredClone(request));
      if (options.openSession) return options.openSession(request);
      return {
        sessionId: request.sessionId,
        controlPort: 21210,
        passivePortStart: 30000,
        passivePortEnd: 30009,
      };
    },
    async closeSession(id) { closeCalls.push(id); return true; },
  };
  const broker = new FtpBroker(config(options.config), {
    approvalManager,
    audit: options.audit || records,
    gateway,
    credentialPluginForService: () => plugin,
    validateTarget: async () => ({ valid: true, resolvedAddresses: ['203.0.113.42'] }),
  });
  return { broker, records, approvalCalls, pluginCalls, openCalls, closeCalls };
}

test('approved FTP lease injects upstream credentials only into the sidecar request', async () => {
  const h = harness();
  const lease = await h.broker.openSession('files', '192.0.2.10', { user: 'agent', reason: 'upload' });
  assert.equal(lease.protocol, 'ftp');
  assert.equal(lease.host, 'gateway.example.com');
  assert.equal(lease.port, 21210);
  assert.equal(lease.tlsMode, 'none');
  assert.equal(lease.accessMode, 'read_write');
  assert.notEqual(lease.password, 'real-upstream-password');
  assert.equal('upstreamCredentials' in lease, false);

  assert.equal(h.approvalCalls.length, 1);
  assert.equal(h.pluginCalls.length, 1);
  assert.equal(h.openCalls.length, 1);
  assert.deepEqual(h.openCalls[0].upstream.resolvedAddresses, ['203.0.113.42']);
  assert.equal(h.openCalls[0].upstream.root, 'dropbox');
  assert.equal(h.openCalls[0].accessMode, 'read_write');
  assert.equal(Buffer.from(h.openCalls[0].upstreamCredentials.passwordBase64, 'base64').toString(), 'real-upstream-password');
  assert.equal(h.openCalls[0].gatewayCredentials.password, lease.password);

  assert.equal(await h.broker.closeSession(lease.id), true);
  assert.deepEqual(h.closeCalls, [lease.id]);
  assert.equal(h.records.finals.at(-1).final.outcome, 'closed');
  await h.broker.close();
});

test('denied FTP lease never retrieves or forwards credentials', async () => {
  const h = harness({ approved: false });
  await assert.rejects(
    () => h.broker.openSession('files', '192.0.2.10'),
    (err) => err instanceof FtpBrokerError && err.status === 403
  );
  assert.equal(h.pluginCalls.length, 0);
  assert.equal(h.openCalls.length, 0);
  assert.equal(h.records.finals.at(-1).final.outcome, 'denied');
  await h.broker.close();
});

test('FTPS lease preserves upstream implicit mode while exposing explicit TLS to the client', async () => {
  const ftps = {
    protocol: 'ftps',
    upstream: 'ftps://files.example.com:990',
    auth: { type: 'plugin', pluginPath: 'ftp-password' },
    policy: { default: 'require_approval' },
    ftp: { allowPrivateTarget: false, tlsMode: 'implicit' },
  };
  const h = harness({ config: { services: { files: ftps } }, accessMode: 'read_only' });
  const lease = await h.broker.openSession('files', '192.0.2.10');
  assert.equal(lease.protocol, 'ftps');
  assert.equal(lease.tlsMode, 'explicit');
  assert.equal(lease.accessMode, 'read_only');
  assert.equal(h.openCalls[0].accessMode, 'read_only');
  assert.equal(h.openCalls[0].upstream.tlsMode, 'implicit');
  await h.broker.close();
});

test('unknown services and capacity exhaustion fail before approval', async () => {
  const h = harness({ config: { ftpGateway: { maxConcurrentSessions: 1 } } });
  await assert.rejects(() => h.broker.openSession('unknown', '192.0.2.10'), /Unknown FTP/);
  const first = await h.broker.openSession('files', '192.0.2.10');
  await assert.rejects(
    () => h.broker.openSession('files', '192.0.2.11'),
    (err) => err.status === 429
  );
  assert.equal(h.approvalCalls.length, 1);
  await h.broker.closeSession(first.id);
  await h.broker.close();
});

test('credential timeout fails closed and wipes a password returned later by a non-cooperative plugin', async () => {
  const latePassword = Buffer.from('late-upstream-password');
  const h = harness({
    config: { ftpGateway: { credentialTimeoutMs: 10 } },
    getCredentials: async () => {
      await new Promise((resolve) => setTimeout(resolve, 30));
      return { username: 'late-user', password: latePassword };
    },
  });
  await assert.rejects(
    () => h.broker.openSession('files', '192.0.2.10'),
    (err) => err instanceof FtpBrokerError && err.status === 503
  );
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.ok(latePassword.every((byte) => byte === 0));
  assert.equal(h.openCalls.length, 0);
  assert.equal(h.records.finals.at(-1).final.outcome, 'credential_timeout');
  await h.broker.close();
});

test('client disconnect after sidecar activation rolls back the lease and returns capacity', async () => {
  const controller = new AbortController();
  const h = harness({
    config: { ftpGateway: { maxConcurrentSessions: 1 } },
    openSession: async (request) => {
      controller.abort(new Error('client disconnected'));
      return {
        sessionId: request.sessionId,
        controlPort: 21210,
        passivePortStart: 30000,
        passivePortEnd: 30009,
      };
    },
  });
  await assert.rejects(
    () => h.broker.openSession('files', '192.0.2.10', undefined, controller.signal),
    (err) => err instanceof FtpBrokerError && err.status === 499
  );
  assert.deepEqual(h.closeCalls, [h.openCalls[0].sessionId]);
  assert.equal(h.records.finals.at(-1).final.outcome, 'client_disconnected');

  // The failed setup must not strand the sole reservation.
  const lease = await h.broker.openSession('files', '192.0.2.11');
  await h.broker.closeSession(lease.id);
  await h.broker.close();
});

test('transport rejection after an ambiguous sidecar activation sends compensating cleanup', async () => {
  let attempts = 0;
  const h = harness({
    config: { ftpGateway: { maxConcurrentSessions: 1 } },
    openSession: async (request) => {
      attempts++;
      // Model the real sidecar committing the child before its HTTP 201 is
      // consumed, followed by a client-side Unix-socket transport failure.
      if (attempts === 1) throw new Error('response transport failed after remote commit');
      return {
        sessionId: request.sessionId,
        controlPort: 21210,
        passivePortStart: 30000,
        passivePortEnd: 30009,
      };
    },
  });

  await assert.rejects(
    () => h.broker.openSession('files', '192.0.2.10'),
    (err) => err instanceof FtpBrokerError && err.status === 503
  );
  assert.deepEqual(h.closeCalls, [h.openCalls[0].sessionId]);

  // Ambiguous failure must return both the remote and local capacity slots.
  const lease = await h.broker.openSession('files', '192.0.2.11');
  await h.broker.closeSession(lease.id);
  await h.broker.close();
});

test('audit activation failure closes the already-created sidecar lease', async () => {
  const records = audit();
  const failingAudit = {
    ...records,
    updateFtpSession(id, update) {
      records.updates.push({ id, update: structuredClone(update) });
      if (update.outcome === 'active') throw new Error('audit unavailable');
      return true;
    },
  };
  const h = harness({ audit: failingAudit });
  await assert.rejects(
    () => h.broker.openSession('files', '192.0.2.10'),
    (err) => err instanceof FtpBrokerError && err.status === 503
  );
  assert.deepEqual(h.closeCalls, [h.openCalls[0].sessionId]);
  assert.equal(h.openCalls[0].upstreamCredentials.passwordBase64.length > 0, true);
  await h.broker.close();
});
