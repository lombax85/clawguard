const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { SshBroker } = require('../dist/ssh-broker');

const KNOWN_HOST_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeBrokerTestKey';
const RESOLVED_TARGET = '203.0.113.42';

function currentUid() {
  return typeof process.getuid === 'function' ? process.getuid() : 0;
}

function currentGid() {
  return typeof process.getgid === 'function' ? process.getgid() : 0;
}

function makeConfig(tmpDir, overrides = {}) {
  const runtimeDir = path.join(tmpDir, 'runtime');
  const base = {
    server: { port: 9090, agentKey: 'test-agent-key' },
    services: {
      production: {
        protocol: 'ssh',
        upstream: 'ssh://configured.internal:2222',
        auth: {
          type: 'plugin',
          token: 'unused',
          pluginPath: 'ssh-agent-key',
          pluginConfig: { username: 'deploy', privateKey: 'resolved-elsewhere' },
        },
        policy: { default: 'require_approval' },
        ssh: { knownHostKey: KNOWN_HOST_KEY, allowPrivateTarget: false },
      },
      web: {
        protocol: 'http',
        upstream: 'https://example.com',
        auth: { type: 'bearer', token: 'unused' },
        policy: { default: 'require_approval' },
      },
    },
    security: {
      allowedUpstreams: ['configured.internal', 'example.com'],
      blockPrivateIPs: true,
      followRedirects: false,
      maxPayloadLogSize: 10240,
    },
    admin: { enabled: false, pin: '', allowedIPs: [], strictMode: true },
    proxy: { enabled: false, caDir: './data/ca', discovery: false, discoveryPolicy: 'block' },
    transparentProxy: { enabled: false, httpPort: 8080, httpsPort: 8443 },
    audit: { type: 'sqlite', path: path.join(tmpDir, 'audit.db'), logPayload: false },
    sshBroker: {
      enabled: true,
      runtimeDir,
      socketPath: path.join(runtimeDir, 'broker.sock'),
      gatewayUid: currentUid(),
      gatewayGid: currentGid(),
      approvalTimeoutMs: 500,
      credentialTimeoutMs: 30000,
      leaseTtlSeconds: 60,
      maxSessionSeconds: 3600,
      sshAgentPath: '/usr/bin/ssh-agent',
      sshAddPath: '/usr/bin/ssh-add',
      maxConcurrentLeases: 2,
    },
  };

  return {
    ...base,
    ...overrides,
    services: { ...base.services, ...(overrides.services || {}) },
    security: { ...base.security, ...(overrides.security || {}) },
    sshBroker: { ...base.sshBroker, ...(overrides.sshBroker || {}) },
  };
}

function makeAudit() {
  const starts = [];
  const updates = [];
  const finals = [];
  return {
    starts,
    updates,
    finals,
    startSshSession(entry) {
      starts.push(structuredClone(entry));
    },
    updateSshSession(id, update) {
      updates.push({ id, update: structuredClone(update) });
      return true;
    },
    finalizeSshSession(id, final) {
      finals.push({ id, final: structuredClone(final) });
      return true;
    },
  };
}

function makeHarness(tmpDir, options = {}) {
  const audit = options.audit || makeAudit();
  const approvalCalls = [];
  const pluginCalls = [];
  const createCalls = [];
  const releaseCalls = [];
  let leaseCounter = 0;

  const approvalManager = {
    async checkSshSessionApproval(...args) {
      approvalCalls.push(args);
      if (options.approve) return options.approve(...args);
      return options.approved !== false;
    },
  };

  const credentialPlugin = options.plugin === null ? undefined : {
    name: 'fake-ssh-credential',
    async getCredentials(ctx) {
      pluginCalls.push({ serviceName: ctx.serviceName });
      if (options.getCredentials) return options.getCredentials(ctx);
      if (options.pluginError) throw options.pluginError;
      if (options.credentials) return options.credentials();
      return { username: 'deploy', privateKey: Buffer.from('fake-private-key') };
    },
  };

  const leaseManager = {
    async create(privateKey) {
      createCalls.push(Buffer.isBuffer(privateKey) ? Buffer.from(privateKey) : privateKey);
      if (options.leaseError) throw options.leaseError;
      leaseCounter += 1;
      if (options.createLease) return options.createLease(leaseCounter, privateKey);
      return {
        id: `agent-lease-${leaseCounter}`,
        socketPath: `/run/fake-agent-${leaseCounter}.sock`,
        expiresAt: Date.now() + 60_000,
      };
    },
    async release(id) {
      releaseCalls.push(id);
      return true;
    },
  };

  const config = makeConfig(tmpDir, options.config || {});
  const broker = new SshBroker(config, {
    approvalManager,
    audit,
    leaseManager,
    credentialPluginForService(serviceName) {
      if (options.pluginLookup) return options.pluginLookup(serviceName, credentialPlugin);
      return credentialPlugin;
    },
    validateTarget: options.validateTarget || (async () => ({
      valid: true,
      resolvedAddresses: [RESOLVED_TARGET],
    })),
    sessionCompletionGraceMs: options.sessionCompletionGraceMs,
    sessionActivationTimeoutMs: options.sessionActivationTimeoutMs,
    allowNonRootForTests: true,
  });

  return {
    audit,
    approvalCalls,
    pluginCalls,
    createCalls,
    releaseCalls,
    config,
    broker,
  };
}

function request(socketPath, requestPath, body, options = {}) {
  const rawBody = options.rawBody !== undefined
    ? options.rawBody
    : JSON.stringify(body);
  const headers = {
    'content-type': options.contentType || 'application/json',
    'content-length': Buffer.byteLength(rawBody),
    ...(options.headers || {}),
  };

  return new Promise((resolve, reject) => {
    const req = http.request({
      socketPath,
      path: requestPath,
      method: options.method || 'POST',
      headers,
      agent: false,
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let json;
        try {
          json = raw ? JSON.parse(raw) : undefined;
        } catch {
          json = undefined;
        }
        resolve({ status: res.statusCode, headers: res.headers, raw, body: json });
      });
    });
    req.once('error', reject);
    req.end(rawBody);
  });
}

function openSession(socketPath, body = {}) {
  return request(socketPath, '/session', {
    service: 'production',
    clientIp: '192.0.2.10',
    action: 'shell',
    ...body,
  });
}

async function waitFor(predicate, timeoutMs = 1000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail('timed out waiting for expected broker state');
}

async function closeHarness(harness, tmpDir) {
  try {
    await harness.broker.close();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

test('approved session returns only the fixed resolved target and completion releases lease with audit', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
  const returnedKey = Buffer.from('fake-private-key');
  const harness = makeHarness(tmpDir, {
    credentials: () => ({ username: 'deploy', privateKey: returnedKey }),
  });
  try {
    await harness.broker.start();
    const opened = await openSession(harness.config.sshBroker.socketPath, { action: 'exec' });

    assert.equal(opened.status, 201);
    assert.equal(opened.headers['cache-control'], 'no-store');
    assert.deepEqual(Object.keys(opened.body).sort(), ['agentSocket', 'expiresAt', 'leaseId', 'maxSessionSeconds', 'target']);
    assert.equal(opened.body.maxSessionSeconds, 3600);
    assert.deepEqual(opened.body.target, {
      host: RESOLVED_TARGET,
      port: 2222,
      username: 'deploy',
      hostKeyAlias: 'clawguard-production',
      knownHostsLine: `clawguard-production ${KNOWN_HOST_KEY}`,
    });
    assert.match(opened.body.leaseId, /^[A-Za-z0-9_-]{32,64}$/);
    assert.deepEqual(harness.pluginCalls, [{ serviceName: 'production' }]);
    assert.equal(harness.createCalls[0].toString(), 'fake-private-key');
    assert.equal(returnedKey.every((byte) => byte === 0), true, 'broker zeroes returned Buffer');

    assert.equal(harness.approvalCalls.length, 1);
    assert.equal(harness.approvalCalls[0][0], 'production');
    assert.equal(harness.approvalCalls[0][2], 'exec configured.internal:2222');
    assert.equal(harness.approvalCalls[0][3], '192.0.2.10');

    const completed = await request(
      harness.config.sshBroker.socketPath,
      `/session/${opened.body.leaseId}/complete`,
      { exitStatus: 0 }
    );
    assert.equal(completed.status, 200);
    assert.deepEqual(completed.body, { ok: true });
    assert.deepEqual(harness.releaseCalls, ['agent-lease-1']);

    const final = harness.audit.finals.find((entry) => entry.id === opened.body.leaseId);
    assert.deepEqual(final.final, {
      outcome: 'completed',
      exitStatus: 0,
      closeReason: 'wrapper_completed',
    });
    assert.equal(harness.audit.starts[0].service, 'production');
    assert.equal(harness.audit.starts[0].action, 'exec');
    assert.equal(
      harness.audit.updates.some((entry) =>
        entry.update.targetHost === 'configured.internal' && entry.update.targetPort === 2222),
      true
    );
  } finally {
    await closeHarness(harness, tmpDir);
  }
});

test('denied approval never calls credential plugin or lease manager', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
  const harness = makeHarness(tmpDir, { approved: false });
  try {
    await harness.broker.start();
    const response = await openSession(harness.config.sshBroker.socketPath);

    assert.equal(response.status, 403);
    assert.deepEqual(response.body, { error: 'SSH session approval denied or unavailable' });
    assert.equal(harness.pluginCalls.length, 0);
    assert.equal(harness.createCalls.length, 0);
    assert.equal(harness.releaseCalls.length, 0);
    assert.equal(harness.audit.finals.at(-1).final.outcome, 'denied');
  } finally {
    await closeHarness(harness, tmpDir);
  }
});

test('unknown, non-SSH, and extra request fields fail closed before credentials', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
  const harness = makeHarness(tmpDir);
  try {
    await harness.broker.start();
    const unknown = await openSession(harness.config.sshBroker.socketPath, { service: 'missing' });
    const nonSsh = await openSession(harness.config.sshBroker.socketPath, { service: 'web' });
    const injectedTarget = await openSession(harness.config.sshBroker.socketPath, {
      host: 'attacker.example',
      port: 22,
    });

    assert.equal(unknown.status, 404);
    assert.equal(nonSsh.status, 404);
    assert.equal(injectedTarget.status, 400);
    assert.deepEqual(injectedTarget.body, { error: 'invalid session request' });
    assert.equal(harness.approvalCalls.length, 0);
    assert.equal(harness.pluginCalls.length, 0);
    assert.equal(harness.createCalls.length, 0);
    assert.equal(harness.audit.starts.length, 2, 'malformed body is rejected before audit session creation');
    assert.deepEqual(
      harness.audit.finals.map((entry) => entry.final.outcome),
      ['unknown_service', 'unknown_service']
    );
  } finally {
    await closeHarness(harness, tmpDir);
  }
});

test('a pending approval reserves capacity against concurrent sessions', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
  let resolveApproval;
  let signalApprovalStarted;
  const approvalStarted = new Promise((resolve) => { signalApprovalStarted = resolve; });
  const harness = makeHarness(tmpDir, {
    config: { sshBroker: { maxConcurrentLeases: 1 } },
    approve: () => {
      signalApprovalStarted();
      return new Promise((resolve) => { resolveApproval = resolve; });
    },
  });
  try {
    await harness.broker.start();
    const firstPromise = openSession(harness.config.sshBroker.socketPath);
    await approvalStarted;

    const second = await openSession(harness.config.sshBroker.socketPath, { action: 'exec' });
    assert.equal(second.status, 429);
    assert.deepEqual(second.body, { error: 'SSH gateway is at session capacity' });
    assert.equal(harness.approvalCalls.length, 1);
    assert.equal(harness.pluginCalls.length, 0);

    resolveApproval(true);
    const first = await firstPromise;
    assert.equal(first.status, 201);
    assert.equal(harness.pluginCalls.length, 1);
    assert.equal(
      harness.audit.finals.some((entry) => entry.final.outcome === 'capacity_denied'),
      true
    );

    const activated = await request(
      harness.config.sshBroker.socketPath,
      `/session/${first.body.leaseId}/activate`,
      {}
    );
    assert.equal(activated.status, 200);
    assert.deepEqual(activated.body, { ok: true });

    const completed = await request(
      harness.config.sshBroker.socketPath,
      `/session/${first.body.leaseId}/complete`,
      { exitStatus: 0 }
    );
    assert.equal(completed.status, 200);
  } finally {
    await closeHarness(harness, tmpDir);
  }
});

test('target validation failure stops before approval, credentials, and lease', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
  const harness = makeHarness(tmpDir, {
    validateTarget: async () => ({ valid: false, reason: 'blocked target' }),
  });
  try {
    await harness.broker.start();
    const response = await openSession(harness.config.sshBroker.socketPath);

    assert.equal(response.status, 502);
    assert.deepEqual(response.body, { error: 'SSH target validation failed' });
    assert.equal(harness.approvalCalls.length, 0);
    assert.equal(harness.pluginCalls.length, 0);
    assert.equal(harness.createCalls.length, 0);
    assert.equal(harness.audit.finals.at(-1).final.outcome, 'target_validation_failed');
  } finally {
    await closeHarness(harness, tmpDir);
  }
});

test('missing or failing credential plugin and lease failure are sanitized and audited', async (t) => {
  async function runFailure(name, options, expectedStatus, expectedOutcome) {
    await t.test(name, async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
      const harness = makeHarness(tmpDir, options);
      try {
        await harness.broker.start();
        const response = await openSession(harness.config.sshBroker.socketPath);
        assert.equal(response.status, expectedStatus);
        assert.equal(response.raw.includes('sensitive failure detail'), false);
        assert.equal(harness.audit.finals.at(-1).final.outcome, expectedOutcome);
      } finally {
        await closeHarness(harness, tmpDir);
      }
    });
  }

  await runFailure(
    'missing plugin',
    { plugin: null },
    503,
    'credential_plugin_unavailable'
  );
  await runFailure(
    'plugin throws',
    { pluginError: new Error('sensitive failure detail') },
    502,
    'credential_lease_failed'
  );
  await runFailure(
    'lease creation throws',
    { leaseError: new Error('sensitive failure detail') },
    502,
    'credential_lease_failed'
  );
});

test('broker safely replaces an unconnected stale Unix socket', async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
  const harness = makeHarness(tmpDir);
  fs.mkdirSync(harness.config.sshBroker.runtimeDir, { recursive: true });
  const socketPath = harness.config.sshBroker.socketPath;
  const childScript = `
    const net = require('node:net');
    const server = net.createServer();
    server.listen(process.argv[1], () => process.stdout.write('ready\\n'));
    setInterval(() => {}, 1000);
  `;
  const child = spawn(process.execPath, ['-e', childScript, socketPath], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  try {
    await new Promise((resolve, reject) => {
      let output = '';
      const timer = setTimeout(() => reject(new Error('stale socket fixture did not start')), 2000);
      child.once('error', reject);
      child.stdout.on('data', (chunk) => {
        output += chunk.toString('utf8');
        if (output.includes('ready\n')) {
          clearTimeout(timer);
          resolve();
        }
      });
    });
    child.kill('SIGKILL');
    await new Promise((resolve) => child.once('exit', resolve));
    if (!fs.existsSync(socketPath)) {
      t.skip('platform removes Unix socket path when listener is killed');
      return;
    }

    await harness.broker.start();
    const response = await openSession(socketPath);
    assert.equal(response.status, 201);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await closeHarness(harness, tmpDir);
  }
});

test('broker refuses regular files and symlinks at its socket path', async (t) => {
  async function assertUnsafePath(name, prepare) {
    await t.test(name, async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
      const harness = makeHarness(tmpDir);
      fs.mkdirSync(harness.config.sshBroker.runtimeDir, { recursive: true });
      prepare(harness.config.sshBroker.socketPath, tmpDir);
      try {
        await assert.rejects(
          () => harness.broker.start(),
          /Refusing to replace unsafe SSH broker socket path/
        );
        assert.equal(harness.approvalCalls.length, 0);
      } finally {
        await closeHarness(harness, tmpDir);
      }
    });
  }

  await assertUnsafePath('regular file', (socketPath) => {
    fs.writeFileSync(socketPath, 'not a socket');
  });
  await assertUnsafePath('symbolic link', (socketPath, tmpDir) => {
    const target = path.join(tmpDir, 'symlink-target');
    fs.writeFileSync(target, 'target');
    fs.symlinkSync(target, socketPath);
  });
});

test('lease expiry removes signing capability but preserves session completion and capacity', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
  const harness = makeHarness(tmpDir, {
    config: { sshBroker: { maxConcurrentLeases: 1 } },
    createLease: (counter) => ({
      id: `short-lease-${counter}`,
      socketPath: `/run/short-agent-${counter}.sock`,
      expiresAt: Date.now() + 40,
    }),
  });
  try {
    await harness.broker.start();
    const opened = await openSession(harness.config.sshBroker.socketPath);
    assert.equal(opened.status, 201);

    await waitFor(() => harness.releaseCalls.length === 1);
    assert.deepEqual(harness.releaseCalls, ['short-lease-1']);
    assert.equal(
      harness.audit.updates.some((entry) =>
        entry.id === opened.body.leaseId && entry.update.outcome === 'active_lease_expired'),
      true
    );
    assert.equal(
      harness.audit.finals.some((entry) => entry.id === opened.body.leaseId),
      false
    );

    // The signing key is gone, but an authenticated SSH session still owns
    // its capacity slot until the wrapper reports the real terminal outcome.
    const capacityDenied = await openSession(harness.config.sshBroker.socketPath);
    assert.equal(capacityDenied.status, 429);

    const completion = await request(
      harness.config.sshBroker.socketPath,
      `/session/${opened.body.leaseId}/complete`,
      { exitStatus: 0 }
    );
    assert.equal(completion.status, 200);
    assert.equal(
      harness.audit.finals.some((entry) =>
        entry.id === opened.body.leaseId && entry.final.outcome === 'completed'),
      true
    );
  } finally {
    await closeHarness(harness, tmpDir);
  }
});

test('lost completion is bounded by the maximum session duration and returns capacity', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
  const harness = makeHarness(tmpDir, {
    config: { sshBroker: { maxConcurrentLeases: 1, maxSessionSeconds: 1 } },
    sessionCompletionGraceMs: 10,
  });
  try {
    await harness.broker.start();
    const opened = await openSession(harness.config.sshBroker.socketPath);
    assert.equal(opened.status, 201);

    await waitFor(() => harness.audit.finals.some((entry) =>
      entry.id === opened.body.leaseId && entry.final.outcome === 'session_timeout'), 1500);
    assert.deepEqual(harness.releaseCalls, ['agent-lease-1']);

    const staleCompletion = await request(
      harness.config.sshBroker.socketPath,
      `/session/${opened.body.leaseId}/complete`,
      { exitStatus: 0 }
    );
    assert.equal(staleCompletion.status, 404);

    const replacement = await openSession(harness.config.sshBroker.socketPath);
    assert.equal(replacement.status, 201);
  } finally {
    await closeHarness(harness, tmpDir);
  }
});

test('unacknowledged wrapper handoff promptly releases lease and capacity', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
  const harness = makeHarness(tmpDir, {
    config: { sshBroker: { maxConcurrentLeases: 1 } },
    sessionActivationTimeoutMs: 25,
  });
  try {
    await harness.broker.start();
    const opened = await openSession(harness.config.sshBroker.socketPath);
    assert.equal(opened.status, 201);

    await waitFor(() => harness.audit.finals.some((entry) =>
      entry.id === opened.body.leaseId && entry.final.outcome === 'activation_timeout'));
    assert.deepEqual(harness.releaseCalls, ['agent-lease-1']);

    const replacement = await openSession(harness.config.sshBroker.socketPath);
    assert.equal(replacement.status, 201);
    const activated = await request(
      harness.config.sshBroker.socketPath,
      `/session/${replacement.body.leaseId}/activate`,
      {}
    );
    assert.equal(activated.status, 200);
    const completed = await request(
      harness.config.sshBroker.socketPath,
      `/session/${replacement.body.leaseId}/complete`,
      { exitStatus: 0 }
    );
    assert.equal(completed.status, 200);
  } finally {
    await closeHarness(harness, tmpDir);
  }
});

test('shutdown aborts and finalizes an approval request in flight', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
  const harness = makeHarness(tmpDir, {
    approve: () => new Promise(() => {}),
  });
  try {
    await harness.broker.start();
    const opening = openSession(harness.config.sshBroker.socketPath).catch(() => null);
    await waitFor(() => harness.audit.updates.some((entry) =>
      entry.update.outcome === 'pending_approval'));

    await harness.broker.close();
    await opening;
    assert.equal(harness.pluginCalls.length, 0);
    assert.equal(harness.createCalls.length, 0);
    assert.equal(harness.audit.finals.some((entry) =>
      entry.final.outcome === 'gateway_shutdown'
      && entry.final.closeReason === 'gateway_shutdown_during_session_setup'
      && entry.final.approved === false), true);
  } finally {
    await harness.broker.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('shutdown aborts a stuck credential plugin and wipes a late Buffer result', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
  let resolveCredentials;
  let pluginSignal;
  const deferredCredentials = new Promise((resolve) => { resolveCredentials = resolve; });
  const harness = makeHarness(tmpDir, {
    config: { sshBroker: { credentialTimeoutMs: 60000 } },
    getCredentials(ctx) {
      pluginSignal = ctx.signal;
      return deferredCredentials;
    },
  });
  try {
    await harness.broker.start();
    const opening = openSession(harness.config.sshBroker.socketPath).catch(() => null);
    await waitFor(() => harness.pluginCalls.length === 1);

    await harness.broker.close();
    await opening;
    assert.equal(pluginSignal.aborted, true);
    assert.equal(harness.createCalls.length, 0);
    assert.equal(harness.audit.finals.some((entry) =>
      entry.final.outcome === 'gateway_shutdown'
      && entry.final.closeReason === 'gateway_shutdown_during_session_setup'
      && entry.final.approved === true), true);

    const lateKey = Buffer.from('late-private-key');
    resolveCredentials({ username: 'deploy', privateKey: lateKey });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(lateKey.every((byte) => byte === 0), true);
  } finally {
    await harness.broker.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('credential retrieval timeout fails closed and returns reserved capacity', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
  const harness = makeHarness(tmpDir, {
    config: {
      sshBroker: { credentialTimeoutMs: 20, maxConcurrentLeases: 1 },
    },
    getCredentials: () => new Promise(() => {}),
  });
  try {
    await harness.broker.start();
    const first = await openSession(harness.config.sshBroker.socketPath);
    assert.equal(first.status, 502);
    assert.equal(harness.audit.finals.some((entry) =>
      entry.final.outcome === 'credential_lease_failed'
      && entry.final.approved === true), true);

    const second = await openSession(harness.config.sshBroker.socketPath);
    assert.equal(second.status, 502, 'timed-out retrieval must return the capacity slot');
  } finally {
    await closeHarness(harness, tmpDir);
  }
});

test('shutdown waits for lease creation, then releases it and finalizes setup', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
  let resolveLease;
  const deferredLease = new Promise((resolve) => { resolveLease = resolve; });
  const harness = makeHarness(tmpDir, { createLease: () => deferredLease });
  try {
    await harness.broker.start();
    const opening = openSession(harness.config.sshBroker.socketPath).catch(() => null);
    await waitFor(() => harness.createCalls.length === 1);

    const closing = harness.broker.close();
    resolveLease({
      id: 'deferred-agent-lease',
      socketPath: '/run/deferred-agent.sock',
      expiresAt: Date.now() + 60_000,
    });
    await closing;
    await opening;

    assert.deepEqual(harness.releaseCalls, ['deferred-agent-lease']);
    assert.equal(harness.audit.finals.some((entry) =>
      entry.final.outcome === 'gateway_shutdown'
      && entry.final.closeReason === 'gateway_shutdown_during_session_setup'
      && entry.final.approved === true), true);
  } finally {
    await harness.broker.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('audit failure during activation immediately rolls back lease and capacity', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
  const audit = makeAudit();
  const update = audit.updateSshSession.bind(audit);
  audit.updateSshSession = (id, value) => {
    update(id, value);
    if (value.outcome === 'active') throw new Error('audit unavailable');
    return true;
  };
  const harness = makeHarness(tmpDir, {
    audit,
    config: { sshBroker: { maxConcurrentLeases: 1 } },
  });
  try {
    await harness.broker.start();
    const first = await openSession(harness.config.sshBroker.socketPath);
    assert.equal(first.status, 502);
    assert.deepEqual(harness.releaseCalls, ['agent-lease-1']);

    const second = await openSession(harness.config.sshBroker.socketPath);
    assert.equal(second.status, 502);
    assert.deepEqual(harness.releaseCalls, ['agent-lease-1', 'agent-lease-2']);
  } finally {
    await closeHarness(harness, tmpDir);
  }
});

test('closing a broker that never started does not unlink another broker socket', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
  const owner = makeHarness(tmpDir);
  const observer = makeHarness(tmpDir);
  try {
    await owner.broker.start();
    await observer.broker.close();
    assert.equal(fs.lstatSync(owner.config.sshBroker.socketPath).isSocket(), true);

    const opened = await openSession(owner.config.sshBroker.socketPath);
    assert.equal(opened.status, 201);
  } finally {
    await owner.broker.close();
    await observer.broker.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('broker close releases active leases, records shutdown, and removes socket', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-broker-'));
  const harness = makeHarness(tmpDir);
  try {
    await harness.broker.start();
    const socketPath = harness.config.sshBroker.socketPath;
    const opened = await openSession(socketPath);
    assert.equal(opened.status, 201);
    assert.equal(fs.lstatSync(socketPath).isSocket(), true);

    await harness.broker.close();
    assert.deepEqual(harness.releaseCalls, ['agent-lease-1']);
    assert.equal(
      harness.audit.finals.some((entry) =>
        entry.id === opened.body.leaseId && entry.final.outcome === 'gateway_shutdown'),
      true
    );
    assert.equal(fs.existsSync(socketPath), false);
  } finally {
    await harness.broker.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
