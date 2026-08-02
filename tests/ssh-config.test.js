const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  DEFAULT_SSH_BROKER,
  loadConfig,
  normalizeSshConfiguration,
  validateSshConfiguration,
} = require('../dist/config');
const {
  isPrivateIP,
  isValidKnownHostKey,
  validateSshService,
  validateSshTargetRuntime,
  validateUpstreamUrl,
} = require('../dist/security');

const keyType = 'ssh-ed25519';
const typeBytes = Buffer.from(keyType);
const keyBytes = Buffer.alloc(32, 0x42);
const knownKeyBlob = Buffer.alloc(4 + typeBytes.length + 4 + keyBytes.length);
knownKeyBlob.writeUInt32BE(typeBytes.length, 0);
typeBytes.copy(knownKeyBlob, 4);
knownKeyBlob.writeUInt32BE(keyBytes.length, 4 + typeBytes.length);
keyBytes.copy(knownKeyBlob, 8 + typeBytes.length);
const KNOWN_HOST_KEY = `${keyType} ${knownKeyBlob.toString('base64')}`;

const security = {
  allowedUpstreams: ['ssh.example.com'],
  blockPrivateIPs: true,
  followRedirects: false,
  maxPayloadLogSize: 10240,
};

function sshService(overrides = {}) {
  return {
    protocol: 'ssh',
    upstream: 'ssh://ssh.example.com:22',
    auth: {
      type: 'plugin',
      token: 'unused',
      pluginPath: 'ssh-private-key',
      pluginConfig: {},
    },
    policy: { default: 'require_approval' },
    ssh: { knownHostKey: KNOWN_HOST_KEY, allowPrivateTarget: false },
    ...overrides,
  };
}

function configWith(service, broker = { ...DEFAULT_SSH_BROKER, enabled: true }) {
  return {
    services: { production: service },
    security,
    sshBroker: broker,
  };
}

test('normalization defaults legacy services to HTTP and keeps the SSH broker disabled', () => {
  const config = {
    services: {
      github: {
        upstream: 'https://api.github.com',
        auth: { type: 'bearer', token: 'dummy' },
        policy: { default: 'require_approval' },
      },
    },
  };

  normalizeSshConfiguration(config);

  assert.equal(config.services.github.protocol, 'http');
  assert.deepEqual(config.sshBroker, DEFAULT_SSH_BROKER);
  assert.deepEqual(validateSshConfiguration(config), []);
});

test('a complete SSH service and broker configuration validates', () => {
  assert.deepEqual(validateSshConfiguration(configWith(sshService())), []);
  assert.equal(validateSshService(sshService(), security).valid, true);
});

test('loadConfig normalizes SSH input and does not require an HTTP token field', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'clawguard-ssh-config-'));
  const configPath = path.join(directory, 'clawguard.yaml');
  const service = sshService();
  delete service.auth.token;
  const input = {
    server: { port: 9090, agentKey: 'test-agent-key' },
    services: { production: service },
    security,
    sshBroker: { enabled: true },
    admin: { enabled: false },
  };
  fs.writeFileSync(configPath, JSON.stringify(input), 'utf8');

  try {
    const loaded = await loadConfig(configPath);
    assert.equal(loaded.services.production.protocol, 'ssh');
    assert.equal(loaded.sshBroker.enabled, true);
    assert.equal(loaded.sshBroker.socketPath, DEFAULT_SSH_BROKER.socketPath);
    assert.equal(loaded.sshBroker.credentialTimeoutMs, 30000);
    assert.equal(loaded.sshBroker.maxSessionSeconds, 3600);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('SSH services require an enabled broker and protocol-specific plugin', () => {
  const disabledErrors = validateSshConfiguration(
    configWith(sshService(), { ...DEFAULT_SSH_BROKER, enabled: false })
  );
  assert.ok(disabledErrors.some((error) => /sshBroker\.enabled/.test(error)));

  const badAuth = sshService({ auth: { type: 'bearer', token: 'secret' } });
  const authErrors = validateSshConfiguration(configWith(badAuth));
  assert.ok(authErrors.some((error) => /auth\.type: plugin/.test(error)));
  assert.ok(authErrors.some((error) => /auth\.pluginPath/.test(error)));
});

test('enabled broker rejects unsafe paths, root identities and invalid limits', () => {
  const broker = {
    ...DEFAULT_SSH_BROKER,
    enabled: true,
    runtimeDir: 'relative/run',
    socketPath: 'relative/broker.sock',
    gatewayUid: 0,
    gatewayGid: -1,
    approvalTimeoutMs: 0,
    credentialTimeoutMs: 999,
    leaseTtlSeconds: 0,
    maxSessionSeconds: 1,
    sshAgentPath: 'ssh-agent',
    sshAddPath: 'ssh-add',
    maxConcurrentLeases: 0,
  };
  const errors = validateSshConfiguration(configWith(sshService(), broker));

  for (const expected of [
    /runtimeDir/, /socketPath/, /gatewayUid/, /gatewayGid/, /approvalTimeoutMs/,
    /credentialTimeoutMs/, /leaseTtlSeconds/, /maxSessionSeconds/,
    /sshAgentPath/, /sshAddPath/, /maxConcurrentLeases/,
  ]) {
    assert.ok(errors.some((error) => expected.test(error)), `missing error ${expected}`);
  }
});

test('SSH service aliases must be accepted identically by config, broker, and wrapper', () => {
  for (const alias of ['prod.eu', `x${'a'.repeat(64)}`, 'prod service']) {
    const config = configWith(sshService());
    config.services = { [alias]: sshService() };
    const errors = validateSshConfiguration(config);
    assert.ok(errors.some((error) => /SSH service alias/.test(error)), alias);
  }

  const valid = configWith(sshService());
  valid.services = { 'prod_eu-1': sshService() };
  assert.deepEqual(validateSshConfiguration(valid), []);
});

test('SSH target must be exactly ssh://host:port', () => {
  for (const upstream of [
    'https://ssh.example.com:22',
    'ssh://ssh.example.com',
    'ssh://deploy@ssh.example.com:22',
    'ssh://ssh.example.com:22/',
    'ssh://ssh.example.com:22/path',
    'ssh://ssh.example.com:22?target=other',
  ]) {
    const result = validateSshService(sshService({ upstream }), security);
    assert.equal(result.valid, false, upstream);
  }
});

test('knownHostKey must be a complete single-line OpenSSH key', () => {
  assert.equal(isValidKnownHostKey(KNOWN_HOST_KEY), true);
  for (const value of [
    'SHA256:abcdef',
    'ssh-ed25519 AAAA comment',
    'ssh-ed25519 not-base64!',
    `${KNOWN_HOST_KEY}\nssh-ed25519 AAAA`,
    `ssh-ed25519 ${'A'.repeat(17 * 1024)}`,
  ]) {
    assert.equal(isValidKnownHostKey(value), false, value);
  }
});

test('private IPv4 and IPv6 literals require explicit SSH opt-in', () => {
  assert.equal(isPrivateIP('10.1.2.3'), true);
  assert.equal(isPrivateIP('fd00::1234'), true);
  assert.equal(isPrivateIP('2001:4860:4860::8888'), false);

  for (const upstream of ['ssh://10.1.2.3:22', 'ssh://[fd00::1234]:22']) {
    const privateSecurity = { ...security, allowedUpstreams: [] };
    assert.equal(validateSshService(sshService({ upstream }), privateSecurity).valid, false);
    assert.equal(validateSshService(sshService({
      upstream,
      ssh: { knownHostKey: KNOWN_HOST_KEY, allowPrivateTarget: true },
    }), privateSecurity).valid, true);
  }
});

test('runtime SSH DNS validation checks IPv4 and IPv6 and fails closed', async () => {
  const service = sshService();
  const publicResult = await validateSshTargetRuntime(service, security, async () => [
    { address: '203.0.113.10', family: 4 },
    { address: '2001:4860:4860::8888', family: 6 },
  ]);
  assert.equal(publicResult.valid, true);
  assert.deepEqual(publicResult.resolvedAddresses, ['203.0.113.10', '2001:4860:4860::8888']);

  const privateResult = await validateSshTargetRuntime(service, security, async () => [
    { address: 'fd00::10', family: 6 },
  ]);
  assert.equal(privateResult.valid, false);
  assert.match(privateResult.reason, /private address/i);

  const failure = await validateSshTargetRuntime(service, security, async () => {
    throw new Error('NXDOMAIN');
  });
  assert.equal(failure.valid, false);
  assert.match(failure.reason, /failed closed/i);
});

test('SSH honors allowedUpstreams while HTTP validator still rejects ssh:', () => {
  const denied = validateSshService(sshService(), { ...security, allowedUpstreams: ['other.example.com'] });
  assert.equal(denied.valid, false);
  assert.match(denied.reason, /allowed upstreams/i);

  const httpResult = validateUpstreamUrl('ssh://ssh.example.com:22', security);
  assert.equal(httpResult.valid, false);
  assert.match(httpResult.reason, /Unsupported protocol/);
});
