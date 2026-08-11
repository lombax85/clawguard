const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  DEFAULT_FTP_GATEWAY,
  loadConfig,
  normalizeFtpConfiguration,
  validateFtpConfiguration,
} = require('../dist/config');
const { validateFtpService, validateFtpTargetRuntime } = require('../dist/security');

const security = {
  allowedUpstreams: ['files.example.com'],
  blockPrivateIPs: true,
  followRedirects: false,
  maxPayloadLogSize: 10240,
};

function service(protocol = 'ftp', overrides = {}) {
  return {
    protocol,
    upstream: `${protocol}://files.example.com:${protocol === 'ftp' ? 21 : 990}`,
    auth: { type: 'plugin', pluginPath: 'ftp-password', pluginConfig: {} },
    policy: { default: 'require_approval' },
    ftp: {
      allowPrivateTarget: false,
      ...(protocol === 'ftps' ? { tlsMode: 'implicit' } : {}),
    },
    ...overrides,
  };
}

function config(ftpService, gateway = { ...DEFAULT_FTP_GATEWAY, enabled: true }) {
  return {
    services: { files: ftpService }, security, ftpGateway: gateway,
    sshBroker: { enabled: false }, admin: { enabled: true, https: { enabled: true } },
  };
}

test('FTP configuration normalizes a disabled gateway and validates FTP plus both FTPS modes', () => {
  const legacy = { services: {} };
  normalizeFtpConfiguration(legacy);
  assert.deepEqual(legacy.ftpGateway, DEFAULT_FTP_GATEWAY);

  assert.deepEqual(validateFtpConfiguration(config(service('ftp'))), []);
  for (const tlsMode of ['explicit', 'implicit']) {
    const ftps = service('ftps');
    ftps.ftp.tlsMode = tlsMode;
    assert.equal(validateFtpService(ftps, security).valid, true);
    assert.deepEqual(validateFtpConfiguration(config(ftps)), []);
  }
});

test('loadConfig applies FTP gateway defaults without requiring an HTTP token field', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'clawguard-ftp-config-'));
  const configPath = path.join(directory, 'clawguard.yaml');
  const input = {
    server: { port: 9090, agentKey: 'test-agent-key' },
    services: { files: service('ftps') },
    security,
    ftpGateway: { enabled: true, publicHost: 'gateway.example.com' },
    admin: { enabled: true, pin: 'test-pin', https: { enabled: true } },
  };
  fs.writeFileSync(configPath, JSON.stringify(input), 'utf8');
  try {
    const loaded = await loadConfig(configPath);
    assert.equal(loaded.services.files.protocol, 'ftps');
    assert.equal(loaded.ftpGateway.enabled, true);
    assert.equal(loaded.ftpGateway.socketPath, DEFAULT_FTP_GATEWAY.socketPath);
    assert.equal(loaded.ftpGateway.passivePortsPerSession, 10);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('FTP services require a dedicated credential plugin and enabled gateway', () => {
  const disabled = validateFtpConfiguration(config(service(), { ...DEFAULT_FTP_GATEWAY, enabled: false }));
  assert.ok(disabled.some((error) => /ftpGateway\.enabled/.test(error)));

  const invalid = service('ftp', {
    auth: { type: 'basic', username: 'forbidden', password: 'forbidden' },
  });
  const errors = validateFtpConfiguration(config(invalid));
  assert.ok(errors.some((error) => /auth\.type: plugin/.test(error)));
  assert.ok(errors.some((error) => /auth\.pluginPath/.test(error)));
});

test('FTP target syntax, root, TLS mode, and credentials in URL fail closed', () => {
  for (const invalid of [
    service('ftp', { upstream: 'ftp://user:pass@files.example.com:21' }),
    service('ftp', { upstream: 'ftp://files.example.com:21/path' }),
    service('ftp', { upstream: 'http://files.example.com:21' }),
    service('ftp', { ftp: { allowPrivateTarget: false, tlsMode: 'explicit' } }),
    service('ftps', { ftp: { allowPrivateTarget: false } }),
    service('ftp', { ftp: { allowPrivateTarget: false, root: '../escape' } }),
  ]) {
    assert.equal(validateFtpService(invalid, security).valid, false, JSON.stringify(invalid));
  }
});

test('runtime FTP validation returns a pinned address set and rejects private DNS answers', async () => {
  const ok = await validateFtpTargetRuntime(service(), security, async () => [
    { address: '203.0.113.10', family: 4 },
    { address: '2001:4860:4860::8888', family: 6 },
  ]);
  assert.equal(ok.valid, true);
  assert.deepEqual(ok.resolvedAddresses, ['203.0.113.10', '2001:4860:4860::8888']);

  const denied = await validateFtpTargetRuntime(service(), security, async () => [
    { address: '10.0.0.7', family: 4 },
  ]);
  assert.equal(denied.valid, false);
  assert.match(denied.reason, /private address/i);
});

test('gateway validation rejects overlapping or undersized port allocations', () => {
  const gateway = {
    ...DEFAULT_FTP_GATEWAY,
    enabled: true,
    maxConcurrentSessions: 10,
    controlPortStart: 21210,
    controlPortEnd: 21215,
    passivePortStart: 21212,
  };
  const errors = validateFtpConfiguration(config(service(), gateway));
  assert.ok(errors.some((error) => /control-port range/.test(error)));
  assert.ok(errors.some((error) => /must not overlap/.test(error)));
});

test('lease credentials require HTTPS unless plaintext API exposure is explicitly opted in', () => {
  const unsafeDefault = config(service(), { ...DEFAULT_FTP_GATEWAY, enabled: true });
  unsafeDefault.admin = { enabled: false };
  assert.ok(validateFtpConfiguration(unsafeDefault).some((error) => /lease credentials require/i.test(error)));

  unsafeDefault.ftpGateway.allowInsecureHttpApi = true;
  assert.deepEqual(validateFtpConfiguration(unsafeDefault), []);
});
