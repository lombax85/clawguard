const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const enabled = process.env.CLAWGUARD_RUN_FTP_E2E === '1';
const fixtureDir = path.join(__dirname, 'fixtures', 'ftp-gateway-e2e');
const project = `clawguard-ftp-e2e-${process.pid}`;

function compose(args, options = {}) {
  return execFileSync('docker', ['compose', '-p', project, ...args], {
    cwd: fixtureDir,
    encoding: 'utf8',
    stdio: options.capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
    env: process.env,
  });
}

function gatewayCall(payload, method = 'POST', requestPath = '/session') {
  const output = execFileSync('docker', [
    'compose', '-p', project, 'exec', '-T',
    '-e', `FTP_GATEWAY_METHOD=${method}`,
    '-e', `FTP_GATEWAY_PATH=${requestPath}`,
    '-e', `FTP_GATEWAY_REQUEST=${payload ? JSON.stringify(payload) : ''}`,
    'gateway', 'node', '/test/call-gateway.js',
  ], { cwd: fixtureDir, encoding: 'utf8' });
  return JSON.parse(output);
}

function upstreamIp() {
  const id = compose(['ps', '-q', 'upstream'], { capture: true }).trim();
  return execFileSync('docker', [
    'inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', id,
  ], { encoding: 'utf8' }).trim();
}

function openRequest(protocol, tlsMode, accessMode = 'read_write') {
  const suffix = protocol === 'ftp' ? 'plain' : 'tls';
  return {
    sessionId: `session_${suffix}_${'x'.repeat(32)}`,
    service: `files_${suffix}`,
    protocol,
    accessMode,
    clientIp: '127.0.0.1',
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    upstream: {
      hostname: 'upstream',
      port: protocol === 'ftp' ? 2121 : 2990,
      resolvedAddresses: [upstreamIp()],
      root: '',
      tlsMode,
      noCheckCertificate: protocol === 'ftps',
    },
    upstreamCredentials: {
      username: 'upstream-test-user',
      passwordBase64: Buffer.from('upstream-test-password').toString('base64'),
    },
    gatewayCredentials: {
      username: `gateway-${suffix}`,
      password: `gateway-${suffix}-${'z'.repeat(32)}`,
    },
  };
}

test('real rclone sidecar proxies FTP and explicit FTPS without exposing the upstream password', { skip: !enabled }, () => {
  let failed = true;
  try {
    compose(['up', '-d', '--build', '--wait']);

    for (const [protocol, upstreamTls, curlTls, scheme] of [
      ['ftp', 'none', [], 'ftp'],
      ['ftps', 'explicit', ['--ssl-reqd', '--insecure'], 'ftp'],
    ]) {
      const request = openRequest(protocol, upstreamTls);
      const opened = gatewayCall(request);
      assert.equal(opened.status, 201, JSON.stringify(opened));
      assert.equal(opened.body.controlPort, 21210);
      assert.equal(JSON.stringify(opened).includes('upstream-test-password'), false);

      if (protocol === 'ftps') {
        assert.throws(() => execFileSync('curl', [
          '--silent', '--show-error', '--fail',
          '--user', `${request.gatewayCredentials.username}:${request.gatewayCredentials.password}`,
          'ftp://127.0.0.1:24210/',
        ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }),
        'the FTPS listener must reject USER/PASS before AUTH TLS');
      }

      const marker = `payload-through-${protocol}`;
      execFileSync('curl', [
        '--silent', '--show-error', '--fail', ...curlTls,
        '--user', `${request.gatewayCredentials.username}:${request.gatewayCredentials.password}`,
        '--upload-file', '-', `${scheme}://127.0.0.1:24210/${protocol}.txt`,
      ], { input: marker, encoding: 'utf8' });
      const downloaded = execFileSync('curl', [
        '--silent', '--show-error', '--fail', ...curlTls,
        '--user', `${request.gatewayCredentials.username}:${request.gatewayCredentials.password}`,
        `${scheme}://127.0.0.1:24210/${protocol}.txt`,
      ], { encoding: 'utf8' });
      assert.equal(downloaded, marker);

      if (protocol === 'ftp') {
        assert.throws(() => execFileSync('curl', [
          '--silent', '--show-error', '--fail',
          '--ftp-port', '-',
          '--user', `${request.gatewayCredentials.username}:${request.gatewayCredentials.password}`,
          'ftp://127.0.0.1:24210/ftp.txt',
        ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }),
        'active FTP must remain unavailable even to an approved client');
      }

      const closed = gatewayCall(undefined, 'DELETE', `/session/${request.sessionId}`);
      assert.equal(closed.status, 200);
    }

    const readOnlyRequest = openRequest('ftp', 'none', 'read_only');
    const readOnlyOpened = gatewayCall(readOnlyRequest);
    assert.equal(readOnlyOpened.status, 201, JSON.stringify(readOnlyOpened));
    const existing = execFileSync('curl', [
      '--silent', '--show-error', '--fail',
      '--user', `${readOnlyRequest.gatewayCredentials.username}:${readOnlyRequest.gatewayCredentials.password}`,
      'ftp://127.0.0.1:24210/ftp.txt',
    ], { encoding: 'utf8' });
    assert.equal(existing, 'payload-through-ftp');
    assert.throws(() => execFileSync('curl', [
      '--silent', '--show-error', '--fail',
      '--user', `${readOnlyRequest.gatewayCredentials.username}:${readOnlyRequest.gatewayCredentials.password}`,
      '--upload-file', '-', 'ftp://127.0.0.1:24210/read-only-denied.txt',
    ], { input: 'must-not-be-written', encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }),
    'read-only approval must block uploads');
    const readOnlyClosed = gatewayCall(
      undefined,
      'DELETE',
      `/session/${readOnlyRequest.sessionId}`,
    );
    assert.equal(readOnlyClosed.status, 200);
    failed = false;
  } finally {
    if (failed) compose(['logs', '--no-color', 'gateway', 'upstream']);
    compose(['down', '--volumes', '--remove-orphans']);
  }
});
