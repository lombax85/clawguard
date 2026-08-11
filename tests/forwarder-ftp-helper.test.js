const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const helper = path.resolve(__dirname, '../forwarder/clawguard-ftp.js');

function runHelper(args, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [helper, ...args], {
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

test('list keeps credentials off argv, sends provenance, and revokes the lease', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'clawguard-ftp-helper-'));
  const requests = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      requests.push({
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      });
      if (req.method === 'POST') {
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          id: 'lease-123',
          protocol: 'ftps',
          host: 'ftp.example.test',
          port: 21210,
          username: 'ephemeral-user',
          password: 'ephemeral-password',
          accessMode: 'read_only',
        }));
        return;
      }
      res.writeHead(204);
      res.end();
    });
  });

  try {
    const port = await listen(server);
    const configPath = path.join(temp, 'forwarder.json');
    const curlArgsPath = path.join(temp, 'curl-args');
    const curlConfigPath = path.join(temp, 'curl-config');
    const fakeCurl = path.join(temp, 'curl');
    fs.writeFileSync(configPath, JSON.stringify({
      clawguard: `http://127.0.0.1:${port}`,
      ftpApi: `http://127.0.0.1:${port}`,
      agentKey: 'dummy-agent-key',
    }));
    fs.writeFileSync(fakeCurl, `#!/bin/sh
printf '%s\n' "$@" > "$FAKE_CURL_ARGS"
cat > "$FAKE_CURL_CONFIG"
printf 'alpha.txt\nbeta.txt\n'
`);
    fs.chmodSync(fakeCurl, 0o755);

    const result = await runHelper([
      'list',
      'production-files',
      '/releases',
      '--user',
      'Alice via test',
      '--reason',
      'List release directory',
      '--insecure',
    ], {
      CLAWGUARD_FORWARDER_CONFIG: configPath,
      PATH: `${temp}${path.delimiter}${process.env.PATH}`,
      FAKE_CURL_ARGS: curlArgsPath,
      FAKE_CURL_CONFIG: curlConfigPath,
    });

    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.stdout, 'alpha.txt\nbeta.txt\n');
    assert.equal(result.stderr, '');
    assert.deepEqual(fs.readFileSync(curlArgsPath, 'utf8').trim().split('\n'), ['--config', '-']);
    const curlConfig = fs.readFileSync(curlConfigPath, 'utf8');
    assert.match(curlConfig, /user = "ephemeral-user:ephemeral-password"/);
    assert.match(curlConfig, /^ssl-reqd$/m);
    assert.match(curlConfig, /^insecure$/m);
    assert.doesNotMatch(fs.readFileSync(curlArgsPath, 'utf8'), /ephemeral-password/);

    assert.equal(requests.length, 2);
    assert.equal(requests[0].method, 'POST');
    assert.equal(requests[0].url, '/__ftp/session');
    assert.equal(requests[0].headers['x-clawguard-key'], 'dummy-agent-key');
    assert.equal(requests[0].headers['x-clawguard-user'], 'Alice via test');
    assert.equal(requests[0].headers['x-clawguard-reason'], 'List release directory');
    assert.deepEqual(JSON.parse(requests[0].body), { service: 'production-files' });
    assert.equal(requests[1].method, 'DELETE');
    assert.equal(requests[1].url, '/__ftp/session/lease-123');
    assert.match(requests[1].headers['x-clawguard-reason'], /^Revoke FTP lease after:/);
  } finally {
    await close(server);
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('approval denial is terminal and is not retried', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'clawguard-ftp-helper-deny-'));
  let requests = 0;
  const server = http.createServer((req, res) => {
    requests += 1;
    req.resume();
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end('{"error":"denied"}');
  });

  try {
    const port = await listen(server);
    const configPath = path.join(temp, 'forwarder.json');
    fs.writeFileSync(configPath, JSON.stringify({
      ftpApi: `http://127.0.0.1:${port}`,
      agentKey: 'dummy-agent-key',
    }));

    const result = await runHelper([
      'list',
      'production-files',
      '--user',
      'Alice via test',
      '--reason',
      'List release directory',
    ], { CLAWGUARD_FORWARDER_CONFIG: configPath });

    assert.equal(result.code, 1);
    assert.match(result.stderr, /approval denied or timed out/);
    assert.equal(requests, 1);
  } finally {
    await close(server);
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
