const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const zlib = require('node:zlib');

const { createProxy } = require('../dist/proxy');

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve(server.address().port);
    });
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

function sendRequest(port, path, headers, body) {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1',
      port,
      path,
      method: 'POST',
      headers,
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({
        statusCode: response.statusCode,
        body: Buffer.concat(chunks),
      }));
    });
    request.on('error', reject);
    request.end(body);
  });
}

test('direct proxy preserves gzip request bytes and encoding headers', async () => {
  const originalBody = Buffer.from('git-upload-pack negotiation '.repeat(100));
  const compressedBody = zlib.gzipSync(originalBody);

  let receivedBody;
  let receivedHeaders;
  const upstream = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      receivedBody = Buffer.concat(chunks);
      receivedHeaders = request.headers;
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('ok');
    });
  });

  const upstreamPort = await listen(upstream);
  const config = {
    server: { port: 0, agentKey: 'test-agent-key' },
    services: {
      git: {
        upstream: `http://127.0.0.1:${upstreamPort}`,
        auth: { type: 'url', token: 'dummy' },
        policy: { default: 'auto_approve', rules: [] },
      },
    },
    audit: { type: 'sqlite', path: ':memory:', logPayload: false },
    security: {
      allowedUpstreams: ['127.0.0.1'],
      blockPrivateIPs: false,
      followRedirects: false,
      maxPayloadLogSize: 10240,
    },
    admin: {
      enabled: false,
      pin: 'unused',
      allowedIPs: [],
      strictMode: true,
    },
    proxy: {
      enabled: false,
      caDir: './data/ca',
      discovery: false,
      discoveryPolicy: 'block',
    },
    transparentProxy: {
      enabled: false,
      httpPort: 0,
      httpsPort: 0,
    },
  };
  const approvalManager = {
    checkApproval: async () => true,
    getStatus: () => [],
  };
  const audit = {
    logRequest: () => {},
    getRecentRequests: () => [],
  };

  const proxy = http.createServer(createProxy(config, approvalManager, audit));
  const proxyPort = await listen(proxy);

  try {
    const response = await sendRequest(proxyPort, '/git/repository.git/git-upload-pack', {
      'content-type': 'application/x-git-upload-pack-request',
      'content-encoding': 'gzip',
      'content-length': String(compressedBody.length),
      'x-clawguard-key': 'test-agent-key',
    }, compressedBody);

    assert.equal(response.statusCode, 200);
    assert.equal(response.body.toString(), 'ok');
    assert.equal(receivedHeaders['content-encoding'], 'gzip');
    assert.equal(receivedHeaders['content-length'], String(compressedBody.length));
    assert.deepEqual(receivedBody, compressedBody);
    assert.deepEqual(zlib.gunzipSync(receivedBody), originalBody);
  } finally {
    await close(proxy);
    await close(upstream);
  }
});
