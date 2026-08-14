const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const { loadPlugin } = require('../dist/auth-plugins/loader');
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

function soap(action, inner = '') {
  return Buffer.from(
    `<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="urn:vim25"><soapenv:Body><vim25:${action}>${inner}</vim25:${action}></soapenv:Body></soapenv:Envelope>`
  );
}

function sendSoap(port, body, cookie) {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1',
      port,
      path: '/vmware-esxi/sdk',
      method: 'POST',
      headers: {
        'content-type': 'text/xml; charset=utf-8',
        'content-length': String(body.length),
        'x-clawguard-key': 'test-agent-key',
        'x-clawguard-user': 'Fabio Lombardo via test',
        'x-clawguard-reason': 'Exercise VMware proxy integration',
        ...(cookie ? { cookie } : {}),
      },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({
        statusCode: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks),
      }));
    });
    request.on('error', reject);
    request.end(body);
  });
}

test('VMware proxy injects credentials after approval and brokers the upstream session cookie', async () => {
  const upstreamCalls = [];
  const upstream = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      upstreamCalls.push({ body, headers: request.headers });
      const isLogin = /<(?:\w+:)?Login\b/.test(body);
      response.writeHead(200, {
        'content-type': 'text/xml; charset=utf-8',
        ...(isLogin
          ? { 'set-cookie': 'vmware_soap_session="UPSTREAM-ONLY"; Path=/sdk; HttpOnly; Secure' }
          : {}),
      });
      response.end('<soapenv:Envelope><soapenv:Body>ok</soapenv:Body></soapenv:Envelope>');
    });
  });

  const upstreamPort = await listen(upstream);
  const pluginData = fs.mkdtempSync(path.join(os.tmpdir(), 'clawguard-vmware-proxy-'));
  const service = {
    upstream: `http://127.0.0.1:${upstreamPort}`,
    auth: {
      type: 'plugin',
      token: 'unused',
      pluginPath: 'vmware-esxi',
      pluginConfig: {
        username: 'REAL-ESXI-USER',
        password: 'REAL-ESXI-PASSWORD',
        sessionTtlSeconds: 600,
      },
    },
    policy: { default: 'require_approval', rules: [] },
    http: { allowPrivateTarget: true },
  };
  await loadPlugin('vmware-esxi', 'vmware-esxi', service.auth.pluginConfig, pluginData);

  const approvalCalls = [];
  const approvalManager = {
    async checkApproval(serviceName, _service, method, requestPath, _agentIp, meta, info) {
      approvalCalls.push({ serviceName, method, requestPath, meta, info });
      return true;
    },
    getStatus: () => [],
  };
  const auditCalls = [];
  const audit = {
    logRequest: (entry) => auditCalls.push(entry),
    getRecentRequests: () => [],
  };
  const config = {
    server: { port: 0, agentKey: 'test-agent-key' },
    services: { 'vmware-esxi': service },
    audit: { type: 'sqlite', path: ':memory:', logPayload: true },
    security: {
      allowedUpstreams: ['127.0.0.1'],
      blockPrivateIPs: true,
      followRedirects: false,
      maxPayloadLogSize: 10240,
    },
    admin: { enabled: false, pin: 'unused', allowedIPs: [], strictMode: true },
    proxy: { enabled: false, caDir: './data/ca', discovery: false, discoveryPolicy: 'block' },
    transparentProxy: { enabled: false, httpPort: 0, httpsPort: 0 },
  };
  const proxy = http.createServer(createProxy(config, approvalManager, audit));
  const proxyPort = await listen(proxy);

  try {
    const login = await sendSoap(proxyPort, soap('Login', [
      '<_this type="SessionManager">SessionManager</_this>',
      '<userName>DUMMY</userName><password>DUMMY</password>',
    ].join('')));
    assert.equal(login.statusCode, 200);
    const clientCookie = login.headers['set-cookie'][0].split(';', 1)[0];
    assert.match(clientCookie, /^clawguard_esxi_session=/);
    assert.equal(clientCookie.includes('UPSTREAM-ONLY'), false);

    const power = await sendSoap(proxyPort, soap(
      'PowerOnVM_Task', '<_this type="VirtualMachine">vm-42</_this>'
    ), clientCookie);
    assert.equal(power.statusCode, 200);

    assert.match(upstreamCalls[0].body, /<userName>REAL-ESXI-USER<\/userName>/);
    assert.match(upstreamCalls[0].body, /<password>REAL-ESXI-PASSWORD<\/password>/);
    assert.equal(upstreamCalls[0].headers['x-clawguard-key'], undefined);
    assert.equal(upstreamCalls[0].headers['x-clawguard-user'], undefined);
    assert.equal(upstreamCalls[1].headers.cookie, 'vmware_soap_session="UPSTREAM-ONLY"');

    assert.equal(approvalCalls[0].info.action, 'Open VMware API session');
    assert.equal(approvalCalls[0].info.risk, 'session');
    assert.equal(approvalCalls[1].info.action, 'Power on virtual machine');
    assert.equal(approvalCalls[1].info.risk, 'write');
    assert.equal(approvalCalls[1].info.target, 'VirtualMachine vm-42');
    assert.equal(approvalCalls[1].info.oneTime, true);
    assert.match(approvalCalls[1].info.approvalPath, /PowerOnVM_Task\/VirtualMachine-vm-42$/);

    await new Promise((resolve) => setImmediate(resolve));
    const auditText = JSON.stringify(auditCalls);
    assert.equal(auditText.includes('REAL-ESXI-USER'), false);
    assert.equal(auditText.includes('REAL-ESXI-PASSWORD'), false);
    assert.equal(auditText.includes('UPSTREAM-ONLY'), false);
    assert.equal(auditCalls.every((entry) => entry.requestBody?.includes('redacted')), true);
    assert.equal(auditCalls.every((entry) => entry.responseBody?.includes('redacted')), true);
  } finally {
    await close(proxy);
    await close(upstream);
    fs.rmSync(pluginData, { recursive: true, force: true });
  }
});
