const test = require('node:test');
const assert = require('node:assert/strict');

const { createPlugin, __test } = require('../dist/auth-plugins/vmware-esxi');
const { approvalInfoLines } = require('../dist/telegram');

function soap(action, inner = '') {
  return Buffer.from(
    `<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="urn:vim25"><soapenv:Body><vim25:${action}>${inner}</vim25:${action}></soapenv:Body></soapenv:Envelope>`
  );
}

function ctx(body, cookie) {
  return {
    serviceName: 'vmware-esxi',
    method: 'POST',
    path: '/sdk',
    headers: {
      'content-type': 'text/xml; charset=utf-8',
      ...(cookie ? { cookie } : {}),
    },
    body,
    upstreamUrl: 'https://192.168.88.3/sdk',
    dataDir: '/tmp/vmware-esxi-test',
    config: {},
  };
}

async function initializedPlugin() {
  const plugin = createPlugin();
  await plugin.init('/tmp/vmware-esxi-test', {
    username: 'real-api-user',
    password: 'real<&password',
    sessionTtlSeconds: 600,
  });
  return plugin;
}

test('VMware approval description shows authoritative SOAP action, target and safe parameters', async () => {
  const plugin = await initializedPlugin();
  const body = soap('CreateSnapshot_Task', [
    '<_this type="VirtualMachine">vm-42</_this>',
    '<name>before-upgrade</name>',
    '<description>Safety checkpoint</description>',
    '<memory>false</memory>',
    '<quiesce>true</quiesce>',
  ].join(''));
  const info = await plugin.describeRequest(ctx(body));
  assert.equal(info.action, 'Create VM snapshot');
  assert.equal(info.risk, 'write');
  assert.equal(info.target, 'VirtualMachine vm-42');
  assert.equal(info.oneTime, true);
  assert.match(info.approvalPath, /^\/sdk\/write\/CreateSnapshot_Task\/VirtualMachine-vm-42$/);
  assert.equal(info.details.some((item) => item.label === 'Name' && item.value === 'before-upgrade'), true);
  assert.equal(info.details.some((item) => item.label === 'Quiesce filesystem' && item.value === 'true'), true);
});

test('VMware read request can be policy auto-approved and does not become one-time', async () => {
  const plugin = await initializedPlugin();
  const info = await plugin.describeRequest(ctx(soap(
    'RetrievePropertiesEx', [
      '<_this type="PropertyCollector">propertyCollector</_this>',
      '<pathSet>name</pathSet><pathSet>runtime.powerState</pathSet><maxObjects>100</maxObjects>',
    ].join('')
  )));
  assert.equal(info.risk, 'read');
  assert.equal(info.oneTime, false);
  assert.match(info.approvalPath, /^\/sdk\/read\/RetrievePropertiesEx/);
  assert.equal(info.details.some((item) => item.label === 'Requested property'
    && item.value === 'runtime.powerState'), true);
  assert.equal(info.details.some((item) => item.label === 'Maximum objects'
    && item.value === '100'), true);
});

test('VMware approval target includes secondary migration managed objects', async () => {
  const plugin = await initializedPlugin();
  const info = await plugin.describeRequest(ctx(soap('RelocateVM_Task', [
    '<_this type="VirtualMachine">vm-42</_this>',
    '<pool type="ResourcePool">resgroup-7</pool>',
    '<host type="HostSystem">host-9</host>',
    '<datastore type="Datastore">datastore-4</datastore>',
    '<priority>highPriority</priority>',
    '<diskMoveType>moveAllDiskBackingsAndAllowSharing</diskMoveType>',
  ].join(''))));
  assert.equal(info.target, [
    'VirtualMachine vm-42',
    'ResourcePool resgroup-7',
    'HostSystem host-9',
    'Datastore datastore-4',
  ].join(', '));
  assert.equal(info.details.some((item) => item.label === 'Migration priority'), true);
  assert.equal(info.details.some((item) => item.label === 'Disk move type'), true);
});

test('VMware Login credentials are injected only after description and audit body is redacted', async () => {
  const plugin = await initializedPlugin();
  const loginBody = soap('Login', [
    '<_this type="SessionManager">SessionManager</_this>',
    '<userName>dummy-user</userName>',
    '<password>dummy-password</password>',
  ].join(''));
  const info = await plugin.describeRequest(ctx(loginBody));
  const serializedInfo = JSON.stringify(info);
  assert.equal(serializedInfo.includes('dummy-password'), false);
  assert.equal(serializedInfo.includes('real<&password'), false);
  assert.equal(info.risk, 'session');

  const rewritten = await plugin.rewriteRequest(ctx(loginBody));
  const xml = rewritten.body.toString('utf8');
  assert.match(xml, /<userName>real-api-user<\/userName>/);
  assert.match(xml, /<password>real&lt;&amp;password<\/password>/);
  assert.equal(rewritten.auditRequestBody.includes('redacted'), true);
  assert.equal(rewritten.auditRequestBody.includes('real-api-user'), false);
});

test('VMware upstream session cookie is replaced by opaque ClawGuard cookie and mapped back', async () => {
  const plugin = await initializedPlugin();
  const loginBody = soap('Login', [
    '<_this type="SessionManager">SessionManager</_this>',
    '<userName>dummy</userName><password>dummy</password>',
  ].join(''));
  const loginRequest = await plugin.rewriteRequest(ctx(loginBody));
  const loginResponse = await plugin.rewriteResponseHeaders({
    serviceName: 'vmware-esxi',
    method: 'POST',
    path: '/sdk',
    statusCode: 200,
    headers: { 'set-cookie': ['vmware_soap_session="UPSTREAM-SECRET"; Path=/sdk; Secure; HttpOnly'] },
    requestState: loginRequest.requestState,
    dataDir: '/tmp/vmware-esxi-test',
    config: {},
  });
  const clientSetCookie = loginResponse.headers['set-cookie'][0];
  assert.equal(clientSetCookie.includes('UPSTREAM-SECRET'), false);
  assert.match(clientSetCookie, /^clawguard_esxi_session=/);
  assert.equal(loginResponse.auditResponseBody.includes('redacted'), true);

  const opaqueToken = clientSetCookie.match(/^clawguard_esxi_session=([^;]+)/)[1];
  const powerRequest = await plugin.rewriteRequest(ctx(
    soap('PowerOnVM_Task', '<_this type="VirtualMachine">vm-42</_this>'),
    `other=value; clawguard_esxi_session=${opaqueToken}`
  ));
  assert.match(powerRequest.headers.cookie, /other=value/);
  assert.match(powerRequest.headers.cookie, /vmware_soap_session="UPSTREAM-SECRET"/);
  assert.equal(powerRequest.headers.cookie.includes(opaqueToken), false);

  const logoutRequest = await plugin.rewriteRequest(ctx(
    soap('Logout', '<_this type="SessionManager">SessionManager</_this>'),
    `clawguard_esxi_session=${opaqueToken}`
  ));
  const logoutResponse = await plugin.rewriteResponseHeaders({
    serviceName: 'vmware-esxi', method: 'POST', path: '/sdk', statusCode: 200,
    headers: {}, requestState: logoutRequest.requestState,
    dataDir: '/tmp/vmware-esxi-test', config: {},
  });
  assert.match(logoutResponse.headers['set-cookie'][0], /Max-Age=0/);
  await assert.rejects(
    () => plugin.rewriteRequest(ctx(
      soap('RetrievePropertiesEx'), `clawguard_esxi_session=${opaqueToken}`
    )),
    /Unknown or expired/
  );
});

test('VMware plugin strips caller-supplied upstream cookies and blocks session export calls', async () => {
  const plugin = await initializedPlugin();
  const request = await plugin.rewriteRequest(ctx(
    soap('RetrieveServiceContent'), 'vmware_soap_session="ATTACKER"; harmless=yes'
  ));
  assert.equal(request.headers.cookie, 'harmless=yes');
  await assert.rejects(
    () => plugin.rewriteRequest(ctx(soap('AcquireCloneTicket'))),
    /session-export operation AcquireCloneTicket is blocked/
  );
});

test('Telegram approval detail rendering includes action, risk, target and bounded safe fields', () => {
  const lines = approvalInfoLines({
    action: 'Power *On* VM',
    risk: 'write',
    target: 'VirtualMachine vm-42',
    details: [{ label: 'Name_[unsafe]', value: 'WalaBuntu `prod`' }],
    oneTime: true,
  });
  const text = lines.join('\n');
  assert.match(text, /Action: \*Power On VM\*/);
  assert.match(text, /Risk: \*write\*/);
  assert.match(text, /Target: \*VirtualMachine vm-42\*/);
  assert.match(text, /Nameunsafe: WalaBuntu prod/);
  assert.match(text, /this request only/);
});

test('SOAP parser never treats credentials as approval details', () => {
  const info = __test.approvalDescription('POST', '/sdk', soap(
    'Login', '<userName>secret-user</userName><password>secret-pass</password>'
  ));
  const text = JSON.stringify(info);
  assert.equal(text.includes('secret-user'), false);
  assert.equal(text.includes('secret-pass'), false);
});
