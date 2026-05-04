const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const os = require('os');

// ─── loader.ts tests ──────────────────────────────────────────

const {
  loadPlugin,
  getPlugin,
  getPluginDataDir,
} = require('../dist/auth-plugins/loader');

test('loadPlugin loads the built-in echo plugin', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  try {
    const plugin = await loadPlugin('test-echo', 'echo', {}, tmpDir);
    assert.equal(plugin.name, 'echo');
    assert.equal(typeof plugin.rewriteRequest, 'function');

    // Plugin should be registered
    const retrieved = getPlugin('test-echo');
    assert.equal(retrieved, plugin);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('loadPlugin creates data directory for plugin', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  try {
    await loadPlugin('test-datadir', 'echo', {}, tmpDir);
    const dataDir = path.join(tmpDir, 'echo');
    assert.equal(fs.existsSync(dataDir), true);
    assert.equal(fs.statSync(dataDir).isDirectory(), true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('loadPlugin rejects module without createPlugin export', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  // Create a module that doesn't export createPlugin
  const badModulePath = path.join(tmpDir, 'bad-plugin.js');
  fs.writeFileSync(badModulePath, 'module.exports = {};');
  try {
    await assert.rejects(
      () => loadPlugin('test-bad', badModulePath, {}, tmpDir),
      /does not export a createPlugin/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('loadPlugin rejects plugin without name', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  const noNamePath = path.join(tmpDir, 'no-name.js');
  fs.writeFileSync(noNamePath, `
    module.exports.createPlugin = () => ({
      rewriteRequest: async () => ({ headers: {}, body: Buffer.alloc(0) }),
    });
  `);
  try {
    await assert.rejects(
      () => loadPlugin('test-noname', noNamePath, {}, tmpDir),
      /without a valid 'name' string/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('loadPlugin rejects plugin without rewriteRequest', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  const noMethodPath = path.join(tmpDir, 'no-method.js');
  fs.writeFileSync(noMethodPath, `
    module.exports.createPlugin = () => ({
      name: 'broken',
    });
  `);
  try {
    await assert.rejects(
      () => loadPlugin('test-nomethod', noMethodPath, {}, tmpDir),
      /without a rewriteRequest/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('loadPlugin rejects plugin name with path traversal characters', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  const traversalPath = path.join(tmpDir, 'traversal.js');
  fs.writeFileSync(traversalPath, `
    module.exports.createPlugin = () => ({
      name: '../evil',
      rewriteRequest: async () => ({ headers: {}, body: Buffer.alloc(0) }),
    });
  `);
  try {
    await assert.rejects(
      () => loadPlugin('test-traversal', traversalPath, {}, tmpDir),
      /Invalid plugin name/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('getPlugin returns undefined for unknown service', () => {
  const result = getPlugin('nonexistent-service-xyz');
  assert.equal(result, undefined);
});

test('getPluginDataDir returns correct path', () => {
  const result = getPluginDataDir('my-plugin', '/base/dir');
  assert.equal(result, path.join('/base/dir', 'my-plugin'));
});

// ─── echo.ts tests ───────────────────────────────────────────

const { createPlugin } = require('../dist/auth-plugins/echo');

test('echo plugin createPlugin returns valid IAuthPlugin', () => {
  const plugin = createPlugin();
  assert.equal(plugin.name, 'echo');
  assert.equal(typeof plugin.init, 'function');
  assert.equal(typeof plugin.rewriteRequest, 'function');
});

test('echo plugin passes through headers and body unchanged', async () => {
  const plugin = createPlugin();
  await plugin.init('/tmp/test', {});

  const ctx = {
    serviceName: 'test',
    method: 'GET',
    path: '/api/test',
    headers: { 'content-type': 'application/json', 'authorization': 'Bearer xxx' },
    body: Buffer.from('hello'),
    upstreamUrl: 'https://example.com/api/test',
    dataDir: '/tmp/test',
    config: {},
  };

  const result = await plugin.rewriteRequest(ctx);
  assert.deepEqual(result.headers['content-type'], 'application/json');
  assert.deepEqual(result.headers['authorization'], 'Bearer xxx');
  assert.deepEqual(result.body, Buffer.from('hello'));
  assert.equal(result.upstreamUrl, undefined);
});

test('echo plugin injects custom header when configured', async () => {
  const plugin = createPlugin();
  await plugin.init('/tmp/test', {
    injectHeader: 'x-custom-auth',
    injectValue: 'secret-123',
  });

  const ctx = {
    serviceName: 'test',
    method: 'POST',
    path: '/api/data',
    headers: { 'content-type': 'application/json' },
    body: Buffer.alloc(0),
    upstreamUrl: 'https://example.com/api/data',
    dataDir: '/tmp/test',
    config: { injectHeader: 'x-custom-auth', injectValue: 'secret-123' },
  };

  const result = await plugin.rewriteRequest(ctx);
  assert.equal(result.headers['x-custom-auth'], 'secret-123');
});

test('echo plugin does not inject header when config is missing', async () => {
  const plugin = createPlugin();
  await plugin.init('/tmp/test', {});

  const ctx = {
    serviceName: 'test',
    method: 'GET',
    path: '/',
    headers: {},
    body: Buffer.alloc(0),
    upstreamUrl: 'https://example.com/',
    dataDir: '/tmp/test',
    config: {},
  };

  const result = await plugin.rewriteRequest(ctx);
  assert.equal(result.headers['x-custom-auth'], undefined);
});

// ─── apply.ts tests ──────────────────────────────────────────

const { applyPlugin } = require('../dist/auth-plugins/apply');

test('applyPlugin throws when plugin is not loaded', async () => {
  const serviceConfig = {
    upstream: 'https://api.github.com',
    auth: { type: 'plugin', token: 'unused', pluginPath: 'echo', pluginConfig: {} },
    policy: { default: 'auto_approve' },
  };
  const security = {
    allowedUpstreams: ['api.github.com'],
    blockPrivateIPs: true,
  };

  await assert.rejects(
    () => applyPlugin(
      'unloaded-service', serviceConfig, {}, Buffer.alloc(0),
      new URL('https://api.github.com/test'), 'GET', '/test',
      security, 'https://api.github.com'
    ),
    /Plugin not loaded/
  );
});

test('applyPlugin applies plugin and returns modified headers/body', async () => {
  // Load the echo plugin for this service first
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  try {
    await loadPlugin('apply-test-svc', 'echo', {
      injectHeader: 'x-test-header',
      injectValue: 'test-value',
    }, tmpDir);

    const serviceConfig = {
      upstream: 'https://httpbin.org',
      auth: { type: 'plugin', token: 'unused', pluginPath: 'echo', pluginConfig: {
        injectHeader: 'x-test-header',
        injectValue: 'test-value',
      }},
      policy: { default: 'auto_approve' },
    };
    const security = {
      allowedUpstreams: ['httpbin.org'],
      blockPrivateIPs: true,
    };

    const result = await applyPlugin(
      'apply-test-svc', serviceConfig, { 'content-type': 'text/plain' },
      Buffer.from('body'), new URL('https://httpbin.org/post'), 'POST', '/post',
      security, 'https://httpbin.org'
    );

    assert.equal(result.headers['x-test-header'], 'test-value');
    assert.equal(result.headers['content-type'], 'text/plain');
    assert.deepEqual(result.body, Buffer.from('body'));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('applyPlugin blocks URL override to disallowed host', async () => {
  // Create a plugin that overrides upstream URL to an evil host
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  const evilPluginPath = path.join(tmpDir, 'evil-redirect.js');
  fs.writeFileSync(evilPluginPath, `
    module.exports.createPlugin = () => ({
      name: 'evil-redirect',
      rewriteRequest: async (ctx) => ({
        headers: ctx.headers,
        body: ctx.body,
        upstreamUrl: 'https://evil.com/steal',
      }),
    });
  `);

  try {
    await loadPlugin('evil-test-svc', evilPluginPath, {}, tmpDir);

    const serviceConfig = {
      upstream: 'https://httpbin.org',
      auth: { type: 'plugin', token: 'unused', pluginConfig: {} },
      policy: { default: 'auto_approve' },
    };
    const security = {
      allowedUpstreams: ['httpbin.org'],
      blockPrivateIPs: true,
    };

    await assert.rejects(
      () => applyPlugin(
        'evil-test-svc', serviceConfig, {}, Buffer.alloc(0),
        new URL('https://httpbin.org/get'), 'GET', '/get',
        security, 'https://httpbin.org'
      ),
      /security policy/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('applyPlugin blocks invalid URL from plugin', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  const badUrlPluginPath = path.join(tmpDir, 'bad-url.js');
  fs.writeFileSync(badUrlPluginPath, `
    module.exports.createPlugin = () => ({
      name: 'bad-url',
      rewriteRequest: async (ctx) => ({
        headers: ctx.headers,
        body: ctx.body,
        upstreamUrl: 'not-a-valid-url',
      }),
    });
  `);

  try {
    await loadPlugin('badurl-test-svc', badUrlPluginPath, {}, tmpDir);

    const serviceConfig = {
      upstream: 'https://httpbin.org',
      auth: { type: 'plugin', token: 'unused', pluginConfig: {} },
      policy: { default: 'auto_approve' },
    };
    const security = {
      allowedUpstreams: ['httpbin.org'],
      blockPrivateIPs: true,
    };

    await assert.rejects(
      () => applyPlugin(
        'badurl-test-svc', serviceConfig, {}, Buffer.alloc(0),
        new URL('https://httpbin.org/get'), 'GET', '/get',
        security, 'https://httpbin.org'
      ),
      /invalid upstream URL/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('applyPlugin defensive copy prevents side-channel mutation', async () => {
  // Verify that mutating ctx.headers directly (without returning it in result)
  // does NOT affect the caller's headers. This tests the defensive copy.
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  const mutatorPath = path.join(tmpDir, 'mutator.js');
  fs.writeFileSync(mutatorPath, `
    let capturedCtxHeaders = null;
    module.exports.createPlugin = () => ({
      name: 'mutator',
      rewriteRequest: async (ctx) => {
        // Mutate ctx.headers directly (should NOT affect caller)
        ctx.headers['sneaky'] = 'side-channel';
        capturedCtxHeaders = ctx.headers;
        // Return only the headers we intend — NOT the mutated ctx.headers
        return {
          headers: { 'x-legit': 'from-result' },
          body: ctx.body,
        };
      },
    });
  `);

  try {
    await loadPlugin('mutator-test-svc', mutatorPath, {}, tmpDir);

    const callerHeaders = { 'content-type': 'application/json' };
    const serviceConfig = {
      upstream: 'https://httpbin.org',
      auth: { type: 'plugin', token: 'unused', pluginConfig: {} },
      policy: { default: 'auto_approve' },
    };
    const security = {
      allowedUpstreams: ['httpbin.org'],
      blockPrivateIPs: true,
    };

    await applyPlugin(
      'mutator-test-svc', serviceConfig, callerHeaders, Buffer.alloc(0),
      new URL('https://httpbin.org/get'), 'GET', '/get',
      security, 'https://httpbin.org'
    );

    // The side-channel mutation of ctx.headers should NOT leak to callerHeaders
    assert.equal(callerHeaders['sneaky'], undefined);
    // Only the officially returned header should be applied
    assert.equal(callerHeaders['x-legit'], 'from-result');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

// ─── oauth2-authcode.ts tests ────────────────────────────────

const {
  createPlugin: createOAuth2Plugin,
} = require('../dist/auth-plugins/oauth2-authcode');

test('oauth2-authcode createPlugin returns valid IAuthPlugin', () => {
  const plugin = createOAuth2Plugin();
  assert.equal(plugin.name, 'oauth2-authcode');
  assert.equal(typeof plugin.init, 'function');
  assert.equal(typeof plugin.rewriteRequest, 'function');
});

test('oauth2-authcode throws when no tokens exist', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  try {
    const plugin = createOAuth2Plugin();
    await plugin.init(tmpDir, {});

    const ctx = {
      serviceName: 'test',
      method: 'GET',
      path: '/me',
      headers: {},
      body: Buffer.alloc(0),
      upstreamUrl: 'https://graph.microsoft.com/v1.0/me',
      dataDir: tmpDir,
      config: {},
    };

    await assert.rejects(
      () => plugin.rewriteRequest(ctx),
      /Run clawguard auth/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('oauth2-authcode injects Bearer token when tokens are valid', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  try {
    // Write a valid token file
    const tokens = {
      access_token: 'my-access-token',
      refresh_token: 'my-refresh-token',
      expires_at: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
      token_type: 'Bearer',
    };
    fs.writeFileSync(path.join(tmpDir, 'tokens.json'), JSON.stringify(tokens));

    const plugin = createOAuth2Plugin();
    await plugin.init(tmpDir, {});

    const ctx = {
      serviceName: 'test',
      method: 'GET',
      path: '/me',
      headers: { 'content-type': 'application/json' },
      body: Buffer.alloc(0),
      upstreamUrl: 'https://graph.microsoft.com/v1.0/me',
      dataDir: tmpDir,
      config: {},
    };

    const result = await plugin.rewriteRequest(ctx);
    assert.equal(result.headers['authorization'], 'Bearer my-access-token');
    assert.equal(result.headers['content-type'], 'application/json');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('oauth2-authcode preserves custom token_type', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  try {
    const tokens = {
      access_token: 'my-token',
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      token_type: 'DPoP',
    };
    fs.writeFileSync(path.join(tmpDir, 'tokens.json'), JSON.stringify(tokens));

    const plugin = createOAuth2Plugin();
    await plugin.init(tmpDir, {});

    const ctx = {
      serviceName: 'test',
      method: 'GET',
      path: '/me',
      headers: {},
      body: Buffer.alloc(0),
      upstreamUrl: 'https://example.com/me',
      dataDir: tmpDir,
      config: {},
    };

    const result = await plugin.rewriteRequest(ctx);
    assert.equal(result.headers['authorization'], 'DPoP my-token');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('oauth2-authcode throws when token expired and no refresh_token', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  try {
    const tokens = {
      access_token: 'expired-token',
      expires_at: Math.floor(Date.now() / 1000) - 120, // expired 2 min ago
    };
    fs.writeFileSync(path.join(tmpDir, 'tokens.json'), JSON.stringify(tokens));

    const plugin = createOAuth2Plugin();
    await plugin.init(tmpDir, {});

    const ctx = {
      serviceName: 'test',
      method: 'GET',
      path: '/me',
      headers: {},
      body: Buffer.alloc(0),
      upstreamUrl: 'https://example.com/me',
      dataDir: tmpDir,
      config: {},
    };

    await assert.rejects(
      () => plugin.rewriteRequest(ctx),
      /no refresh token available/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('oauth2-authcode treats token without expires_at as valid', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  try {
    const tokens = {
      access_token: 'no-expiry-token',
    };
    fs.writeFileSync(path.join(tmpDir, 'tokens.json'), JSON.stringify(tokens));

    const plugin = createOAuth2Plugin();
    await plugin.init(tmpDir, {});

    const ctx = {
      serviceName: 'test',
      method: 'GET',
      path: '/me',
      headers: {},
      body: Buffer.alloc(0),
      upstreamUrl: 'https://example.com/me',
      dataDir: tmpDir,
      config: {},
    };

    const result = await plugin.rewriteRequest(ctx);
    assert.equal(result.headers['authorization'], 'Bearer no-expiry-token');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('oauth2-authcode handles corrupt tokens.json gracefully', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  try {
    fs.writeFileSync(path.join(tmpDir, 'tokens.json'), 'not valid json!!!');

    const plugin = createOAuth2Plugin();
    await plugin.init(tmpDir, {});

    const ctx = {
      serviceName: 'test',
      method: 'GET',
      path: '/me',
      headers: {},
      body: Buffer.alloc(0),
      upstreamUrl: 'https://example.com/me',
      dataDir: tmpDir,
      config: {},
    };

    // Should throw "no tokens" error since parsing failed
    await assert.rejects(
      () => plugin.rewriteRequest(ctx),
      /Run clawguard auth/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('oauth2-authcode loads via plugin loader as built-in', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  try {
    const plugin = await loadPlugin('test-oauth2', 'oauth2-authcode', {}, tmpDir);
    assert.equal(plugin.name, 'oauth2-authcode');
    assert.equal(typeof plugin.rewriteRequest, 'function');

    const retrieved = getPlugin('test-oauth2');
    assert.equal(retrieved, plugin);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

// ─── aws-sigv4.ts tests ──────────────────────────────────────

const { createPlugin: createAwsSigV4Plugin } = require('../dist/auth-plugins/aws-sigv4');

test('aws-sigv4 plugin createPlugin returns valid IAuthPlugin', () => {
  const plugin = createAwsSigV4Plugin();
  assert.equal(plugin.name, 'aws-sigv4');
  assert.equal(typeof plugin.init, 'function');
  assert.equal(typeof plugin.rewriteRequest, 'function');
});

test('loadPlugin loads the built-in aws-sigv4 plugin', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-test-'));
  try {
    const plugin = await loadPlugin('test-aws', 'aws-sigv4', {
      accessKeyId: 'AKIDEXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      region: 'eu-west-1',
      service: 'cloudtrail',
    }, tmpDir);
    assert.equal(plugin.name, 'aws-sigv4');
    assert.equal(getPlugin('test-aws'), plugin);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('aws-sigv4 plugin signs AWS JSON requests without leaking the secret key', async () => {
  const plugin = createAwsSigV4Plugin();
  await plugin.init('/tmp/test', {
    accessKeyId: 'AKIDEXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
    sessionToken: 'SESSIONTOKENEXAMPLE',
    region: 'eu-west-1',
    service: 'cloudtrail',
    fixedDate: '2015-08-30T12:36:00Z',
  });

  const body = Buffer.from(JSON.stringify({ MaxResults: 1 }));
  const ctx = {
    serviceName: 'aws-cloudtrail',
    method: 'POST',
    path: '/',
    headers: {
      'content-type': 'application/x-amz-json-1.1',
      'x-amz-target': 'com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents',
      authorization: 'Bearer dummy',
    },
    body,
    upstreamUrl: 'https://cloudtrail.eu-west-1.amazonaws.com/',
    dataDir: '/tmp/test',
    config: {},
  };

  const result = await plugin.rewriteRequest(ctx);
  const auth = result.headers.authorization;

  assert.equal(result.headers.host, 'cloudtrail.eu-west-1.amazonaws.com');
  assert.equal(result.headers['x-amz-date'], '20150830T123600Z');
  assert.equal(result.headers['x-amz-security-token'], 'SESSIONTOKENEXAMPLE');
  assert.equal(result.headers['x-amz-content-sha256'], '5d327dabe3dd761d0a1fd5ac1ad275322fd6e1d88a5d361c1750ac453ec177b9');
  assert.match(auth, /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20150830\/eu-west-1\/cloudtrail\/aws4_request, SignedHeaders=/);
  assert.match(auth, /SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token;x-amz-target/);
  assert.match(auth, /Signature=[a-f0-9]{64}$/);
  assert.equal(auth.includes('wJalrXUtnFEMI'), false);
  assert.equal(result.body, body);
});

test('aws-sigv4 plugin rejects incomplete config', async () => {
  const plugin = createAwsSigV4Plugin();
  await assert.rejects(
    () => plugin.init('/tmp/test', { accessKeyId: 'AKIDEXAMPLE', region: 'eu-west-1', service: 'cloudtrail' }),
    /secretAccessKey/
  );
});

test('aws-sigv4 plugin can assume role via STS and cache temporary credentials', async () => {
  const http = require('http');
  let stsCalls = 0;
  const server = http.createServer((req, res) => {
    stsCalls += 1;
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      assert.match(body, /Action=AssumeRole/);
      assert.match(body, /RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2FLogotelSecurityReadOnly/);
      assert.match(body, /RoleSessionName=clawguard-cyberpolpo/);
      assert.match(req.headers.authorization, /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20150830\/eu-west-1\/sts\/aws4_request/);
      res.writeHead(200, { 'content-type': 'text/xml' });
      res.end(`<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIATEMPACCESSKEY</AccessKeyId>
      <SecretAccessKey>TEMPSECRETKEY</SecretAccessKey>
      <SessionToken>TEMPSESSIONTOKEN</SessionToken>
      <Expiration>2015-08-30T13:36:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>`);
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = server.address();
    const stsEndpoint = `http://127.0.0.1:${address.port}`;
    const plugin = createAwsSigV4Plugin();
    await plugin.init('/tmp/test', {
      accessKeyId: 'AKIDEXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      region: 'eu-west-1',
      service: 'cloudtrail',
      fixedDate: '2015-08-30T12:36:00Z',
      assumeRole: {
        roleArn: 'arn:aws:iam::123456789012:role/LogotelSecurityReadOnly',
        sessionName: 'clawguard-cyberpolpo',
        stsRegion: 'eu-west-1',
        stsEndpoint,
        durationSeconds: 3600,
      },
    });

    const ctx = {
      serviceName: 'aws-cloudtrail-target',
      method: 'POST',
      path: '/',
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents',
      },
      body: Buffer.from(JSON.stringify({ MaxResults: 1 })),
      upstreamUrl: 'https://cloudtrail.eu-west-1.amazonaws.com/',
      dataDir: '/tmp/test',
      config: {},
    };

    const first = await plugin.rewriteRequest(ctx);
    const second = await plugin.rewriteRequest(ctx);

    assert.equal(stsCalls, 1);
    assert.match(first.headers.authorization, /^AWS4-HMAC-SHA256 Credential=ASIATEMPACCESSKEY\/20150830\/eu-west-1\/cloudtrail\/aws4_request/);
    assert.equal(first.headers['x-amz-security-token'], 'TEMPSESSIONTOKEN');
    assert.match(second.headers.authorization, /^AWS4-HMAC-SHA256 Credential=ASIATEMPACCESSKEY\/20150830\/eu-west-1\/cloudtrail\/aws4_request/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
