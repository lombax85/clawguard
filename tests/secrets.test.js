const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { parseSecretRef, resolveSecretValue, createSecretProviders } = require('../dist/secrets/provider');
const { StaticSecretProvider } = require('../dist/secrets/static');
const { VaultSecretProvider } = require('../dist/secrets/vault');

// ─── parseSecretRef ─────────────────────────────────────────

test('parseSecretRef parses vault KV v2 reference', () => {
  const ref = parseSecretRef('vault:secret/data/github#token');
  assert.deepEqual(ref, { provider: 'vault', path: 'secret/data/github', field: 'token' });
});

test('parseSecretRef parses vault KV v1 reference', () => {
  const ref = parseSecretRef('vault:secret/github#token');
  assert.deepEqual(ref, { provider: 'vault', path: 'secret/github', field: 'token' });
});

test('parseSecretRef returns null for plain string', () => {
  assert.equal(parseSecretRef('ghp_my-plain-token'), null);
});

test('parseSecretRef returns null for string without field', () => {
  assert.equal(parseSecretRef('vault:secret/data/github'), null);
});

test('parseSecretRef returns null for empty string', () => {
  assert.equal(parseSecretRef(''), null);
});

test('parseSecretRef handles provider names like aws, gcp, azure', () => {
  const aws = parseSecretRef('aws:arn/my-secret#api_key');
  assert.deepEqual(aws, { provider: 'aws', path: 'arn/my-secret', field: 'api_key' });

  const gcp = parseSecretRef('gcp:projects/my-project/secrets/my-secret#value');
  assert.deepEqual(gcp, { provider: 'gcp', path: 'projects/my-project/secrets/my-secret', field: 'value' });
});

// ─── StaticSecretProvider ───────────────────────────────────

test('StaticSecretProvider returns value as-is', async () => {
  const provider = new StaticSecretProvider();
  assert.equal(provider.name, 'static');
  const result = await provider.resolve('my-token-value');
  assert.equal(result, 'my-token-value');
});

// ─── resolveSecretValue ─────────────────────────────────────

test('resolveSecretValue returns plain strings unchanged', async () => {
  const providers = new Map();
  providers.set('static', new StaticSecretProvider());
  const result = await resolveSecretValue('ghp_my-plain-token', providers);
  assert.equal(result, 'ghp_my-plain-token');
});

test('resolveSecretValue throws on unknown provider', async () => {
  const providers = new Map();
  providers.set('static', new StaticSecretProvider());
  await assert.rejects(
    () => resolveSecretValue('unknown:path/to/secret#field', providers),
    { message: /Unknown secret provider: "unknown"/ }
  );
});

// ─── createSecretProviders ──────────────────────────────────

test('createSecretProviders returns static provider when no config', async () => {
  const providers = await createSecretProviders(undefined);
  assert.equal(providers.has('static'), true);
  assert.equal(providers.size, 1);
});

// ─── VaultSecretProvider with mock server ───────────────────

test('VaultSecretProvider resolves KV v2 secret from mock Vault', async () => {
  // Start a mock Vault HTTP server
  const mockData = {
    data: {
      data: { token: 'ghp_real-github-token', username: 'myuser' },
      metadata: { version: 1 },
    },
  };

  const server = http.createServer((req, res) => {
    // Verify Vault token header
    assert.equal(req.headers['x-vault-token'], 'test-vault-token');

    if (req.url === '/v1/secret/data/github') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(mockData));
    } else {
      res.writeHead(404);
      res.end('not found');
    }
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    const vault = new VaultSecretProvider({
      address: `http://127.0.0.1:${port}`,
      auth: { method: 'token', token: 'test-vault-token' },
    });
    await vault.init();

    const token = await vault.resolve('secret/data/github#token');
    assert.equal(token, 'ghp_real-github-token');

    const username = await vault.resolve('secret/data/github#username');
    assert.equal(username, 'myuser');
  } finally {
    server.close();
  }
});

test('VaultSecretProvider throws on missing field', async () => {
  const mockData = {
    data: {
      data: { token: 'value' },
      metadata: { version: 1 },
    },
  };

  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(mockData));
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    const vault = new VaultSecretProvider({
      address: `http://127.0.0.1:${port}`,
      auth: { method: 'token', token: 'test-token' },
    });
    await vault.init();

    await assert.rejects(
      () => vault.resolve('secret/data/test#nonexistent'),
      { message: /Field "nonexistent" not found/ }
    );
  } finally {
    server.close();
  }
});

test('VaultSecretProvider resolves KV v1 secret', async () => {
  // KV v1 has data directly under .data (no nested .data.data)
  const mockData = {
    data: { api_key: 'sk-v1-secret-key' },
  };

  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(mockData));
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    const vault = new VaultSecretProvider({
      address: `http://127.0.0.1:${port}`,
      auth: { method: 'token', token: 'test-token' },
    });
    await vault.init();

    const key = await vault.resolve('secret/myapp#api_key');
    assert.equal(key, 'sk-v1-secret-key');
  } finally {
    server.close();
  }
});

test('VaultSecretProvider caches secrets', async () => {
  let requestCount = 0;
  const mockData = {
    data: { data: { token: 'cached-value' } },
  };

  const server = http.createServer((req, res) => {
    requestCount++;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(mockData));
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    const vault = new VaultSecretProvider({
      address: `http://127.0.0.1:${port}`,
      auth: { method: 'token', token: 'test-token' },
      cacheTTL: 60,
    });
    await vault.init();

    // First call hits the server
    await vault.resolve('secret/data/test#token');
    assert.equal(requestCount, 1);

    // Second call should use cache
    await vault.resolve('secret/data/test#token');
    assert.equal(requestCount, 1);
  } finally {
    server.close();
  }
});

test('VaultSecretProvider sends X-Vault-Namespace header when configured', async () => {
  let receivedNamespace = null;
  const mockData = { data: { data: { token: 'ns-value' } } };

  const server = http.createServer((req, res) => {
    receivedNamespace = req.headers['x-vault-namespace'];
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(mockData));
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    const vault = new VaultSecretProvider({
      address: `http://127.0.0.1:${port}`,
      namespace: 'admin/team1',
      auth: { method: 'token', token: 'test-token' },
    });
    await vault.init();

    await vault.resolve('secret/data/test#token');
    assert.equal(receivedNamespace, 'admin/team1');
  } finally {
    server.close();
  }
});

test('VaultSecretProvider uses VAULT_TOKEN env var over config', async () => {
  let receivedToken = null;
  const mockData = { data: { data: { token: 'value' } } };

  const server = http.createServer((req, res) => {
    receivedToken = req.headers['x-vault-token'];
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(mockData));
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  const origToken = process.env['VAULT_TOKEN'];
  try {
    process.env['VAULT_TOKEN'] = 'env-override-token';

    const vault = new VaultSecretProvider({
      address: `http://127.0.0.1:${port}`,
      auth: { method: 'token', token: 'config-token' },
    });
    await vault.init();

    await vault.resolve('secret/data/test#token');
    assert.equal(receivedToken, 'env-override-token');
  } finally {
    if (origToken !== undefined) {
      process.env['VAULT_TOKEN'] = origToken;
    } else {
      delete process.env['VAULT_TOKEN'];
    }
    server.close();
  }
});

test('VaultSecretProvider uses VAULT_ADDR env var over config', async () => {
  const mockData = { data: { data: { token: 'from-env-addr' } } };

  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(mockData));
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  const origAddr = process.env['VAULT_ADDR'];
  try {
    process.env['VAULT_ADDR'] = `http://127.0.0.1:${port}`;

    const vault = new VaultSecretProvider({
      address: 'http://wrong-host:9999',
      auth: { method: 'token', token: 'test-token' },
    });
    await vault.init();

    const token = await vault.resolve('secret/data/test#token');
    assert.equal(token, 'from-env-addr');
  } finally {
    if (origAddr !== undefined) {
      process.env['VAULT_ADDR'] = origAddr;
    } else {
      delete process.env['VAULT_ADDR'];
    }
    server.close();
  }
});

test('VaultSecretProvider init throws without token', async () => {
  const origToken = process.env['VAULT_TOKEN'];
  try {
    delete process.env['VAULT_TOKEN'];

    const vault = new VaultSecretProvider({
      address: 'http://localhost:8200',
      auth: { method: 'token' },
    });

    await assert.rejects(
      () => vault.init(),
      { message: /Vault token auth requires a token/ }
    );
  } finally {
    if (origToken !== undefined) {
      process.env['VAULT_TOKEN'] = origToken;
    }
  }
});

// ─── Full integration: resolveSecretValue with vault ────────

test('resolveSecretValue resolves vault: prefixed token via mock', async () => {
  const mockData = { data: { data: { token: 'resolved-secret' } } };

  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(mockData));
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    const providers = await createSecretProviders({
      vault: {
        address: `http://127.0.0.1:${port}`,
        auth: { method: 'token', token: 'test-token' },
      },
    });

    const result = await resolveSecretValue('vault:secret/data/myapp#token', providers);
    assert.equal(result, 'resolved-secret');
  } finally {
    server.close();
  }
});
