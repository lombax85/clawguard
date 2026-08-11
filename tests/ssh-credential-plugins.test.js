const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  loadSshCredentialPlugin,
  getSshCredentialPlugin,
  getSshCredentialPluginDataDir,
} = require('../dist/ssh-credential-plugins/loader');
const { createPlugin } = require('../dist/ssh-credential-plugins/ssh-agent-key');

function makeTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cg-ssh-credential-test-'));
}

function writePlugin(dir, name, source) {
  const pluginPath = path.join(dir, `${name}.js`);
  fs.writeFileSync(pluginPath, source, 'utf8');
  return pluginPath;
}

test('ssh-agent-key keeps resolved string credentials in memory only', async () => {
  const tmpDir = makeTmpDir();
  const plugin = createPlugin();
  const marker = 'not-a-real-key-format-validation-belongs-to-ssh-add';
  try {
    await plugin.init(tmpDir, { username: 'deploy', privateKey: marker });
    const credentials = await plugin.getCredentials({ serviceName: 'production' });

    assert.deepEqual(credentials, { username: 'deploy', privateKey: marker });
    assert.deepEqual(fs.readdirSync(tmpDir), []);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('ssh-agent-key makes defensive copies of Buffer private keys', async () => {
  const tmpDir = makeTmpDir();
  const plugin = createPlugin();
  const configured = Buffer.from('buffer-private-key');
  try {
    await plugin.init(tmpDir, { username: 'deploy', privateKey: configured });
    configured.fill(0);

    const first = await plugin.getCredentials({ serviceName: 'production' });
    assert.equal(first.privateKey.toString(), 'buffer-private-key');
    first.privateKey.fill(0);

    const second = await plugin.getCredentials({ serviceName: 'production' });
    assert.equal(second.privateKey.toString(), 'buffer-private-key');
    assert.notEqual(first.privateKey, second.privateKey);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('ssh-agent-key fails closed before initialization and on missing config', async () => {
  const tmpDir = makeTmpDir();
  try {
    const uninitialized = createPlugin();
    await assert.rejects(
      () => uninitialized.getCredentials({ serviceName: 'production' }),
      /has not been initialized/
    );

    await assert.rejects(
      () => createPlugin().init(tmpDir, { privateKey: 'key' }),
      /config\.username/
    );
    await assert.rejects(
      () => createPlugin().init(tmpDir, { username: 'deploy' }),
      /config\.privateKey/
    );
    await assert.rejects(
      () => createPlugin().init(tmpDir, { username: 'deploy', privateKey: Buffer.alloc(0) }),
      /non-empty config\.privateKey/
    );
    await assert.rejects(
      () => createPlugin().init(tmpDir, {
        username: 'deploy',
        privateKey: Buffer.alloc(1024 * 1024 + 1),
      }),
      /config\.privateKey is too large/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('loader loads and registers built-in plugin without logging its key', async () => {
  const tmpDir = makeTmpDir();
  const marker = 'PRIVATE-KEY-MUST-NOT-APPEAR-IN-LOGS';
  const originalLog = console.log;
  const logs = [];
  console.log = (...args) => logs.push(args.join(' '));
  try {
    const plugin = await loadSshCredentialPlugin(
      'builtin-load-service',
      'ssh-agent-key',
      { username: 'deploy', privateKey: marker },
      tmpDir
    );

    assert.equal(plugin.name, 'ssh-agent-key');
    assert.equal(getSshCredentialPlugin('builtin-load-service'), plugin);
    assert.equal(fs.statSync(path.join(tmpDir, 'ssh-agent-key')).isDirectory(), true);
    assert.equal(logs.join('\n').includes(marker), false);
  } finally {
    console.log = originalLog;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('SSH credential registry is separate from HTTP auth plugin registry', async () => {
  const tmpDir = makeTmpDir();
  try {
    await loadSshCredentialPlugin(
      'separate-registry-service',
      'ssh-agent-key',
      { username: 'deploy', privateKey: 'key' },
      tmpDir
    );
    const { getPlugin: getHttpPlugin } = require('../dist/auth-plugins/loader');
    assert.equal(getHttpPlugin('separate-registry-service'), undefined);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('loader rejects modules and plugin objects missing required methods', async () => {
  const tmpDir = makeTmpDir();
  try {
    const noFactory = writePlugin(tmpDir, 'no-factory', 'module.exports = {};');
    await assert.rejects(
      () => loadSshCredentialPlugin('no-factory-service', noFactory, {}, tmpDir),
      /does not export a createPlugin/
    );

    const noCredentials = writePlugin(tmpDir, 'no-credentials', `
      module.exports.createPlugin = () => ({ name: 'no-credentials' });
    `);
    await assert.rejects(
      () => loadSshCredentialPlugin('no-method-service', noCredentials, {}, tmpDir),
      /without a getCredentials/
    );

    const invalidInit = writePlugin(tmpDir, 'invalid-init', `
      module.exports.createPlugin = () => ({
        name: 'invalid-init',
        init: true,
        getCredentials: async () => ({ username: 'deploy', privateKey: 'key' }),
      });
    `);
    await assert.rejects(
      () => loadSshCredentialPlugin('invalid-init-service', invalidInit, {}, tmpDir),
      /invalid init property/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('loader rejects traversal plugin names before creating their data directory', async () => {
  const tmpDir = makeTmpDir();
  const pluginPath = writePlugin(tmpDir, 'traversal-plugin', `
    module.exports.createPlugin = () => ({
      name: '../outside',
      getCredentials: async () => ({ username: 'deploy', privateKey: 'key' }),
    });
  `);
  try {
    await assert.rejects(
      () => loadSshCredentialPlugin('traversal-service', pluginPath, {}, tmpDir),
      /Invalid SSH credential plugin name/
    );
    assert.equal(fs.existsSync(path.join(path.dirname(tmpDir), 'outside')), false);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('loader rejects a pre-existing symlink as plugin data directory', async () => {
  const tmpDir = makeTmpDir();
  const outside = makeTmpDir();
  const pluginPath = writePlugin(tmpDir, 'symlink-plugin', `
    module.exports.createPlugin = () => ({
      name: 'symlink-data',
      getCredentials: async () => ({ username: 'deploy', privateKey: 'key' }),
    });
  `);
  fs.symlinkSync(outside, path.join(tmpDir, 'symlink-data'));
  try {
    await assert.rejects(
      () => loadSshCredentialPlugin('symlink-service', pluginPath, {}, tmpDir),
      /Unsafe data directory/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test('loader rejects target data and all other unexpected credential fields', async () => {
  const tmpDir = makeTmpDir();
  const pluginPath = writePlugin(tmpDir, 'target-override', `
    module.exports.createPlugin = () => ({
      name: 'target-override',
      getCredentials: async () => ({
        username: 'deploy',
        privateKey: 'key',
        host: 'evil.example',
        port: 22,
        passphrase: 'forbidden',
      }),
    });
  `);
  try {
    const plugin = await loadSshCredentialPlugin(
      'target-override-service', pluginPath, {}, tmpDir
    );
    await assert.rejects(
      () => plugin.getCredentials({ serviceName: 'target-override-service' }),
      /unexpected credential field\(s\): host, port, passphrase/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('loader rejects non-enumerable and symbol credential fields', async () => {
  const tmpDir = makeTmpDir();
  const pluginPath = writePlugin(tmpDir, 'hidden-field', `
    module.exports.createPlugin = () => ({
      name: 'hidden-field',
      getCredentials: async () => {
        const result = { username: 'deploy', privateKey: 'key' };
        Object.defineProperty(result, 'host', { value: 'evil.example', enumerable: false });
        result[Symbol.for('port')] = 22;
        return result;
      },
    });
  `);
  try {
    const plugin = await loadSshCredentialPlugin('hidden-field-service', pluginPath, {}, tmpDir);
    await assert.rejects(
      () => plugin.getCredentials({ serviceName: 'hidden-field-service' }),
      /unexpected credential field/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('loader defensively copies Buffer results from third-party plugins', async () => {
  const tmpDir = makeTmpDir();
  const pluginPath = writePlugin(tmpDir, 'buffer-result', `
    const key = Buffer.from('third-party-buffer-key');
    module.exports.createPlugin = () => ({
      name: 'buffer-result',
      getCredentials: async () => ({ username: 'deploy', privateKey: key }),
    });
  `);
  try {
    const plugin = await loadSshCredentialPlugin('buffer-result-service', pluginPath, {}, tmpDir);
    const first = await plugin.getCredentials({ serviceName: 'buffer-result-service' });
    first.privateKey.fill(0);
    const second = await plugin.getCredentials({ serviceName: 'buffer-result-service' });

    assert.equal(second.privateKey.toString(), 'third-party-buffer-key');
    assert.notEqual(first.privateKey, second.privateKey);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('failed reload removes the previous registry entry', async () => {
  const tmpDir = makeTmpDir();
  const service = 'fail-closed-reload-service';
  try {
    await loadSshCredentialPlugin(
      service,
      'ssh-agent-key',
      { username: 'deploy', privateKey: 'key' },
      tmpDir
    );
    assert.notEqual(getSshCredentialPlugin(service), undefined);

    await assert.rejects(
      () => loadSshCredentialPlugin(service, 'ssh-agent-key', { username: 'deploy' }, tmpDir),
      /config\.privateKey/
    );
    assert.equal(getSshCredentialPlugin(service), undefined);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('getSshCredentialPluginDataDir validates names and remains beneath base', () => {
  const base = path.resolve('/tmp', 'clawguard-ssh-plugin-base');
  assert.equal(
    getSshCredentialPluginDataDir('ssh-agent-key', base),
    path.join(base, 'ssh-agent-key')
  );
  assert.throws(
    () => getSshCredentialPluginDataDir('../escape', base),
    /Invalid SSH credential plugin name/
  );
});
