const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createPlugin } = require('../dist/ftp-credential-plugins/ftp-password');
const {
  getFtpCredentialPlugin,
  loadFtpCredentialPlugin,
} = require('../dist/ftp-credential-plugins/loader');

function temp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'cg-ftp-plugin-')); }

test('ftp-password retains resolved credentials only in memory and returns disposable copies', async () => {
  const dir = temp();
  const plugin = createPlugin();
  const configured = Buffer.from('upstream-password');
  try {
    await plugin.init(dir, { username: 'ftp-user', password: configured });
    configured.fill(0);
    const first = await plugin.getCredentials({ serviceName: 'files' });
    assert.equal(first.username, 'ftp-user');
    assert.equal(first.password.toString(), 'upstream-password');
    first.password.fill(0);
    const second = await plugin.getCredentials({ serviceName: 'files' });
    assert.equal(second.password.toString(), 'upstream-password');
    assert.deepEqual(fs.readdirSync(dir), []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('FTP credential loader is isolated and never logs passwords', async () => {
  const dir = temp();
  const marker = 'PASSWORD-MUST-NOT-BE-LOGGED';
  const logs = [];
  const original = console.log;
  console.log = (...args) => logs.push(args.join(' '));
  try {
    const plugin = await loadFtpCredentialPlugin(
      'files-plugin-test',
      'ftp-password',
      { username: 'ftp-user', password: marker },
      dir
    );
    assert.equal(getFtpCredentialPlugin('files-plugin-test'), plugin);
    assert.equal(logs.join('\n').includes(marker), false);
    const { getPlugin: getHttpPlugin } = require('../dist/auth-plugins/loader');
    assert.equal(getHttpPlugin('files-plugin-test'), undefined);
  } finally {
    console.log = original;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('FTP credential loader rejects target overrides and malformed credentials', async () => {
  const dir = temp();
  const pluginPath = path.join(dir, 'bad.js');
  fs.writeFileSync(pluginPath, `
    module.exports.createPlugin = () => ({
      name: 'bad-ftp-plugin',
      getCredentials: async () => ({
        username: 'ftp-user', password: 'secret', host: 'evil.example'
      })
    });
  `);
  try {
    const plugin = await loadFtpCredentialPlugin('bad-ftp-service', pluginPath, {}, dir);
    await assert.rejects(() => plugin.getCredentials({ serviceName: 'bad-ftp-service' }), /unexpected credential fields/);
    await assert.rejects(() => createPlugin().init(dir, { username: 'x', password: 'line\nbreak' }), /non-NUL bytes/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
