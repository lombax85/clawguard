const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createAdminSshKeyTools } = require('../dist/admin-ssh');

const agentProbe = spawnSync('ssh-agent', ['-V'], { encoding: 'utf8' });
const addProbe = spawnSync('ssh-add', ['-l'], { encoding: 'utf8' });
const sshToolsAvailable = agentProbe.error?.code !== 'ENOENT' && addProbe.error?.code !== 'ENOENT';

test('admin SSH key tools generate and inspect an unencrypted Ed25519 key', {
  skip: !sshToolsAvailable,
}, async () => {
  const tools = createAdminSshKeyTools();
  const generated = await tools.generate('clawguard-admin-test');

  assert.match(generated.privateKey, /BEGIN OPENSSH PRIVATE KEY/);
  assert.match(generated.publicKey, /^ssh-ed25519 [A-Za-z0-9+/=]+ clawguard-admin-test$/);
  assert.match(generated.fingerprint, /^SHA256:/);

  const inspected = await tools.inspect(generated.privateKey);
  assert.equal(inspected.publicKey, generated.publicKey);
  assert.equal(inspected.fingerprint, generated.fingerprint);
  assert.equal(JSON.stringify(inspected).includes('OPENSSH PRIVATE KEY'), false);
});

test('admin SSH key inspection rejects invalid private key material', {
  skip: !sshToolsAvailable,
}, async () => {
  await assert.rejects(
    () => createAdminSshKeyTools().inspect('not-a-private-key'),
    /invalid or encrypted/i
  );
});

test('admin SSH host-key scan returns a normalized fingerprint without trusting tool comments', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'clawguard-keyscan-test-'));
  const scanner = path.join(directory, 'ssh-keyscan');
  fs.writeFileSync(scanner, [
    '#!/bin/sh',
    "printf '%s\\n' '# scanner banner'",
    "printf '%s\\n' '[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC tool-comment'",
  ].join('\n'), { mode: 0o700 });

  try {
    const tools = createAdminSshKeyTools('ssh-agent', 'ssh-add', scanner);
    const keys = await tools.scanHost(['127.0.0.1'], 2222);
    assert.equal(keys.length, 1);
    assert.equal(keys[0].algorithm, 'ssh-ed25519');
    assert.equal(keys[0].recommended, true);
    assert.match(keys[0].fingerprint, /^SHA256:/);
    assert.equal(keys[0].publicKey.includes('tool-comment'), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
