const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const { SshAgentLeaseManager } = require('../dist/ssh-agent-lease');

function findTool(name) {
  try {
    return execFileSync('/usr/bin/env', ['sh', '-c', `command -v ${name}`], {
      encoding: 'utf8',
    }).trim();
  } catch {
    return null;
  }
}

const sshAgentPath = findTool('ssh-agent');
const sshAddPath = findTool('ssh-add');
const sshKeygenPath = findTool('ssh-keygen');

function makeKey(tmpDir) {
  const keyPath = path.join(tmpDir, 'test_key');
  execFileSync(sshKeygenPath, ['-q', '-t', 'ed25519', '-N', '', '-f', keyPath]);
  return fs.readFileSync(keyPath);
}

function makeManager(runtimeDir, overrides = {}) {
  return new SshAgentLeaseManager({
    runtimeDir,
    gatewayUid: typeof process.getuid === 'function' ? process.getuid() : 0,
    gatewayGid: typeof process.getgid === 'function' ? process.getgid() : 0,
    leaseTtlSeconds: 30,
    maxConcurrentLeases: 2,
    sshAgentPath,
    sshAddPath,
    allowNonRootForTests: true,
    ...overrides,
  });
}

test('SSH agent lease loads a key through stdin and removes its socket on release', {
  skip: !sshAgentPath || !sshAddPath || !sshKeygenPath,
}, async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-agent-'));
  const manager = makeManager(path.join(tmpDir, 'runtime'));
  try {
    const lease = await manager.create(makeKey(tmpDir));
    assert.equal(fs.lstatSync(lease.socketPath).isSocket(), true);
    assert.match(lease.id, /^[A-Za-z0-9_-]{43}$/);
    assert.ok(Buffer.byteLength(lease.socketPath) <= 103);
    assert.equal(fs.statSync(path.join(tmpDir, 'runtime')).mode & 0o777, 0o710);
    assert.equal(fs.statSync(path.dirname(lease.socketPath)).mode & 0o777, 0o700);
    assert.equal(fs.statSync(lease.socketPath).mode & 0o777, 0o600);

    const listed = execFileSync(sshAddPath, ['-L'], {
      env: { ...process.env, SSH_AUTH_SOCK: lease.socketPath },
      encoding: 'utf8',
    });
    assert.match(listed, /^ssh-ed25519 /);

    assert.equal(await manager.release(lease.id), true);
    assert.equal(fs.existsSync(lease.socketPath), false);
    assert.equal(manager.activeCount, 0);
  } finally {
    await manager.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('SSH agent lease rejects oversized key material before spawning a tool', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-agent-'));
  const manager = makeManager(path.join(tmpDir, 'runtime'), {
    sshAgentPath: '/bin/false',
    sshAddPath: '/bin/false',
  });
  try {
    await assert.rejects(
      () => manager.create(Buffer.alloc(1024 * 1024 + 1)),
      /private key is too large/
    );
    assert.equal(manager.activeCount, 0);
    assert.deepEqual(fs.readdirSync(path.join(tmpDir, 'runtime')), []);
  } finally {
    await manager.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('SSH agent lease rejects invalid private keys without leaking a socket', {
  skip: !sshAgentPath || !sshAddPath,
}, async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-agent-'));
  const runtimeDir = path.join(tmpDir, 'runtime');
  const manager = makeManager(runtimeDir);
  try {
    await assert.rejects(() => manager.create('not a private key'), /ssh-add rejected/);
    assert.equal(manager.activeCount, 0);
    assert.deepEqual(fs.readdirSync(runtimeDir), []);
  } finally {
    await manager.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('SSH agent lease atomically enforces its concurrency cap for simultaneous creates', {
  skip: !sshAgentPath || !sshAddPath || !sshKeygenPath,
}, async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-agent-'));
  const manager = makeManager(path.join(tmpDir, 'runtime'), { maxConcurrentLeases: 1 });
  try {
    const key = makeKey(tmpDir);
    const results = await Promise.allSettled([
      manager.create(key),
      manager.create(key),
    ]);
    const fulfilled = results.filter((result) => result.status === 'fulfilled');
    const rejected = results.filter((result) => result.status === 'rejected');

    assert.equal(fulfilled.length, 1);
    assert.equal(rejected.length, 1);
    assert.match(String(rejected[0].reason), /capacity reached/);
    assert.equal(manager.activeCount, 1);
    await manager.release(fulfilled[0].value.id);
  } finally {
    await manager.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('SSH agent lease rejects runtime directories too long for portable Unix sockets', () => {
  const runtimeDir = path.join(os.tmpdir(), 'x'.repeat(140));
  assert.throws(() => makeManager(runtimeDir, {
    sshAgentPath: '/bin/false',
    sshAddPath: '/bin/false',
  }), /runtimeDir is too long for a portable Unix socket path/);
  assert.equal(fs.existsSync(runtimeDir), false);
});

test('SSH agent startup failure includes bounded stderr diagnostics', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-agent-'));
  const failingAgent = path.join(tmpDir, 'failing-agent.sh');
  fs.writeFileSync(failingAgent, '#!/bin/sh\nprintf "agent startup failed\\n" >&2\nexit 7\n', { mode: 0o700 });
  const manager = makeManager(path.join(tmpDir, 'runtime'), {
    sshAgentPath: failingAgent,
    startupTimeoutMs: 1000,
  });
  try {
    await assert.rejects(
      () => manager.create('not-used'),
      /ssh-agent exited before creating its socket: agent startup failed/
    );
    assert.deepEqual(fs.readdirSync(path.join(tmpDir, 'runtime')), []);
  } finally {
    await manager.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
