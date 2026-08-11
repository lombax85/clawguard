const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { ApprovalManager } = require('../dist/approval');
const { AuditLogger } = require('../dist/audit');
const { buildSshSessionApprovalKeyboard } = require('../dist/telegram');

function createAudit() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-ssh-audit-'));
  const audit = new AuditLogger(path.join(dir, 'audit.db'));
  return {
    audit,
    cleanup() {
      audit.close();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

function serviceConfig(defaultAction = 'auto_approve') {
  return {
    upstream: 'https://unused.example',
    auth: { type: 'bearer', token: 'unused' },
    policy: { default: defaultAction, rules: [] },
  };
}

function fakeTelegram(next) {
  const calls = { ssh: [], clear: [] };
  return {
    calls,
    async requestSshSessionApproval(requestId, service, sessionPath, agentIp, meta) {
      calls.ssh.push({ requestId, service, path: sessionPath, agentIp, meta });
      if (next instanceof Error) throw next;
      if (typeof next === 'function') return next();
      return next;
    },
    clearPendingRequest(requestId) {
      calls.clear.push(requestId);
    },
  };
}

function fakeWebhook() {
  const calls = { required: [], resolved: [] };
  return {
    calls,
    notifyApprovalRequired(...args) { calls.required.push(args); },
    notifyApprovalResolved(...args) { calls.resolved.push(args); },
  };
}

test('SSH Telegram keyboard exposes only one-session approval and deny', () => {
  const keyboard = buildSshSessionApprovalKeyboard('req_123');
  const buttons = keyboard.inline_keyboard.flat();

  assert.deepEqual(buttons, [
    { text: '✅ Approve this session', callback_data: 'approve_ssh_session:req_123' },
    { text: '❌ Deny', callback_data: 'deny:req_123' },
  ]);
  assert.equal(buttons.some((button) => /15m|1h|24h|week|month|forever|path/i.test(button.text)), false);
});

test('SSH approval fails closed without Telegram and emits webhook resolution', async () => {
  const fixture = createAudit();
  try {
    // A legacy cached SSH approval must not be restored or consumed.
    fixture.audit.logApproval('prod', 'SSH_SESSION', 'legacy-user', 3600, null);
    const webhook = fakeWebhook();
    const manager = new ApprovalManager(undefined, fixture.audit, 50, webhook);

    assert.equal(manager.hasActiveApproval('prod', 'SSH_SESSION'), false);
    const approved = await manager.checkSshSessionApproval(
      'prod',
      serviceConfig('auto_approve'),
      '/deploy@app.internal:22/shell/session-1',
      '10.0.0.8',
      { user: 'agent-a', reason: 'maintenance' }
    );

    assert.equal(approved, false);
    assert.equal(manager.getActiveCount(), 0);
    assert.equal(fixture.audit.getRecentApprovals(10).length, 1, 'SSH decision must not persist another approval');
    assert.equal(webhook.calls.required.length, 1);
    assert.equal(webhook.calls.required[0][2], 'SSH_SESSION');
    assert.equal(webhook.calls.resolved.length, 1);
    assert.deepEqual(webhook.calls.resolved[0].slice(1), [false, 'no_telegram']);
  } finally {
    fixture.cleanup();
  }
});

test('SSH approval ignores auto_approve and is consumed once without caching', async () => {
  const fixture = createAudit();
  try {
    const telegram = fakeTelegram({ approved: true, approvedBy: 'alice' });
    const webhook = fakeWebhook();
    const manager = new ApprovalManager(telegram, fixture.audit, 50, webhook);
    const meta = { user: 'agent-a', reason: 'open controlled shell' };

    const first = await manager.checkSshSessionApproval(
      'prod', serviceConfig('auto_approve'), '/deploy@app:22/shell/s1', '10.0.0.8', meta
    );
    const second = await manager.checkSshSessionApproval(
      'prod', serviceConfig('auto_approve'), '/deploy@app:22/shell/s2', '10.0.0.8', meta
    );

    assert.equal(first, true);
    assert.equal(second, true);
    assert.equal(telegram.calls.ssh.length, 2, 'every SSH session must prompt independently');
    assert.deepEqual(telegram.calls.ssh[0].meta, meta);
    assert.equal(manager.getActiveCount(), 0);
    assert.equal(fixture.audit.getRecentApprovals(10).length, 0);
    assert.equal(webhook.calls.required.length, 2);
    assert.equal(webhook.calls.resolved.length, 2);
  } finally {
    fixture.cleanup();
  }
});

test('SSH approval denies unpaired, Telegram error, and timeout outcomes', async () => {
  const cases = [
    {
      name: 'unpaired',
      telegram: () => fakeTelegram({ approved: false, approvedBy: 'unpaired' }),
      timeout: 50,
      expectedBy: 'unpaired',
    },
    {
      name: 'telegram error',
      telegram: () => fakeTelegram(new Error('send failed')),
      timeout: 50,
      expectedBy: 'telegram_error',
    },
    {
      name: 'timeout',
      telegram: () => fakeTelegram(() => new Promise(() => {})),
      timeout: 5,
      expectedBy: 'timeout',
    },
  ];

  for (const scenario of cases) {
    const fixture = createAudit();
    try {
      const webhook = fakeWebhook();
      const manager = new ApprovalManager(
        scenario.telegram(), fixture.audit, scenario.timeout, webhook
      );
      const approved = await manager.checkSshSessionApproval(
        'prod', serviceConfig(), `/deploy@app:22/shell/${scenario.name}`, '10.0.0.8'
      );

      assert.equal(approved, false, scenario.name);
      assert.equal(manager.getActiveCount(), 0, scenario.name);
      assert.equal(fixture.audit.getRecentApprovals(10).length, 0, scenario.name);
      assert.equal(webhook.calls.resolved.length, 1, scenario.name);
      assert.equal(webhook.calls.resolved[0][2], scenario.expectedBy, scenario.name);
    } finally {
      fixture.cleanup();
    }
  }
});

test('SSH approval abort clears the pending Telegram decision during gateway shutdown', async () => {
  const fixture = createAudit();
  try {
    const telegram = fakeTelegram(() => new Promise(() => {}));
    const webhook = fakeWebhook();
    const manager = new ApprovalManager(telegram, fixture.audit, 10_000, webhook);
    const controller = new AbortController();

    const decision = manager.checkSshSessionApproval(
      'prod', serviceConfig(), '/deploy@app:22/shell/shutdown', '10.0.0.8',
      undefined, 10_000, controller.signal
    );
    await new Promise((resolve) => setImmediate(resolve));
    controller.abort();

    assert.equal(await decision, false);
    assert.equal(telegram.calls.ssh.length, 1);
    assert.equal(telegram.calls.clear.length > 0, true);
    assert.deepEqual(webhook.calls.resolved[0].slice(1), [false, 'gateway_shutdown']);
  } finally {
    fixture.cleanup();
  }
});

test('SSH audit supports start, update, finalize, and recent metadata', () => {
  const fixture = createAudit();
  try {
    fixture.audit.startSshSession({
      id: 'session-1',
      startedAt: '2026-08-02T10:00:00.000Z',
      service: 'prod',
      clientIp: '10.0.0.8',
      targetHost: 'app.internal',
      targetPort: 22,
      upstreamUser: 'deploy',
      action: 'exec',
      // Unknown properties are ignored at runtime and have no DB columns.
      command: 'must-not-be-recorded',
      stream: 'must-not-be-recorded',
      privateKey: 'must-not-be-recorded',
    });

    assert.equal(fixture.audit.updateSshSession('session-1', {
      approved: true,
      outcome: 'active',
      leaseExpiresAt: '2026-08-02T10:05:00.000Z',
    }), true);

    assert.equal(fixture.audit.finalizeSshSession('session-1', {
      endedAt: '2026-08-02T10:00:02.000Z',
      outcome: 'completed',
      exitStatus: 23,
      closeReason: 'remote closed\ncleanly',
    }), true);

    const [row] = fixture.audit.getRecentSshSessions(10);
    assert.equal(row.id, 'session-1');
    assert.equal(row.approved, true);
    assert.equal(row.outcome, 'completed');
    assert.equal(row.durationMs, 2000);
    assert.equal(row.exitStatus, 23);
    assert.equal(row.closeReason, 'remote closed cleanly');
    assert.equal(row.leaseExpiresAt, '2026-08-02T10:05:00.000Z');
    assert.equal(row.command, undefined);
    assert.equal(row.stream, undefined);
    assert.equal(row.privateKey, undefined);
    assert.equal(fixture.audit.updateSshSession('missing', { outcome: 'active' }), false);
  } finally {
    fixture.cleanup();
  }
});

test('SSH audit rejects invalid action and target port', () => {
  const fixture = createAudit();
  try {
    const base = {
      id: 'invalid', service: 'prod', clientIp: '10.0.0.8',
      targetHost: 'app.internal', targetPort: 22, upstreamUser: 'deploy', action: 'shell',
    };
    assert.throws(
      () => fixture.audit.startSshSession({ ...base, action: 'sftp' }),
      /Invalid SSH session action/
    );
    assert.throws(
      () => fixture.audit.startSshSession({ ...base, targetPort: 70000 }),
      /Invalid SSH target port/
    );
  } finally {
    fixture.cleanup();
  }
});
