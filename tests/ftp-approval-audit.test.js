const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');

const { ApprovalManager } = require('../dist/approval');
const { AuditLogger } = require('../dist/audit');
const { buildFtpSessionApprovalKeyboard, TelegramNotifier } = require('../dist/telegram');

function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-ftp-audit-'));
  const audit = new AuditLogger(path.join(dir, 'audit.db'));
  return { audit, close() { audit.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}

function service() {
  return {
    protocol: 'ftps', upstream: 'ftps://files.example.com:21',
    auth: { type: 'plugin', pluginPath: 'ftp-password' },
    policy: { default: 'auto_approve' },
    ftp: { allowPrivateTarget: false, tlsMode: 'explicit' },
  };
}

test('FTP Telegram keyboard exposes one-lease read-only/read-write decisions and deny', () => {
  const buttons = buildFtpSessionApprovalKeyboard('req_123').inline_keyboard.flat();
  assert.deepEqual(buttons, [
    { text: '👁 Read only', callback_data: 'approve_ftp_read_only:req_123' },
    { text: '✍️ Read/write', callback_data: 'approve_ftp_read_write:req_123' },
    { text: '❌ Deny', callback_data: 'deny:req_123' },
  ]);
  assert.equal(buttons.some((button) => /15m|1h|24h|week|month|forever|path/i.test(button.text)), false);
});

test('FTP Telegram callback returns the access mode selected by the approver', async () => {
  class FakeTelegramBot extends EventEmitter {
    onText() {}
    isPolling() { return true; }
    async sendMessage() { return { message_id: 1 }; }
    async answerCallbackQuery() {}
    async editMessageText() {}
    async stopPolling() {}
    async startPolling() {}
  }

  const bot = new FakeTelegramBot();
  const notifier = new TelegramNotifier(
    {
      botToken: 'clawguard-managed',
      chatId: '123',
      pairing: { enabled: false, secret: '' },
    },
    {},
    { bot }
  );

  try {
    const pending = notifier.requestFtpSessionApproval(
      'ftp-mode-callback', 'files', '/lease/callback', '192.0.2.10'
    );
    await new Promise((resolve) => setImmediate(resolve));
    bot.emit('callback_query', {
      id: 'callback-1',
      data: 'approve_ftp_read_only:ftp-mode-callback',
      message: { message_id: 1, chat: { id: 123 } },
      from: { id: 456, first_name: 'Alice' },
    });
    assert.deepEqual(await pending, {
      approved: true,
      approvedBy: 'Alice',
      accessMode: 'read_only',
    });
  } finally {
    await notifier.stop();
  }
});

test('FTP approval is fail-closed, one-shot, and never restores or persists reusable approval', async () => {
  const f = fixture();
  try {
    f.audit.logApproval('files', 'FTP_SESSION', 'legacy', 3600, null);
    const noTelegram = new ApprovalManager(undefined, f.audit);
    assert.equal(noTelegram.hasActiveApproval('files', 'FTP_SESSION'), false);
    assert.equal(await noTelegram.checkFtpSessionApproval(
      'files', service(), '/lease/one', '192.0.2.10'
    ), false);

    const calls = [];
    const modes = ['read_only', 'read_write', undefined];
    const telegram = {
      async requestFtpSessionApproval(...args) {
        calls.push(args);
        return { approved: true, approvedBy: 'alice', accessMode: modes[calls.length - 1] };
      },
      clearPendingRequest() {},
    };
    const manager = new ApprovalManager(telegram, f.audit);
    assert.equal(await manager.checkFtpSessionApproval(
      'files', service(), '/lease/two', '192.0.2.10', { user: 'agent', reason: 'upload' }
    ), 'read_only');
    assert.equal(await manager.checkFtpSessionApproval(
      'files', service(), '/lease/three', '192.0.2.10'
    ), 'read_write');
    assert.equal(await manager.checkFtpSessionApproval(
      'files', service(), '/lease/missing-mode', '192.0.2.10'
    ), false, 'an approval without an explicit FTP access mode must fail closed');
    assert.equal(calls.length, 3);
    assert.equal(manager.getActiveCount(), 0);
    assert.equal(f.audit.getRecentApprovals(10).length, 1, 'only the seeded legacy row should exist');
  } finally {
    f.close();
  }
});

test('FTP audit records metadata but no password or file contents', () => {
  const f = fixture();
  try {
    f.audit.startFtpSession({
      id: 'lease-1',
      startedAt: '2026-08-11T10:00:00.000Z',
      service: 'files',
      protocol: 'ftps',
      clientIp: '192.0.2.10',
      targetHost: 'files.example.com',
      targetPort: 21,
      password: 'must-not-be-recorded',
      contents: 'must-not-be-recorded',
    });
    assert.equal(f.audit.updateFtpSession('lease-1', {
      approved: true, outcome: 'active', upstreamUser: 'deploy', controlPort: 21210,
      accessMode: 'read_only',
      leaseExpiresAt: '2026-08-11T10:01:00.000Z',
    }), true);
    assert.equal(f.audit.finalizeFtpSession('lease-1', {
      endedAt: '2026-08-11T10:00:02.000Z', outcome: 'closed', closeReason: 'client\nclosed',
    }), true);
    const [row] = f.audit.getRecentFtpSessions(10);
    assert.equal(row.approved, true);
    assert.equal(row.accessMode, 'read_only');
    assert.equal(row.durationMs, 2000);
    assert.equal(row.closeReason, 'client closed');
    assert.equal(row.password, undefined);
    assert.equal(row.contents, undefined);
  } finally {
    f.close();
  }
});
