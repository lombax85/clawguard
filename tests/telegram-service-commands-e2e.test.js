const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { TelegramNotifier } = require('../dist/telegram');
const { ApprovalManager } = require('../dist/approval');
const { AuditLogger } = require('../dist/audit');
const { createProxy } = require('../dist/proxy');

// Replace only Telegram's network transport. Commands enter through its public
// message API; requests cross the real proxy, approval manager and SQLite store.
class TelegramTransport extends EventEmitter {
  handlers = [];
  messages = [];
  onText(pattern, callback) { this.handlers.push({ pattern, callback }); }
  async setMyCommands(commands) { this.commands = commands; }
  async sendMessage(chat, text, options) {
    const message = { message_id: this.messages.length + 1, chat: { id: Number(chat) }, text, options };
    this.messages.push(message);
    return message;
  }
  isPolling() { return true; }
  async stopPolling() {}
  async startPolling() {}
  async command(text, overrides = {}) {
    const message = { text, chat: { id: 100 }, from: { id: 7, username: 'owner', is_bot: false }, ...overrides };
    this.emit('message', message);
    for (const { pattern, callback } of this.handlers) {
      const match = pattern.exec(text);
      if (match) await callback(message, match);
    }
  }
}

async function listen(server) {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

async function fixture(run) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-commands-'));
  const dbPath = path.join(directory, 'audit.db');
  let audit = new AuditLogger(dbPath);
  audit.pairUser('100', 'owner');
  const transport = new TelegramTransport();
  const telegramConfig = { botToken: 'test', chatId: '100', messageThreadId: 9,
    allowedApprovers: ['7'], pairing: { enabled: true, secret: 'test-pairing-secret' } };
  let telegram = new TelegramNotifier(telegramConfig, audit, { bot: transport });
  let manager = new ApprovalManager(telegram, audit, 20);
  let hits = 0;
  const upstream = http.createServer((req, res) => {
    hits++;
    assert.equal(req.headers.authorization, 'Bearer upstream-test-token');
    res.setHeader('Content-Type', 'application/json'); res.end('{"ok":true}');
  });
  const upstreamUrl = await listen(upstream);
  const service = { upstream: upstreamUrl, auth: { type: 'bearer', token: 'upstream-test-token' },
    http: { allowPrivateTarget: true, allowedMethods: ['GET', 'POST'] }, policy: { default: 'require_approval' } };
  const config = { server: { agentKey: 'test-agent' }, services: { app: service },
    security: { allowedUpstreams: ['127.0.0.1'], blockPrivateIPs: true, followRedirects: false, maxPayloadLogSize: 1024 },
    admin: { enabled: false }, audit: { logPayload: false } };
  telegram.configureServiceCommands(() => config.services, manager);
  let server = http.createServer(createProxy(config, manager, audit));
  let base = await listen(server);
  const request = async (method = 'GET', alias = 'app') => {
    const response = await fetch(`${base}/${alias}/resource`, { method, headers: { 'X-ClawGuard-Key': 'test-agent' } });
    await response.text();
    return response.status;
  };
  try {
    await run({ transport, config, request, get audit() { return audit; }, get manager() { return manager; },
      hits: () => hits, async restart() {
        await new Promise(resolve => server.close(resolve));
        await telegram.stop(); audit.close();
        audit = new AuditLogger(dbPath);
        transport.handlers = []; transport.removeAllListeners();
        telegram = new TelegramNotifier(telegramConfig, audit, { bot: transport });
        manager = new ApprovalManager(telegram, audit, 20);
        telegram.configureServiceCommands(() => config.services, manager);
        server = http.createServer(createProxy(config, manager, audit)); base = await listen(server);
      } });
  } finally {
    await new Promise(resolve => server.close(resolve));
    await new Promise(resolve => upstream.close(resolve));
    await telegram.stop(); audit.close(); fs.rmSync(directory, { recursive: true, force: true });
  }
}

test('Telegram /help and temporary HTTP approval work through the proxy with mandatory silent logs and revocation', async () => {
  await fixture(async f => {
    await f.transport.command('/help@ClawGuardBot');
    for (const command of ['help', 'status', 'allow', 'revoke', 'showlog', 'pair', 'unpair']) {
      assert.ok(f.transport.commands.some(item => item.command === command));
      assert.ok(f.transport.messages.at(-1).text.includes('/' + command));
    }
    assert.equal(f.transport.messages.at(-1).options.message_thread_id, 9);
    assert.equal(await f.request(), 403);
    await f.transport.command('/allow app 1h');
    assert.equal(f.audit.isShowlogEnabled('100'), true);
    const before = f.transport.messages.length;
    assert.equal(await f.request('POST'), 200);
    assert.equal(await f.request(), 200);
    assert.equal(await f.request('DELETE'), 405, 'grant must not bypass allowed methods');
    assert.equal(f.hits(), 2);
    const logs = f.transport.messages.slice(before);
    assert.equal(logs.length, 2);
    assert.ok(logs.every(msg => msg.options.disable_notification === true && !msg.options.reply_markup));
    assert.ok(logs.every(msg => msg.options.message_thread_id === 9));
    await f.transport.command('/showlog off');
    assert.equal(await f.request(), 200);
    assert.equal(f.transport.messages.at(-1).options.disable_notification, true);
    await f.transport.command('/status');
    assert.match(f.transport.messages.at(-1).text, /app: 60 min/);
    await f.transport.command('/revoke app');
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
    assert.equal(await f.request(), 403);
  });
});

test('temporary grants survive restart, expire, and are invalidated when the service changes', async t => {
  await fixture(async f => {
    await f.transport.command('/allow app 1m');
    await f.restart();
    assert.equal(await f.request(), 200);
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 61_000 });
    assert.equal(await f.request(), 403);
    t.mock.timers.reset();
    await f.transport.command('/allow app 1h');
    f.config.services.app.http.allowedMethods.push('PUT');
    assert.equal(await f.request(), 403);
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
    await f.transport.command('/allow app 1h');
    await f.transport.command('/unpair');
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
    assert.equal(await f.request(), 403);
  });
});

test('temporary approval commands reject other chats, other users, bots, invalid durations and unknown services', async () => {
  await fixture(async f => {
    for (const overrides of [{ chat: { id: 200 } }, { from: { id: 8, is_bot: false } },
      { from: { id: 7, is_bot: true } }, { sender_chat: { id: 100 } }]) {
      await f.transport.command('/allow app 1h', overrides);
      assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
    }
    for (const command of ['/allow app', '/allow app 0m', '/allow app 25h', '/allow app 9999h',
      '/allow app -1m', '/allow app 1s', '/allow missing 1h', '/allow app 1h read_write']) {
      await f.transport.command(command);
      assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
    }
    assert.equal(await f.request(), 403);
  });
});

test('Telegram grants cover fresh SSH decisions and explicit FTP access modes, without reusable protocol approvals', async () => {
  await fixture(async f => {
    f.config.services.ssh = { ...f.config.services.app, protocol: 'ssh', upstream: 'ssh://test.example:22' };
    f.config.services.ftp = { ...f.config.services.app, protocol: 'ftps', upstream: 'ftps://test.example:21' };
    await f.transport.command('/allow ssh 1h');
    assert.equal(await f.manager.checkSshSessionApproval('ssh', f.config.services.ssh, '/exec', '127.0.0.1'), true);
    await f.transport.command('/allow ftp 1h');
    assert.equal(f.audit.getTemporaryServiceApprovals().some(item => item.service === 'ftp'), false);
    await f.transport.command('/allow ftp 1h read_only');
    assert.equal(await f.manager.checkFtpSessionApproval('ftp', f.config.services.ftp, '/lease', '127.0.0.1'), 'read_only');
    await f.transport.command('/allow ftp 1h read_write');
    assert.equal(await f.manager.checkFtpSessionApproval('ftp', f.config.services.ftp, '/lease', '127.0.0.1'), 'read_write');
    assert.deepEqual(f.audit.getActiveApprovals(), []);
    await f.transport.command('/revoke ssh');
    assert.equal(await f.manager.checkSshSessionApproval('ssh', f.config.services.ssh, '/exec', '127.0.0.1'), false);
    f.manager.revokeAll();
    assert.equal(await f.manager.checkFtpSessionApproval('ftp', f.config.services.ftp, '/lease', '127.0.0.1'), false);
  });
});
