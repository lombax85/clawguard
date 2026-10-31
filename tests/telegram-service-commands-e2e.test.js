const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { setTimeout: delay } = require('node:timers/promises');
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
  answers = [];
  onText(pattern, callback) { this.handlers.push({ pattern, callback }); }
  async setMyCommands(commands) { this.commands = commands; }
  async sendMessage(chat, text, options) {
    const message = { message_id: this.messages.length + 1, chat: { id: Number(chat) }, text, options };
    this.messages.push(message);
    return message;
  }
  async editMessageText(text, options) {
    const message = this.messages.find(item => item.message_id === options.message_id && String(item.chat.id) === String(options.chat_id));
    assert.ok(message, 'edited message must exist');
    message.text = text;
    message.options = { ...message.options, ...options };
    return message;
  }
  async answerCallbackQuery(id, options) { this.answers.push({ id, ...options }); }
  async tap(message, data, overrides = {}) {
    const query = { id: `tap-${this.answers.length}`, from: { id: 7, username: 'owner', is_bot: false },
      data, message: structuredClone(message), ...overrides };
    for (const listener of this.listeners('callback_query')) await listener(query);
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

function button(message, text) {
  const match = message.options.reply_markup?.inline_keyboard.flat().find(item => item.text === text);
  assert.ok(match, `Missing button: ${text}`);
  assert.ok(Buffer.byteLength(match.callback_data) <= 64, 'Telegram callback data must fit in 64 bytes');
  return match.callback_data;
}

async function listen(server) {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

async function fixture(run, approvalTimeoutMs = 20) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-commands-'));
  const dbPath = path.join(directory, 'audit.db');
  let audit = new AuditLogger(dbPath);
  audit.pairUser('100', 'owner');
  const transport = new TelegramTransport();
  const telegramConfig = { botToken: 'test', chatId: '100', messageThreadId: 9,
    allowedApprovers: ['7'], pairing: { enabled: true, secret: 'test-pairing-secret' } };
  let telegram = new TelegramNotifier(telegramConfig, audit, { bot: transport });
  let manager = new ApprovalManager(telegram, audit, approvalTimeoutMs);
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
        manager = new ApprovalManager(telegram, audit, approvalTimeoutMs);
        telegram.configureServiceCommands(() => config.services, manager);
        server = http.createServer(createProxy(config, manager, audit)); base = await listen(server);
      } });
  } finally {
    await new Promise(resolve => server.close(resolve));
    await new Promise(resolve => upstream.close(resolve));
    await telegram.stop(); audit.close(); fs.rmSync(directory, { recursive: true, force: true });
  }
}

test('Telegram /help and temporary HTTP approval work through the proxy with optional silent logs and revocation', async () => {
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
    const muted = f.transport.messages.length;
    assert.equal(await f.request(), 200);
    assert.equal(f.transport.messages.length, muted, 'showlog off must also mute temporary approvals');
    await f.transport.command('/status');
    assert.match(f.transport.messages.at(-1).text, /app: 60 min/);
    await f.transport.command('/revoke app');
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
    assert.equal(await f.request(), 403);
  });
});

async function approveRequest(f, method, alias, choice) {
  const before = f.transport.messages.length;
  const response = f.request(method, alias);
  let prompt;
  for (let attempt = 0; attempt < 100 && !prompt; attempt++) {
    prompt = f.transport.messages.slice(before).find(msg => msg.options.reply_markup);
    if (!prompt) await delay(5);
  }
  assert.ok(prompt, 'request must ask for a Telegram decision');
  await f.transport.tap(prompt, button(prompt, choice));
  return response;
}

test('/allow 30m replaces longer cached approvals for that service, including after restart', async t => {
  for (const restart of [false, true]) {
    await t.test(restart ? 'with restart' : 'without restart', async t => {
      await fixture(async f => {
        f.config.services.other = structuredClone(f.config.services.app);
        assert.equal(await approveRequest(f, 'GET', 'app', '✅ 1h'), 200);
        assert.equal(await approveRequest(f, 'POST', 'app', '🎯 24h-path'), 200);
        assert.equal(await approveRequest(f, 'GET', 'other', '✅ 1h'), 200);
        await f.transport.command('/allow app 30m');
        const [grant] = f.audit.getTemporaryServiceApprovals();
        if (restart) await f.restart();
        t.mock.timers.enable({ apis: ['Date'], now: grant.expiresAt - 1 });
        try {
          assert.equal(await f.request(), 200);
          assert.equal(await f.request('POST'), 200);
          t.mock.timers.setTime(grant.expiresAt);
          const before = f.transport.messages.length;
          assert.equal(await f.request(), 403, 'GET must ask again at the exact expiry');
          assert.equal(await f.request('POST'), 403, 'path-scoped approval must not resume');
          assert.ok(f.transport.messages.slice(before).some(msg => msg.options.reply_markup));
          assert.equal(await f.request('GET', 'other'), 200, 'other services retain their approvals');
          await f.restart();
          assert.equal(await f.request(), 403, 'a restart must not restore the replaced approval');
        } finally { t.mock.timers.reset(); }
      }, 750);
    });
  }
});

test('/showlog off mutes HTTP, SSH and FTP grants across restart; on restores silent logs', async () => {
  await fixture(async f => {
    // An old pairing must not become a new recipient when temporary logs
    // start to use the same preference as ordinary automatic-call logs.
    f.audit.pairUser('200', 'old-chat');
    f.audit.setShowlog('200', true);
    f.config.services.automatic = { ...f.config.services.app, policy: { default: 'auto_approve' } };
    f.config.services.ssh = { ...f.config.services.app, protocol: 'ssh', upstream: 'ssh://test.example:22' };
    f.config.services.ftp = { ...f.config.services.app, protocol: 'ftps', upstream: 'ftps://test.example:21' };
    for (const command of ['/allow app 30m', '/allow ssh 30m', '/allow ftp 30m read_only']) {
      await f.transport.command(command);
    }
    await f.transport.command('/showlog off');
    for (const restart of [false, true]) {
      if (restart) await f.restart();
      const before = f.transport.messages.length;
      assert.equal(await f.request(), 200);
      assert.equal(await f.request('GET', 'automatic'), 200);
      assert.equal(await f.manager.checkSshSessionApproval('ssh', f.config.services.ssh, '/exec', '127.0.0.1'), true);
      assert.equal(await f.manager.checkFtpSessionApproval('ftp', f.config.services.ftp, '/lease', '127.0.0.1'), 'read_only');
      assert.equal(f.transport.messages.length, before);
    }
    await f.transport.command('/showlog on');
    const before = f.transport.messages.length;
    assert.equal(await f.request(), 200);
    assert.equal(await f.manager.checkSshSessionApproval('ssh', f.config.services.ssh, '/exec', '127.0.0.1'), true);
    assert.equal(await f.manager.checkFtpSessionApproval('ftp', f.config.services.ftp, '/lease', '127.0.0.1'), 'read_only');
    const logs = f.transport.messages.slice(before);
    assert.equal(logs.length, 3);
    assert.ok(logs.every(msg => msg.options.disable_notification === true));
    await f.transport.command('/showlog off');
    await f.transport.command('/allow app 15m');
    assert.equal(f.audit.isShowlogEnabled('100'), true, 'a new allow enables logs again');
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

test('/allow buttons select a service and duration, grant only once, keep silent logs and revoke through the proxy', async () => {
  await fixture(async f => {
    await f.transport.command('/allow');
    const menu = f.transport.messages.at(-1);
    assert.equal(menu.options.message_thread_id, 9);
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
    await f.transport.tap(menu, button(menu, 'app'));
    const beforeBack = button(menu, '1h');
    await f.transport.tap(menu, button(menu, '← Services'));
    await f.transport.tap(menu, beforeBack);
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
    await f.transport.tap(menu, button(menu, 'app'));
    assert.match(menu.text, /Target: http:\/\/127.0.0.1:/);
    assert.match(menu.text, /approve all requests/);
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
    for (const duration of ['15m', '30m', '1h', '4h', '8h', '24h']) button(menu, duration);
    const durationButton = button(menu, '1h');
    await Promise.all([f.transport.tap(menu, durationButton), f.transport.tap(menu, durationButton)]);
    const [grant] = f.audit.getTemporaryServiceApprovals();
    assert.ok(grant);
    assert.equal(grant.expiresAt - grant.approvedAt, 3_600_000);
    assert.equal(grant.service, 'app');
    assert.equal(f.audit.isShowlogEnabled('100'), true);
    assert.equal(await f.request('POST'), 200);
    assert.equal(f.transport.messages.at(-1).options.disable_notification, true);
    await f.transport.tap(menu, durationButton);
    assert.deepEqual(f.audit.getTemporaryServiceApprovals(), [grant], 'replay must not extend or duplicate a grant');
    await f.transport.tap(menu, button(menu, '🔒 Revoke now'));
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
    assert.deepEqual(menu.options.reply_markup.inline_keyboard, []);
    assert.equal(await f.request(), 403);
  });
});

test('direct service menus require explicit FTP access and cancellation never grants', async () => {
  await fixture(async f => {
    f.config.services.ftp = { ...f.config.services.app, protocol: 'ftps', upstream: 'ftps://test.example:21' };
    await f.transport.command('/allow ftp');
    let menu = f.transport.messages.at(-1);
    const initialMode = button(menu, '✍️ Read/write');
    await f.transport.tap(menu, button(menu, '👁 Read only'));
    assert.match(menu.text, /Access: Read only/);
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
    await f.transport.tap(menu, initialMode);
    assert.match(f.transport.answers.at(-1).text, /expired/);
    await f.transport.tap(menu, button(menu, '30m'));
    assert.equal(await f.manager.checkFtpSessionApproval('ftp', f.config.services.ftp, '/lease', '127.0.0.1'), 'read_only');
    assert.equal(f.audit.getTemporaryServiceApprovals()[0].expiresAt - f.audit.getTemporaryServiceApprovals()[0].approvedAt, 1_800_000);
    await f.transport.command('/allow ftp');
    menu = f.transport.messages.at(-1);
    await f.transport.tap(menu, button(menu, '✍️ Read/write'));
    await f.transport.tap(menu, button(menu, '15m'));
    assert.equal(await f.manager.checkFtpSessionApproval('ftp', f.config.services.ftp, '/lease', '127.0.0.1'), 'read_write');
    await f.transport.command('/allow app');
    menu = f.transport.messages.at(-1);
    const oldButton = button(menu, '24h');
    await f.transport.tap(menu, button(menu, 'Cancel'));
    await f.transport.tap(menu, oldButton);
    assert.equal(f.audit.getTemporaryServiceApprovals().some(item => item.service === 'app'), false);
  });
});

test('menu callbacks reject other accounts, chats, messages and unoffered actions without consuming the owner choice', async () => {
  await fixture(async f => {
    await f.transport.command('/allow app');
    const menu = f.transport.messages.at(-1);
    const data = button(menu, '1h');
    for (const overrides of [{ from: { id: 8, is_bot: false } }, { from: { id: 7, is_bot: true } },
      { message: { ...menu, chat: { id: 200 } } }, { message: { ...menu, message_id: 9999 } }]) {
      await f.transport.tap(menu, data, overrides);
      assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
    }
    for (const forged of [data.replace(':duration:1h', ':duration:48h'), data.replace(':duration:1h', ':revoke'),
      data + ':extra', data.replace(':duration:1h', ':mode:read_write')]) {
      await f.transport.tap(menu, forged);
      assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
    }
    await f.transport.tap(menu, data);
    assert.equal(await f.request(), 200);
  });
});

test('menus expire, bind the reviewed configuration and stop working after restart or unpairing', async t => {
  await fixture(async f => {
    await f.transport.command('/allow app');
    let menu = f.transport.messages.at(-1);
    let data = button(menu, '1h');
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 601_000 });
    await f.transport.tap(menu, data);
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
    t.mock.timers.reset();
    await f.transport.command('/allow app');
    menu = f.transport.messages.at(-1);
    data = button(menu, '1h');
    f.config.services.app.http.allowedMethods.push('PUT');
    await f.transport.tap(menu, data);
    assert.match(f.transport.answers.at(-1).text, /Service changed/);
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
    await f.transport.command('/allow app');
    menu = f.transport.messages.at(-1);
    data = button(menu, '1h');
    await f.restart();
    await f.transport.tap(menu, data);
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
    await f.transport.command('/allow app');
    menu = f.transport.messages.at(-1);
    data = button(menu, '1h');
    await f.transport.command('/unpair');
    await f.transport.tap(menu, data);
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
  });
});

test('service menus paginate long aliases with bounded callback data and never remap an index', async () => {
  await fixture(async f => {
    for (let i = 0; i < 17; i++) f.config.services[`service-${String(i).padStart(2, '0')}-${'x'.repeat(53)}`] = structuredClone(f.config.services.app);
    await f.transport.command('/allow');
    const menu = f.transport.messages.at(-1);
    const firstApp = button(menu, 'app');
    await f.transport.tap(menu, button(menu, 'Next →'));
    await f.transport.tap(menu, firstApp);
    assert.match(f.transport.answers.at(-1).text, /expired/);
    await f.transport.tap(menu, button(menu, 'Next →'));
    const lastAlias = Object.keys(f.config.services).sort().at(-1);
    const select = button(menu, lastAlias);
    delete f.config.services.app;
    await f.transport.tap(menu, select);
    await f.transport.tap(menu, button(menu, '4h'));
    assert.equal(f.audit.getTemporaryServiceApprovals()[0].service, lastAlias);
  });
});

test('a stale revoke button cannot revoke a renewed grant and typed commands also provide a revoke button', async () => {
  await fixture(async f => {
    await f.transport.command('/allow app 1h');
    const oldMenu = f.transport.messages.at(-1);
    const oldRevoke = button(oldMenu, '🔒 Revoke now');
    await f.transport.command('/allow app 8h');
    const newMenu = f.transport.messages.at(-1);
    const [renewed] = f.audit.getTemporaryServiceApprovals();
    await f.transport.tap(oldMenu, oldRevoke);
    assert.deepEqual(f.audit.getTemporaryServiceApprovals(), [renewed]);
    await f.transport.tap(newMenu, button(newMenu, '🔒 Revoke now'));
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 0);
  });
});

test('/revoke lists only active grants after restart and revokes only the selected service', async t => {
  await fixture(async f => {
    for (const name of ['cached', 'expired', 'revoked', 'idle']) {
      f.config.services[name] = structuredClone(f.config.services.app);
    }
    f.config.services.ftp = { ...f.config.services.app, protocol: 'ftps', upstream: 'ftps://test.example:21' };
    await f.transport.command('/revoke');
    assert.match(f.transport.messages.at(-1).text, /No active temporary approvals/);
    assert.equal(await approveRequest(f, 'GET', 'cached', '✅ 1h'), 200);
    await f.transport.command('/allow expired 1m');
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 60_000 });
    try {
      for (const command of ['/allow app 30m', '/allow ftp 30m read_only', '/allow revoked 30m', '/revoke revoked']) {
        await f.transport.command(command);
      }
      await f.restart();
      for (const overrides of [{ chat: { id: 200 } }, { from: { id: 8, is_bot: false } },
        { from: { id: 7, is_bot: true } }, { sender_chat: { id: 100 } }]) {
        const before = f.transport.messages.length;
        await f.transport.command('/revoke', overrides);
        assert.ok(f.transport.messages.slice(before).every(msg => !msg.options?.reply_markup));
      }
      await f.transport.command('/revoke@ClawGuardBot');
      const menu = f.transport.messages.at(-1);
      assert.equal(menu.options.message_thread_id, 9);
      assert.deepEqual(menu.options.reply_markup.inline_keyboard.flat().map(item => item.text), ['app', 'ftp', 'Cancel']);
      const revoke = button(menu, 'app');
      for (const overrides of [{ from: { id: 8, is_bot: false } }, { from: { id: 7, is_bot: true } },
        { message: { ...menu, chat: { id: 200 } } }, { message: { ...menu, message_id: -1 } }]) {
        await f.transport.tap(menu, revoke, overrides);
        assert.equal(f.audit.getTemporaryServiceApprovals().length, 2);
      }
      await Promise.all([f.transport.tap(menu, revoke), f.transport.tap(menu, revoke)]);
      assert.match(menu.text, /Approvals revoked for app/);
      assert.deepEqual(menu.options.reply_markup.inline_keyboard, []);
      assert.equal(await f.request(), 403);
      assert.equal(await f.request('GET', 'cached'), 200);
      assert.deepEqual(f.audit.getTemporaryServiceApprovals().map(item => item.service), ['ftp']);
      await f.transport.command('/revoke');
      const ftpMenu = f.transport.messages.at(-1);
      await f.transport.tap(ftpMenu, button(ftpMenu, 'ftp'));
      assert.equal(await f.manager.checkFtpSessionApproval('ftp', f.config.services.ftp, '/lease', '127.0.0.1'), false);
      await f.transport.command('/revoke');
      assert.match(f.transport.messages.at(-1).text, /No active temporary approvals/);
    } finally { t.mock.timers.reset(); }
  }, 750);
});

test('/revoke pages active services and rejects stale, expired or unoffered selections', async t => {
  await fixture(async f => {
    for (let i = 0; i < 10; i++) {
      const name = `service-${i}-${'x'.repeat(55)}`;
      f.config.services[name] = structuredClone(f.config.services.app);
      await f.transport.command(`/allow ${name} 30m`);
    }
    const names = f.audit.getTemporaryServiceApprovals().map(item => item.service).sort();
    await f.transport.command('/revoke');
    const menu = f.transport.messages.at(-1);
    assert.match(menu.text, /1\/2/);
    const offPage = button(menu, names[0]).replace(/service:0$/, 'service:8');
    await f.transport.tap(menu, offPage);
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 10);
    await f.transport.tap(menu, button(menu, 'Next →'));
    assert.match(menu.text, /2\/2/);
    const stale = button(menu, names[8]);
    await f.transport.command(`/allow ${names[8]} 1h`);
    await f.transport.tap(menu, stale);
    assert.match(menu.text, /expired or was replaced/);
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 10);
    await f.transport.command('/revoke');
    const current = f.transport.messages.at(-1);
    await f.transport.tap(current, button(current, 'Next →'));
    await f.transport.tap(current, button(current, '← Previous'));
    await f.transport.tap(current, button(current, 'Next →'));
    await f.transport.tap(current, button(current, names[9]));
    assert.equal(await f.request('GET', names[9]), 403);
    assert.equal(await f.request('GET', names[8]), 200);
    await f.transport.command('/revoke');
    const cancelled = f.transport.messages.at(-1);
    const cancelledChoice = button(cancelled, names[0]);
    await f.transport.tap(cancelled, button(cancelled, 'Cancel'));
    await f.transport.tap(cancelled, cancelledChoice);
    assert.equal(f.audit.getTemporaryServiceApprovals().length, 9);
    await f.transport.command('/revoke');
    const expired = f.transport.messages.at(-1);
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 10 * 60_000 });
    try {
      await f.transport.tap(expired, button(expired, names[0]));
      assert.match(f.transport.answers.at(-1).text, /Menu expired/);
      assert.equal(f.audit.getTemporaryServiceApprovals().length, 9);
    } finally { t.mock.timers.reset(); }
  });
});

test('HTTP policy stays explicit and new SSH/FTP decisions resume at temporary approval expiry', async t => {
  await fixture(async f => {
    f.config.services.automatic = { ...f.config.services.app, policy: { default: 'auto_approve' } };
    f.config.services.ssh = { ...f.config.services.app, protocol: 'ssh', upstream: 'ssh://test.example:22' };
    f.config.services.ftp = { ...f.config.services.app, protocol: 'ftps', upstream: 'ftps://test.example:21' };
    for (const command of ['/allow automatic 1m', '/allow ssh 1m', '/allow ftp 1m read_only']) {
      await f.transport.command(command);
    }
    const expiry = Math.max(...f.audit.getTemporaryServiceApprovals().map(item => item.expiresAt));
    await f.restart();
    t.mock.timers.enable({ apis: ['Date'], now: expiry });
    try {
      assert.equal(await f.request('GET', 'automatic'), 200, 'allow must not rewrite the configured policy');
      assert.match(f.transport.messages.at(-1).text, /policy:autoapprove/);
      assert.equal(await f.manager.checkSshSessionApproval('ssh', f.config.services.ssh, '/exec', '127.0.0.1'), false);
      assert.equal(await f.manager.checkFtpSessionApproval('ftp', f.config.services.ftp, '/lease', '127.0.0.1'), false);
      await f.transport.command('/revoke');
      assert.match(f.transport.messages.at(-1).text, /No active temporary approvals/);
    } finally { t.mock.timers.reset(); }
  });
});
