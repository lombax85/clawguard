const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { TelegramNotifier } = require('../../dist/telegram');
const { ApprovalManager } = require('../../dist/approval');
const { AuditLogger } = require('../../dist/audit');
const { createProxy } = require('../../dist/proxy');

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
  const request = (method = 'GET', alias = 'app', target = '/resource') => new Promise((resolve, reject) => {
    const req = http.request(base, { method, path: `/${alias}${target}`, headers: { 'X-ClawGuard-Key': 'test-agent' } }, res => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject); req.end();
  });
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


module.exports = { fixture, button, listen };
