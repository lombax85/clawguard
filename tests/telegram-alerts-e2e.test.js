const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { setTimeout: delay } = require('node:timers/promises');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const yaml = require('js-yaml');
const { loadConfig } = require('../dist/config');
const { TelegramNotifier } = require('../dist/telegram');
const { WebhookNotifier } = require('../dist/webhook');
const { ApprovalManager } = require('../dist/approval');
const { AuditLogger } = require('../dist/audit');
const { createProxy } = require('../dist/proxy');

// Stub only Telegram's external transport. HTTP approvals, webhook delivery,
// configuration and restart persistence use the real application components.
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
  async editMessageText() {}
  async answerCallbackQuery() {}
  isPolling() { return true; }
  async stopPolling() {}
  async startPolling() {}
  async command(text, overrides = {}) {
    const message = { text, chat: { id: 100 }, from: { id: 7, is_bot: false }, ...overrides };
    this.emit('message', message);
    for (const { pattern, callback } of this.handlers) {
      const match = pattern.exec(text);
      if (match) await callback(message, match);
    }
  }
  async decide(message, approved) {
    const action = approved ? 'approve_once:' : 'deny:';
    const data = message.options.reply_markup.inline_keyboard.flat().find(button => button.callback_data.startsWith(action)).callback_data;
    for (const callback of this.listeners('callback_query')) {
      await callback({ id: `decision-${message.message_id}`, data, message, from: { id: 7, first_name: 'owner', is_bot: false } });
    }
  }
}

async function waitFor(predicate) {
  const deadline = performance.now() + 2_000;
  while (performance.now() < deadline) {
    const result = predicate();
    if (result) return result;
    await delay(5);
  }
  assert.fail('Timed out waiting for public response');
}

async function listen(server) {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

async function fixture(run, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-alerts-'));
  const dbPath = path.join(directory, 'audit.db');
  const events = [];
  const receiver = http.createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    events.push(JSON.parse(body));
    res.writeHead(204).end();
  });
  const webhookInput = { enabled: true, url: await listen(receiver), cancelOnResolve: true,
    timeoutMs: 500, escalateAfterSeconds: 0, ...options };
  let hits = 0;
  const upstream = http.createServer((req, res) => {
    hits++;
    assert.equal(req.headers.authorization, 'Bearer test-upstream');
    res.end('ok');
  });
  const configInput = { server: { port: 9090, agentKey: 'test-agent' },
    services: { app: { upstream: await listen(upstream), auth: { type: 'bearer', token: 'test-upstream' },
      http: { allowPrivateTarget: true }, policy: { default: 'require_approval' } } },
    security: { allowedUpstreams: ['127.0.0.1'], blockPrivateIPs: true, followRedirects: false, maxPayloadLogSize: 1024 },
    admin: { enabled: false }, audit: { logPayload: false }, notifications: { webhook: webhookInput } };
  const configPath = path.join(directory, 'clawguard.yaml');
  fs.writeFileSync(configPath, yaml.dump(configInput));
  const config = await loadConfig(configPath);
  const webhookConfig = config.notifications.webhook;
  const transport = new TelegramTransport();
  const telegramConfig = { botToken: 'test', chatId: '100', messageThreadId: 9,
    allowedApprovers: ['7'], pairing: { enabled: true, secret: 'test' } };
  let audit, webhook, telegram, manager, server, base;
  async function start() {
    audit = new AuditLogger(dbPath);
    if (!audit.isPairedUser('100')) audit.pairUser('100', 'owner');
    transport.handlers = []; transport.removeAllListeners();
    telegram = new TelegramNotifier(telegramConfig, audit, { bot: transport });
    webhook = webhookConfig.enabled ? new WebhookNotifier(webhookConfig, audit) : undefined;
    if (webhook) telegram.configureWebhookAlerts(webhook);
    manager = new ApprovalManager(telegram, audit, 2_000, webhook);
    telegram.configureServiceCommands(() => config.services, manager);
    server = http.createServer(createProxy(config, manager, audit));
    base = await listen(server);
  }
  async function stop() {
    webhook?.stop();
    await telegram.stop();
    await new Promise(resolve => server.close(resolve));
    audit.close();
  }
  await start();
  try {
    await run({ transport, events, hits: () => hits, get audit() { return audit; },
      async restart() { await stop(); await start(); },
      async request() {
        manager.revokeApproval('app'); // Each fixture request needs its own decision.
        const before = transport.messages.length;
        let settled = false;
        const response = fetch(`${base}/app/resource`, {
          method: 'POST', headers: { 'X-ClawGuard-Key': 'test-agent' },
        }).then(async result => { await result.text(); settled = true; return result.status; });
        const message = await waitFor(() => transport.messages.slice(before).find(item => item.options.reply_markup));
        return { response, message, settled: () => settled };
      } });
  } finally {
    await stop();
    await Promise.all([receiver, upstream].map(item => new Promise(resolve => item.close(resolve))));
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test('/alerts off survives restart and leaves Telegram approvals active; on restores webhook delivery', async () => {
  await fixture(async f => {
    await f.transport.command('/help');
    assert.ok(f.transport.commands.some(item => item.command === 'alerts'));
    assert.match(f.transport.messages.at(-1).text, /\/alerts \[on\|off\|status\]/);
    await f.transport.command('/alerts@ClawGuardBot off');
    assert.match(f.transport.messages.at(-1).text, /alerts: OFF/);
    assert.equal(f.transport.messages.at(-1).options.message_thread_id, 9);
    const request = await f.request();
    await delay(60);
    assert.equal(request.settled(), false, 'muting must not grant approval');
    assert.equal(f.hits(), 0);
    assert.deepEqual(f.events, []);
    await f.transport.decide(request.message, true);
    assert.equal(await request.response, 200);
    assert.equal(f.hits(), 1);
    await f.restart();
    await f.transport.command('/status');
    assert.match(f.transport.messages.at(-1).text, /Enhanced alerts \(webhook\): OFF/);
    const afterRestart = await f.request();
    await f.transport.decide(afterRestart.message, false);
    assert.equal(await afterRestart.response, 403);
    await delay(60);
    assert.deepEqual(f.events, []);
    await f.transport.command('/alerts on');
    await f.restart();
    await f.transport.command('/alerts status');
    assert.match(f.transport.messages.at(-1).text, /alerts: ON/);
    const restored = await f.request();
    await waitFor(() => f.events.length === 1);
    assert.equal(f.events[0].event, 'approval_required');
    await f.transport.decide(restored.message, false);
    assert.equal(await restored.response, 403);
    await waitFor(() => f.events.length === 2);
    assert.equal(f.events[1].event, 'approval_resolved');
    assert.equal(f.events[1].requestId, f.events[0].requestId);
  });
});

test('muting cancels queued escalation; enabling does not replay cancelled or muted requests', async () => {
  await fixture(async f => {
    const queued = await f.request();
    assert.deepEqual(f.events, []);
    await f.transport.command('/alerts off');
    const muted = await f.request();
    await f.transport.command('/alerts on');
    await delay(350);
    assert.deepEqual(f.events, []);
    for (const request of [queued, muted]) {
      await f.transport.decide(request.message, false);
      assert.equal(await request.response, 403);
    }
    const next = await f.request();
    await waitFor(() => f.events.length === 1);
    await f.transport.decide(next.message, false);
    assert.equal(await next.response, 403);
    await waitFor(() => f.events.length === 2);
    assert.deepEqual(f.events.map(item => item.event), ['approval_required', 'approval_resolved']);
  }, { escalateAfterSeconds: 0.25 });
});

test('an alert sent before muting can still be cleared when its Telegram request resolves', async () => {
  await fixture(async f => {
    const sent = await f.request();
    await waitFor(() => f.events.length === 1);
    await f.transport.command('/alerts off');
    await f.transport.decide(sent.message, false);
    assert.equal(await sent.response, 403);
    await waitFor(() => f.events.length === 2);
    assert.equal(f.events[1].event, 'approval_resolved');
    const muted = await f.request();
    await f.transport.decide(muted.message, false);
    assert.equal(await muted.response, 403);
    await delay(60);
    assert.equal(f.events.length, 2);
  });
});

test('/alerts rejects other chats, unauthorized users, bots, anonymous senders, unpaired chats and malformed arguments', async () => {
  await fixture(async f => {
    const before = f.transport.messages.length;
    await f.transport.command('/alerts off', { chat: { id: 200 } });
    assert.equal(f.transport.messages.length, before);
    for (const overrides of [{ from: { id: 8, is_bot: false } }, { from: { id: 7, is_bot: true } },
      { sender_chat: { id: 100 } }, { from: undefined }]) {
      await f.transport.command('/alerts off', overrides);
      assert.match(f.transport.messages.at(-1).text, /Access denied/);
    }
    f.audit.unpairUser('100');
    await f.transport.command('/alerts off');
    assert.match(f.transport.messages.at(-1).text, /Access denied/);
    f.audit.pairUser('100', 'owner');
    for (const text of ['/alerts off extra', '/alerts toggle', '/alerts off on']) {
      await f.transport.command(text);
      assert.match(f.transport.messages.at(-1).text, /Usage:/);
    }
    await f.transport.command('/alerts');
    assert.match(f.transport.messages.at(-1).text, /alerts: ON/);
    const request = await f.request();
    await waitFor(() => f.events.length === 1);
    await f.transport.decide(request.message, false);
    assert.equal(await request.response, 403);
    await waitFor(() => f.events.length === 2);
  });
});

test('/alerts on cannot enable a webhook disabled in server configuration', async () => {
  await fixture(async f => {
    await f.transport.command('/alerts on');
    assert.match(f.transport.messages.at(-1).text, /not configured/);
    await f.restart();
    await f.transport.command('/status');
    assert.match(f.transport.messages.at(-1).text, /webhook\): not configured/);
    const request = await f.request();
    await f.transport.decide(request.message, false);
    assert.equal(await request.response, 403);
    await delay(60);
    assert.deepEqual(f.events, []);
  }, { enabled: false });
});

test('quick Telegram decisions still cancel escalation and cancelOnResolve remains optional', async () => {
  await fixture(async f => {
    const quick = await f.request();
    await f.transport.decide(quick.message, false);
    assert.equal(await quick.response, 403);
    await delay(350);
    assert.deepEqual(f.events, []);
    const escalated = await f.request();
    await waitFor(() => f.events.length === 1);
    await f.transport.command('/alerts off');
    await f.transport.decide(escalated.message, false);
    assert.equal(await escalated.response, 403);
    await delay(60);
    assert.deepEqual(f.events.map(item => item.event), ['approval_required']);
  }, { escalateAfterSeconds: 0.25, cancelOnResolve: false });
});

const daytimeHours = { start: '08:00', end: '23:00', timezone: 'Europe/Rome' };

async function checkDelivery(f, expected) {
  const before = f.events.length;
  const request = await f.request();
  if (expected) await waitFor(() => f.events.length === before + 1);
  else await delay(60);
  assert.equal(f.events.length, before + Number(expected));
  assert.equal(request.settled(), false, 'active hours must not decide access');
  await f.transport.decide(request.message, false);
  assert.equal(await request.response, 403);
  if (expected) await waitFor(() => f.events.length === before + 2);
  else await delay(20);
  assert.equal(f.events.length, before + (expected ? 2 : 0));
  if (expected) {
    assert.deepEqual(f.events.slice(before).map(item => item.event), ['approval_required', 'approval_resolved']);
  }
}

test('configured active hours gate real webhooks at local-time boundaries in winter and summer', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: new Date('2026-11-09T06:59:59Z').getTime() });
  try {
    await fixture(async f => {
      for (const [instant, active] of [
        ['2026-11-09T06:59:59Z', false], // 07:59 CET
        ['2026-11-09T07:00:00Z', true],  // 08:00 CET: start included
        ['2026-11-09T21:59:59Z', true],
        ['2026-11-09T22:00:00Z', false], // 23:00 CET: end excluded
        ['2026-07-09T06:00:00Z', true],  // 08:00 CEST
        ['2026-07-09T21:00:00Z', false], // 23:00 CEST
      ]) {
        t.mock.timers.setTime(new Date(instant).getTime());
        await checkDelivery(f, active);
      }
    }, { activeHours: daytimeHours });
  } finally { t.mock.timers.reset(); }
});

test('active hours can cross midnight and use the named zone during daylight-saving transitions', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: new Date('2026-11-09T21:59:59Z').getTime() });
  try {
    await fixture(async f => {
      for (const [instant, active] of [
        ['2026-11-09T21:59:59Z', false],
        ['2026-11-09T22:00:00Z', true],
        ['2026-11-10T00:00:00Z', true],
        ['2026-11-10T06:59:59Z', true],
        ['2026-11-10T07:00:00Z', false],
      ]) {
        t.mock.timers.setTime(new Date(instant).getTime());
        await checkDelivery(f, active);
      }
    }, { activeHours: { start: '22:00', end: '07:00', timezone: 'UTC' } });
    await fixture(async f => {
      for (const [instant, active] of [
        ['2026-03-29T00:59:59Z', false], // 01:59 CET
        ['2026-03-29T01:00:00Z', false], // 03:00 CEST: 02:00 is skipped
        ['2026-10-25T00:30:00Z', true],  // 02:30 CEST
        ['2026-10-25T01:30:00Z', true],  // 02:30 CET: repeated hour
        ['2026-10-25T02:00:00Z', false], // 03:00 CET
      ]) {
        t.mock.timers.setTime(new Date(instant).getTime());
        await checkDelivery(f, active);
      }
    }, { activeHours: { start: '02:00', end: '03:00', timezone: 'Europe/Rome' } });
  } finally { t.mock.timers.reset(); }
});

test('escalation checks the window at delivery and never replays an out-of-hours alert', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: new Date('2026-11-09T21:59:59Z').getTime() });
  try {
    await fixture(async f => {
      const closing = await f.request();
      t.mock.timers.setTime(new Date('2026-11-09T22:00:00Z').getTime());
      await delay(350);
      assert.deepEqual(f.events, []);
      t.mock.timers.setTime(new Date('2026-11-10T07:00:00Z').getTime());
      await delay(60);
      assert.deepEqual(f.events, [], 'no morning replay');
      await f.transport.decide(closing.message, false);
      assert.equal(await closing.response, 403);

      t.mock.timers.setTime(new Date('2026-11-11T06:59:59Z').getTime());
      const opening = await f.request();
      t.mock.timers.setTime(new Date('2026-11-11T07:00:00Z').getTime());
      await waitFor(() => f.events.length === 1);
      await f.transport.decide(opening.message, false);
      assert.equal(await opening.response, 403);
      await waitFor(() => f.events.length === 2);
      assert.deepEqual(f.events.map(item => item.event), ['approval_required', 'approval_resolved']);
    }, { activeHours: daytimeHours, escalateAfterSeconds: 0.25 });
  } finally { t.mock.timers.reset(); }
});

test('sent alerts can be cleared after active hours; on and restart do not bypass the schedule', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: new Date('2026-11-09T21:59:59Z').getTime() });
  try {
    await fixture(async f => {
      const sent = await f.request();
      await waitFor(() => f.events.length === 1);
      t.mock.timers.setTime(new Date('2026-11-09T22:00:00Z').getTime());
      await f.transport.decide(sent.message, false);
      assert.equal(await sent.response, 403);
      await waitFor(() => f.events.length === 2);
      assert.equal(f.events[1].event, 'approval_resolved');

      await f.transport.command('/alerts off');
      await f.transport.command('/alerts on');
      await f.restart();
      for (const command of ['/alerts status', '/status']) {
        await f.transport.command(command);
        assert.match(f.transport.messages.at(-1).text, /ON; active hours: 08:00–23:00 \(Europe\/Rome\), daily/);
        assert.match(f.transport.messages.at(-1).text, /outside active hours — new alerts muted/);
      }
      await checkDelivery(f, false);
      t.mock.timers.setTime(new Date('2026-11-10T07:00:00Z').getTime());
      await f.transport.command('/alerts off');
      await checkDelivery(f, false);
      await f.transport.command('/alerts on');
      await checkDelivery(f, true);
    }, { activeHours: daytimeHours });
  } finally { t.mock.timers.reset(); }
});

test('startup rejects invalid YAML active hours, including when the webhook is disabled', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-alert-hours-config-'));
  const configPath = path.join(directory, 'clawguard.yaml');
  try {
    for (const activeHours of [null, [], '08:00-23:00', {},
      { ...daytimeHours, start: '8:00' }, { ...daytimeHours, end: '24:00' },
      { ...daytimeHours, start: '08:60' }, { ...daytimeHours, start: 800 },
      { ...daytimeHours, end: '08:00' }, { ...daytimeHours, timezone: undefined },
      { ...daytimeHours, timezone: 'Mars/Olympus' }, { ...daytimeHours, timezone: '+01:00' },
    ]) {
      fs.writeFileSync(configPath, yaml.dump({
        server: { port: 9090, agentKey: 'test' }, admin: { enabled: false },
        services: { app: { upstream: 'https://example.com', auth: { type: 'bearer', token: 'test' },
          policy: { default: 'require_approval' } } },
        notifications: { webhook: { enabled: false, activeHours } },
      }));
      const result = spawnSync(process.execPath, ['-e',
        'require("./dist/config").loadConfig(process.argv[1]).then(() => console.log("CONFIG_LOADED"))', configPath],
      { cwd: path.resolve(__dirname, '..'), encoding: 'utf8', timeout: 5000 });
      assert.equal(result.status, 1, JSON.stringify(activeHours));
      assert.match(result.stderr, /notifications\.webhook\.activeHours/);
      assert.doesNotMatch(result.stdout, /CONFIG_LOADED/);
    }
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
