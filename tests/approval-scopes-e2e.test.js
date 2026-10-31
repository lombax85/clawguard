const test = require('node:test');
const assert = require('node:assert/strict');
const { setTimeout: delay } = require('node:timers/promises');
const http = require('node:http');
const express = require('express');
const { createAdminRouter } = require('../dist/admin');
const { fixture, button, listen } = require('./helpers/telegram-fixture.cjs');

async function begin(f, target, method = 'GET', alias = 'app') {
  const before = f.transport.messages.length;
  const response = f.request(method, alias, target);
  let menu;
  for (let i = 0; i < 100 && !menu; i++) {
    menu = f.transport.messages.slice(before).find(item => item.options.reply_markup);
    if (!menu) await delay(5);
  }
  assert.ok(menu, 'request must wait for an approval');
  return { menu, response, tap: text => f.transport.tap(menu, button(menu, text)) };
}
async function deny(f, target, method = 'GET', alias = 'app') {
  const r = await begin(f, target, method, alias);
  await r.tap('❌ Deny');
  assert.equal(await r.response, 403);
}
async function scope(f, target, method = 'GET') {
  const r = await begin(f, target, method);
  await r.tap('🎯 Choose scope');
  return r;
}

test('default scope is exact GET with all query values, survives restart and expires at the boundary', async t => {
  await fixture(async f => {
    const r = await scope(f, '/api/items?owner=me&page=1&tag=a&tag=b');
    assert.match(r.menu.text, /Subpaths: excluded/);
    assert.match(r.menu.text, /All parameters/);
    assert.equal(f.hits(), 0);
    await r.tap('30m');
    assert.equal(await r.response, 200);
    assert.equal(await f.request('GET', 'app', '/api/items?tag=a&tag=b&page=1&owner=me'), 200);
    for (const target of ['/api/items?owner=me&page=2&tag=a&tag=b', '/api/items?owner=me&page=1&tag=b&tag=a',
      '/api/items?owner=me&page=1&tag=a&tag=b&extra=1', '/api/items', '/api/items/child?owner=me&page=1&tag=a&tag=b']) {
      await deny(f, target);
    }
    await deny(f, '/api/items?owner=me&page=1&tag=a&tag=b', 'POST');
    await f.restart();
    assert.equal(await f.request('GET', 'app', '/api/items?owner=me&page=1&tag=a&tag=b'), 200);
    const [grant] = f.audit.getScopedApprovals();
    t.mock.timers.enable({ apis: ['Date'], now: grant.expiresAt });
    try { await deny(f, '/api/items?owner=me&page=1&tag=a&tag=b'); }
    finally { t.mock.timers.reset(); }
  }, 3000);
});

test('repository scope ignores query, selects GET and POST and respects path boundaries and method restrictions', async () => {
  await fixture(async f => {
    f.config.services.other = structuredClone(f.config.services.app);
    const r = await scope(f, '/logotel_spa/repo.git/info/refs?service=git-upload-pack');
    await r.tap('Path');
    await r.tap('2. /logotel_spa/repo.git');
    assert.match(r.menu.text, /Subpaths: included/);
    await r.tap('Query'); await r.tap('Ignore query');
    await r.tap('Methods'); await r.tap('POST'); await r.tap('Done');
    await r.tap('1h');
    assert.equal(await r.response, 200);
    for (const target of ['/logotel_spa/repo.git', '/logotel_spa/repo.git/info/refs?different=1', '/logotel_spa/repo.git/git-upload-pack']) {
      assert.equal(await f.request('GET', 'app', target), 200);
      assert.equal(await f.request('POST', 'app', target), 200);
    }
    for (const target of ['/logotel_spa/repo.git-other/info', '/logotel_spa/other.git/info',
      '/logotel_spa/repo.git/../other.git/info', '/logotel_spa/repo.git/%2e%2e/other',
      '/logotel_spa/repo.git/a%2fb', '/logotel_spa/repo.git/a%252fb', '/logotel_spa/repo.git/a%5cb']) {
      await deny(f, target);
    }
    await deny(f, '/logotel_spa/repo.git/info/refs', 'GET', 'other');
    assert.equal(await f.request('DELETE', 'app', '/logotel_spa/repo.git/info'), 405);
    await f.transport.command('/revoke app');
    await deny(f, '/logotel_spa/repo.git/info');
    await f.restart();
    await deny(f, '/logotel_spa/repo.git/info');
  }, 3000);
});

test('selected query parameters keep their values and multiplicity while other parameters can change', async () => {
  await fixture(async f => {
    const r = await scope(f, '/api/items?owner=me&page=1&tag=a&tag=b');
    await r.tap('Query'); await r.tap('Choose parameters');
    await r.tap('Done');
    assert.ok(!r.menu.options.reply_markup.inline_keyboard.flat().some(b => b.text === '1h'));
    await r.tap('Query'); await r.tap('Choose parameters');
    await r.tap('owner'); await r.tap('Done');
    assert.match(r.menu.text, /Selected parameters: owner=me/);
    await r.tap('15m');
    assert.equal(await r.response, 200);
    assert.equal(await f.request('GET', 'app', '/api/items?extra=yes&owner=me&page=50'), 200);
    for (const target of ['/api/items?owner=you', '/api/items?page=1', '/api/items?owner=me&owner=you', '/api/items?owner=me&owner=me']) {
      await deny(f, target);
    }
    await f.restart();
    assert.equal(await f.request('GET', 'app', '/api/items?owner=me'), 200);
  }, 3000);
});

test('scope callbacks bind message, chat, user and revision; once cannot be replayed or cached', async () => {
  await fixture(async f => {
    const r = await begin(f, '/a/b');
    const original = structuredClone(r.menu);
    const open = button(r.menu, '🎯 Choose scope');
    for (const overrides of [{ from: { id: 8, is_bot: false } }, { from: { id: 7, is_bot: true } },
      { message: { ...r.menu, chat: { id: 200 } } }, { message: { ...r.menu, message_id: -1 } }]) {
      await f.transport.tap(r.menu, open, overrides);
      assert.equal(f.hits(), 0);
    }
    await r.tap('🎯 Choose scope');
    const oldGrant = button(r.menu, '1h');
    await r.tap('Path');
    await f.transport.tap(r.menu, oldGrant);
    assert.equal(f.hits(), 0);
    await r.tap('1. /a');
    const grant = button(r.menu, '30m');
    const forged = button(original, '✅ Only this request').replace('approve_once:', 'approve_1month:');
    await f.transport.tap(original, forged);
    assert.equal(f.hits(), 0);
    await Promise.all([f.transport.tap(r.menu, grant), f.transport.tap(r.menu, grant)]);
    assert.equal(await r.response, 200);
    assert.equal(f.audit.getScopedApprovals().length, 1);
    await f.transport.command('/revoke app');
    await f.transport.tap(r.menu, grant);
    assert.equal(f.audit.getScopedApprovals().length, 0);
    const single = await begin(f, '/single');
    await single.tap('✅ Only this request');
    assert.equal(await single.response, 200);
    await deny(f, '/single');
  }, 3000);
});

test('expired request cannot be revived by navigation or a duration button', async t => {
  await fixture(async f => {
    const r = await scope(f, '/api/items');
    const grant = button(r.menu, '1h');
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 4000 });
    try {
      await f.transport.tap(r.menu, grant);
      assert.match(f.transport.answers.at(-1).text, /expired/);
      assert.equal(f.audit.getScopedApprovals().length, 0);
      assert.equal(await r.response, 403);
    } finally { t.mock.timers.reset(); }
  }, 3000);
});

test('path and query menus paginate and show full scope; sensitive query values are hidden in the preview', async () => {
  await fixture(async f => {
    const path = '/a/b/c/d/e/f/g/h/i/j';
    const r = await scope(f, `${path}?token=private-test-value&${Array.from({ length: 10 }, (_, i) => `p${i}=v${i}`).join('&')}`);
    assert.ok(!r.menu.text.includes('private-test-value'));
    assert.match(r.menu.text, /token=\[hidden\]/);
    await r.tap('Path'); await r.tap('Next →'); await r.tap('8. /a/b/c/d/e/f/g/h');
    await r.tap('Query'); await r.tap('Choose parameters'); await r.tap('Next →');
    await r.tap('p9'); await r.tap('Done');
    assert.match(r.menu.text, /Path: \/a\/b\/c\/d\/e\/f\/g\/h\n/);
    await r.tap('24h');
    assert.equal(await r.response, 200);
    assert.equal(f.audit.getScopedApprovals()[0].scope.path, '/a/b/c/d/e/f/g/h');
  }, 3000);
});

test('dashboard shows structured scope and can revoke its ID without removing a different scope', async () => {
  await fixture(async f => {
    for (const target of ['/one?owner=me', '/two?owner=me']) {
      const r = await scope(f, target); await r.tap('1h'); assert.equal(await r.response, 200);
    }
    f.config.admin = { enabled: true, pin: 'test-pin', allowedIPs: ['127.0.0.1'], strictMode: false };
    f.config.sshBroker = {};
    const app = express();
    app.use('/__admin', createAdminRouter(f.config, f.manager, f.audit));
    const server = http.createServer(app);
    const base = await listen(server);
    async function admin(path, method = 'GET', authenticated = true) {
      const res = await fetch(`${base}/__admin/api/${path}`, { method, headers: authenticated ? { 'X-ClawGuard-Pin': 'test-pin' } : {} });
      return { status: res.status, body: await res.json() };
    }
    try {
      assert.equal((await admin('approvals', 'GET', false)).status, 401);
      const data = (await admin('approvals')).body;
      const approvals = Object.values(data.active);
      assert.equal(approvals.length, 2);
      assert.equal(data.recent[0].scope.query.mode, 'exact');
      const one = approvals.find(item => item.scope.path === '/one');
      assert.deepEqual(one.scope.methods, ['GET']);
      assert.ok(one.expiresAt && one.remainingMinutes > 0);
      assert.equal((await admin(`revoke/wrong?scopeId=${one.scopeId}`, 'POST')).status, 404);
      assert.equal((await admin(`revoke/app?scopeId=${one.scopeId}&method=GET`, 'POST')).status, 400);
      assert.equal((await admin(`revoke/app?scopeId=${one.scopeId}`, 'POST')).status, 200);
      await deny(f, '/one?owner=me');
      assert.equal(await f.request('GET', 'app', '/two?owner=me'), 200);
      assert.equal((await admin('revoke-all', 'POST')).status, 200);
      await deny(f, '/two?owner=me');
    } finally { await new Promise(resolve => server.close(resolve)); }
  }, 3000);
});

test('new allow replaces scopes; service configuration changes invalidate scopes', async t => {
  await fixture(async f => {
    let r = await scope(f, '/one'); await r.tap('24h'); assert.equal(await r.response, 200);
    await f.transport.command('/allow app 30m');
    assert.deepEqual(f.audit.getScopedApprovals(), []);
    const [temporary] = f.audit.getTemporaryServiceApprovals();
    t.mock.timers.enable({ apis: ['Date'], now: temporary.expiresAt });
    try { await deny(f, '/one'); } finally { t.mock.timers.reset(); }
    await f.transport.command('/revoke app');
    r = await scope(f, '/two'); await r.tap('1h'); assert.equal(await r.response, 200);
    f.config.services.app.http.allowedMethods.push('PUT');
    await deny(f, '/two');
    assert.deepEqual(f.audit.getScopedApprovals(), []);
  }, 3000);
});

test('legacy approvals keep their scope after upgrade and a new allow replaces them durably', async t => {
  await fixture(async f => {
    // Simulate a database written by the previous release, then use public requests.
    f.audit.logApproval('app', 'GET', 'previous owner', 3600, null);
    f.audit.logApproval('app', 'POST', 'previous owner', 86400, '/exact?x=1');
    await f.restart();
    assert.equal(await f.request('GET', 'app', '/any'), 200);
    assert.equal(await f.request('POST', 'app', '/exact?x=1'), 200);
    await deny(f, '/exact?x=2', 'POST');
    await f.transport.command('/allow app 30m');
    const [grant] = f.audit.getTemporaryServiceApprovals();
    t.mock.timers.enable({ apis: ['Date'], now: grant.expiresAt });
    try {
      await f.restart();
      await deny(f, '/any');
      await deny(f, '/exact?x=1', 'POST');
    } finally { t.mock.timers.reset(); }
  }, 3000);
});

test('a root scope cannot authorize a plugin operation that requires a fresh decision', async () => {
  await fixture(async f => {
    const r = await scope(f, '/sdk/read');
    await r.tap('Path'); await r.tap('0. /');
    await r.tap('Query'); await r.tap('Ignore query');
    await r.tap('Methods'); await r.tap('POST'); await r.tap('Done');
    await r.tap('1h'); assert.equal(await r.response, 200);
    const before = f.transport.messages.length;
    const decision = f.manager.checkApproval('app', f.config.services.app, 'POST', '/sdk', '127.0.0.1', undefined,
      { approvalPath: '/sdk/write/PowerOnVM_Task', oneTime: true });
    const prompt = f.transport.messages.slice(before).find(msg => msg.options.reply_markup);
    assert.ok(prompt);
    assert.deepEqual(prompt.options.reply_markup.inline_keyboard.flat().map(b => b.text), ['✅ Approve this request', '❌ Deny']);
    // Let sendMessage finish binding the returned message before the callback.
    await delay(0);
    await f.transport.tap(prompt, button(prompt, '❌ Deny'));
    assert.equal(await decision, false);
  }, 3000);
});
